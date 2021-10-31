#include "kernel_main.h"

/*
用户层常见的反调试手段介绍和破解之法：
1.基于peb.debugport成员的反调试：该成员值在内核中通过DbgkpMarkProcessPeb函数进行设置，破解之法：debugport移位时该函数不进行移位该成员被用户层使用的方式有：
		IsDebuggerPresentAPI
		IsDebuggerPresentPEB
		检查HeapFlags
		检查HeapForceFlags
		UnhandledExcepFilter
2.NtQueryInformationProcess系列：内核代码会检查进程的eprocess.DebugPort成员的值，破解之法：debugport移位时该函数不进行移位，或者在该函数中进行过滤。即ssdt hook对结果过滤
3.WUDF系列（仅限64位进程）：内核代码会检查进程的eprocess.DebugPort成员的值，破解之法同上
4.NtSetInformationThread：内核代码会修改ethread.CrossThreadFlags.HideFromDebugger位，破解之法：SSDT hook过滤或者修改内核代码中检测该比特位的代码
5.CloseHandle（close protected handle or illegal handel：该函数调用NtClose函数，而在内核代码中NtClose函数检测eprocess.DebugPort的值，破解之法：debugport移位时该函数不进行移位
6.NtYieldExecution：该函数检测不稳定，一般不会被使用。破解之法：SSDT hook该函数后直接返回STATUS_NO_YIELD_PERFORMED即可
7.NtQueryObject：通过查询有无DebugObject对象或数量来判断是否处于调试中，破解之法：SSDT hook对结果进行过滤
8.NtQuerySystemInformation：可以检测是否存在内核调试器，破解之法：SSDT hook，对查询结果进行修改
9.SharedUserData中KernelDebugger成员：内核会不定期修改，因此需要修改内核代码，破解之法：修改内核代码或者不使用内核调试器
10.硬件断点：SSDT hook对结果进行过滤
11.其他：父子进程、工作集、特定进程检测






*/


BOOL can_protect(WCHAR *process_name)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.protect_name_list[i].type == 1 && wcscmp(adps.protect_name_list[i].str, process_name) == 0)
		{
			return TRUE;
		}
		if (adps.protect_name_list[i].type == 2 && wcsstr(adps.protect_name_list[i].str, process_name))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL can_crack(WCHAR *process_name)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.crack_name_list[i].type == 1 && wcscmp(adps.crack_name_list[i].str, process_name) == 0)
		{
			return TRUE;
		}
		if (adps.crack_name_list[i].type == 2 && wcsstr(adps.crack_name_list[i].str, process_name))
		{
			return TRUE;
		}
	}
	return FALSE;

}

BOOL is_protect_process(PEPROCESS peprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_protect[i] == peprocess)
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL add_protect_process(PEPROCESS peprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_protect[i] == 0)
		{
			adps.process_protect[i] = peprocess;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL delete_protect_process(PEPROCESS eprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_protect[i] == eprocess)
		{
			adps.process_protect[i] = 0;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL is_crack_process(PEPROCESS peprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_crack[i] == peprocess)
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL add_crack_process(PEPROCESS peprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_crack[i] == 0)
		{
			adps.process_crack[i] = peprocess;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL delete_crack_process(PEPROCESS eprocess)
{
	for (int i = 0; i < MAX_SIZE_WORK; i++)
	{
		if (adps.process_crack[i] == eprocess)
		{
			adps.process_crack[i] = 0;
			return TRUE;
		}
	}
	return FALSE;
}

void init_ssdt_fun_addr_table()
{
	for (int i = 0; i < ARRAYSIZE(ssdt_fun_table_win10); i++)
	{
		ssdt_fun_table_win10[i].fun_addr = get_ssdt_fun_addr_by_index_x64(i);
		if (ssdt_fun_table_win10[i].fun_addr == NULL)
		{
			KDbgPrint("%s:failed get SSDT fun:%wZ\n", __FUNCTION__, &ssdt_fun_table_win10[i].fun_name);
		}
	}
}

void init_shadow_ssdt_fun_addr_table()
{
	for (int i = 0; i < ARRAYSIZE(shadow_ssdt_fun_table_win10); i++)
	{
		shadow_ssdt_fun_table_win10[i].fun_addr = get_shadow_ssdt_fun_addr_by_index_x64(i);
		if (shadow_ssdt_fun_table_win10[i].fun_addr == NULL)
		{
			KDbgPrint("%s:failed get shadow SSDT fun:%wZ\n", __FUNCTION__, &shadow_ssdt_fun_table_win10[i].fun_name);
		}
	}
}

void init_os_info()
{
	memset(&os_info, 0, sizeof(OS_INFO));
	get_nt_driver_info(&os_info.nt_driver_info);
	PsGetVersion(&os_info.major, &os_info.minor, &os_info.build, &os_info.csd);
}

void change_debug_port_offset(BOOL unload)
{
	//debug port 移位
	if (unload)
	{
		//恢复
		for (int i = 0; i < ARRAYSIZE(funs_debug_port_17763); i++)
		{
			UINT64 addr = funs_debug_port_17763[i].code_rva + (UINT64)funs_debug_port_17763[i].offset + (UINT64)os_info.nt_driver_info.Base;
			int length = funs_debug_port_17763[i].data_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &funs_debug_port_17763[i].ori_data, length))
				funs_debug_port_17763[i].status = 1;
			else
				funs_debug_port_17763[i].status = 0;
		}
	}
	else
	{
		for (int i = 0; i < ARRAYSIZE(funs_debug_port_17763); i++)
		{
			UINT64 addr = funs_debug_port_17763[i].code_rva + (UINT64)funs_debug_port_17763[i].offset + (UINT64)os_info.nt_driver_info.Base;
			int length = funs_debug_port_17763[i].data_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &funs_debug_port_17763[i].new_data, length))
				funs_debug_port_17763[i].status = 1;
			else
				funs_debug_port_17763[i].status = 0;
		}
	}

}

void replace_code(BOOL unload)
{
	//替换指令部分
	if (unload)
	{
		for (int i = 0; i < ARRAYSIZE(fun_replace_17763); i++)
		{
			UINT64 addr = fun_replace_17763[i].code_rva + (UINT64)os_info.nt_driver_info.Base;
			int length = fun_replace_17763[i].ori_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &fun_replace_17763[i].ori_code, length))
				fun_replace_17763[i].status = 1;
			else
				fun_replace_17763[i].status = 0;
		}

	}
	else
	{
		for (int i = 0; i < ARRAYSIZE(fun_replace_17763); i++)
		{
			UINT64 addr = fun_replace_17763[i].code_rva + (UINT64)os_info.nt_driver_info.Base;
			int length = fun_replace_17763[i].new_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &fun_replace_17763[i].new_code, length))
				fun_replace_17763[i].status = 1;
			else
				fun_replace_17763[i].status = 0;
		}
	}
}

void disable_callback_register(BOOL unload)
{
	if (unload)
	{
		for (int i = 0; i < ARRAYSIZE(fun_callback_17763); i++)
		{
			UINT64 addr = fun_callback_17763[i].code_rva + (UINT64)os_info.nt_driver_info.Base;
			int length = fun_callback_17763[i].ori_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &fun_callback_17763[i].ori_code, length))
				fun_callback_17763[i].status = 1;
			else
				fun_callback_17763[i].status = 0;
		}
	}
	else
	{
		for (int i = 0; i < ARRAYSIZE(fun_callback_17763); i++)
		{
			UINT64 addr = fun_callback_17763[i].code_rva + (UINT64)os_info.nt_driver_info.Base;
			int length = fun_callback_17763[i].new_length;
			if (STATUS_SUCCESS == write_kernel_memory((PVOID)addr, &fun_callback_17763[i].new_code, length))
				fun_callback_17763[i].status = 1;
			else
				fun_callback_17763[i].status = 0;
		}
	}
}

void __fastcall sys_call_stub(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	DWORD index = SystemCallIndex;
	PFUN_INFO_ENTRY pfun_entry;
	//32位进程的系统调用和64位系统调用的转换，32位进程的部分函数的调用号发生了重定向，但调用函数的本质并未发生变化
	switch (SystemCallIndex)
	{
	case 0x10046:
		index = 0x46;
		break;
	case 0x3000f:
		index = 0xf;
		break;
	}

	//Shadow SSDT函数 win10
	if (SystemCallIndex >= 0x1000 && SystemCallIndex <= 0x1000 + 1241)
	{
		index = SystemCallIndex - 0x1000;
		pfun_entry = &shadow_ssdt_fun_table_win10[index];
		if (*SystemCallFunction == pfun_entry->fun_addr && pfun_entry->detour_fun_addr != NULL)
		{
			*SystemCallFunction = pfun_entry->detour_fun_addr;
		}
		return;
	}

	//SSDT 函数 win10
	if (index < ARRAYSIZE(ssdt_fun_table_win10))
	{
		pfun_entry = &ssdt_fun_table_win10[index];
		if (*SystemCallFunction == pfun_entry->fun_addr && pfun_entry->detour_fun_addr != NULL)
		{
			*SystemCallFunction = pfun_entry->detour_fun_addr;
		}
		return;
	}

}

void start_infinity_hook()
{
	NTSTATUS status = IfhInitialize(sys_call_stub);
	if (!NT_SUCCESS(status))
	{
		KDbgPrint("%s: line=%d call IfhInitialize fun failed! status=0x%x\n", __FUNCTION__, __LINE__, status);
	}
}

NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
)
{
	

	//打开或创建“文件”对象时会调用
	static wchar_t IfhMagicFileName[] = L"ifh--";


	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		PWCHAR ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);


			if (wcsstr(ObjectName, IfhMagicFileName))
			{
				KDbgPrint("[+] infinityhook: Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePool(ObjectName);

				return STATUS_ACCESS_DENIED;
			}

			ExFreePool(ObjectName);
		}
	}

	return ((PFNtCreateFile)ssdt_fun_table_win10[85].fun_addr)(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength
		);
}

NTSTATUS DetourNtMapViewOfSection(
	IN HANDLE               SectionHandle,
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress OPTIONAL,
	IN UINT64               ZeroBits OPTIONAL,
	IN UINT64               CommitSize,
	IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
	IN OUT PUINT64          ViewSize,
	IN   SECTION_INHERIT    InheritDisposition,
	IN UINT64               AllocationType OPTIONAL,
	IN ULONG                Protect
)
{
	//注意X86下的函数声明再X64内核态下的参数的数据位长度发生变化

	if (ExGetPreviousMode() == KernelMode)
	{
		get_int3();
	}

	NTSTATUS Status = ((PFNtMapViewOfSection)ssdt_fun_table_win10[40].fun_addr)(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
		SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	return Status;
}


NTSTATUS DetourNtUnMapViewOfSection(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
)
{
	NTSTATUS Status = ((PFNtUnmapViewOfSection)ssdt_fun_table_win10[42].fun_addr)(ProcessHandle, BaseAddress);

	return Status;
}


NTSTATUS DetourNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
)
{
	NTSTATUS Status = ((PFNtAllocateVirtualMemory)ssdt_fun_table_win10[24].fun_addr)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	
	return Status;
}

NTSTATUS DetourNtFreeVirtualMemory(
	_In_    HANDLE  ProcessHandle,						//目标进程的句柄
	_Inout_ PVOID   *BaseAddress,						//保存释放的内存的基址的指针
	_Inout_ PSIZE_T RegionSize,							//释放的区域大小，如果是0，系统将释放整个域。返回后其将保存真正的释放大小
	_In_    ULONG   FreeType							//MEM_DECOMMIT, or MEM_RELEASE.
)
{
	NTSTATUS Status = ((PFNtFreeVirtualMemory)ssdt_fun_table_win10[30].fun_addr)(ProcessHandle, BaseAddress, RegionSize, FreeType);

	return Status;
}

NTSTATUS DetourNtProtectVirtualMemory(
	IN HANDLE		ProcessHandle,
	IN OUT PVOID	*UnsafeBaseAddress,
	IN OUT SIZE_T	*UnsafeNumberOfBytesToProtect,
	IN ULONG		NewAccessProtection,
	OUT PULONG		UnsafeOldAccessProtection
)
{
	NTSTATUS Status = ((PFNtProtectVirtualMemory)ssdt_fun_table_win10[80].fun_addr)(
		ProcessHandle,
		UnsafeBaseAddress,
		UnsafeNumberOfBytesToProtect,
		NewAccessProtection,
		UnsafeOldAccessProtection
		);



	return Status;
}

NTSTATUS DetourNtQueryInformationProcess(
	IN HANDLE           ProcessHandle,
	IN PROCESS_INFORMATION_CLASS_SR ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
)
{
	//自定义与用户层通信方案
	if (ProcessInformationClass == 1000)
		return communicate_to_user((DWORD)ProcessHandle, ProcessInformation, ProcessInformationLength);
	//其他的请求由系统处理
	NTSTATUS status = ((PFNtQueryInformationProcess)ssdt_fun_table_win10[25].fun_addr)(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength
		);
	if (!NT_SUCCESS(status)) return status;
	//对于需要破坏的进程，这里进行相关工作
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		KDbgPrint("%s: pid=%d want to get process debug info, we cleared debug info!\n", __FUNCTION__, PsGetCurrentProcessId());
		switch (ProcessInformationClass)
		{
		case ProcessBasicInformation_Sr:
			if (ProcessInformationLength == sizeof(PROCESS_BASIC_INFORMATION64_SR))//64位
			{
				auto p = (PPROCESS_BASIC_INFORMATION64_SR)ProcessInformation;
				if (adps.explorer_pid != 0)
					p->InheritedFromUniqueProcessId = adps.explorer_pid;
			}
			else if (ProcessInformationLength == sizeof(PROCESS_BASIC_INFORMATION32_SR))//32位
			{
				auto p = (PPROCESS_BASIC_INFORMATION32_SR)ProcessInformation;
				if (adps.explorer_pid != 0)
					p->InheritedFromUniqueProcessId = adps.explorer_pid;
			}
			break;
		case ProcessDebugPort_Sr:
			if (ProcessInformationLength == 1)
				*(UINT8*)ProcessInformation = FALSE;
			else if (ProcessInformationLength == 2)
				*(UINT16*)ProcessInformation = FALSE;
			else if (ProcessInformationLength == 4)
				*(UINT32*)ProcessInformation = FALSE;
			else if (ProcessInformationLength == 8)
				*(UINT64*)ProcessInformation = FALSE;
			else
				*(UINT8*)ProcessInformation = FALSE;
			break;
		case ProcessDebugFlags_Sr:
			status = STATUS_ACCESS_DENIED;
			break;
		case ProcessDebugObjectHandle_Sr:
			*(HANDLE*)ProcessInformation = NULL;
			break;
		default:

			break;
		}
	}
	return status;
}

NTSTATUS DetourNtQueryObject(
	__in HANDLE Handle,
	__in OBJECT_INFORMATION_CLASS_SR ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
	__in ULONG ObjectInformationLength,
	__out_opt PULONG ReturnLength
)
{
	NTSTATUS status = STATUS_ACCESS_DENIED;
	POBJECT_TYPE_INFORMATION_SR p = NULL;
	WCHAR obj_name[50];
	status = ((PFNtQueryObject)ssdt_fun_table_win10[16].fun_addr)(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength
		);
	if (!NT_SUCCESS(status)) return status;

	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		KDbgPrint("%s: pid=%d want to get debugobject info, we cleared debug info!\n", __FUNCTION__, PsGetCurrentProcessId());
		if (ObjectInformationClass == ObjectTypeInformation_Sr)
		{
			//反调试方调用queryobject函数查询debugobject对象的数量，这里暂时不需要处理
		}
		else if (ObjectInformationClass == ObjectTypesInformation_Sr)
		{
			//反调试方调用queryobject函数查询所有内核对象的数量，这里找到debugobject对象后将对象数量和句柄数量清0
			UCHAR *pobj_info_addr = (UCHAR *)(((POBJECT_ALL_INFORMATION_SR)ObjectInformation)->ObjectTypeInformation);
			ULONG number_of_objects = ((POBJECT_ALL_INFORMATION_SR)ObjectInformation)->NumberOfObjects;
			for (ULONG i = 0; i < number_of_objects; i++)
			{
				POBJECT_TYPE_INFORMATION_SR pobj_type_info = (POBJECT_TYPE_INFORMATION_SR)pobj_info_addr;

				memset(obj_name, 0, pobj_type_info->TypeName.Length + sizeof(WCHAR));
				memcpy(obj_name, pobj_type_info->TypeName.Buffer, pobj_type_info->TypeName.Length);

				if (wcsstr(obj_name, L"DebugObject"))
				{
					pobj_type_info->TotalNumberOfHandles = 0;
					pobj_type_info->TotalNumberOfObjects = 0;
					break;
				}

				pobj_info_addr = (UCHAR*)pobj_type_info->TypeName.Buffer;
				pobj_info_addr += pobj_type_info->TypeName.MaximumLength;

				ULONG_PTR tmp = ((ULONG_PTR)pobj_info_addr) & -(int)sizeof(void*);

				if ((ULONG_PTR)tmp != (ULONG_PTR)pobj_info_addr)
					tmp += sizeof(void*);
				pobj_info_addr = ((unsigned char*)tmp);
			}

		}
	}
	return status;
}

NTSTATUS DetourNtSetInformationThread(
	IN HANDLE               ThreadHandle,
	IN THREAD_INFORMATION_CLASS_SR ThreadInformationClass,
	IN PVOID                ThreadInformation,
	IN ULONG                ThreadInformationLength
)
{
	//32位进程设置线程上下文使用的是0x1d功能号，此时的CONTEXT32大小为716字节
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pethread = NULL;
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur) && ThreadInformationClass == ThreadHideFromDebugger_Sr)
	{
		//校验参数合法性来进行适当的拦截,因为防守方会采用伪造参数来查看该函数是否被hook

		//线程句柄不合法
		status = ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, UserMode, &pethread, NULL);
		if (!NT_SUCCESS(status)) goto ORINGINAL_NTSETINFORMATIONTHREAD;
		ObDereferenceObject(pethread);
		//长度不正确
		if (ThreadInformationLength > 1) goto ORINGINAL_NTSETINFORMATIONTHREAD;
		//提供的写入地址参数不正确
		if (ThreadInformation) goto ORINGINAL_NTSETINFORMATIONTHREAD;
		KDbgPrint("%s: pid=%d want to ThreadHideFromDebugger, we intercepted it!\n", __FUNCTION__, PsGetCurrentProcessId());
		return status;
	}
	else
	{
	ORINGINAL_NTSETINFORMATIONTHREAD:
		status = ((PFNtSetInformationThread)ssdt_fun_table_win10[13].fun_addr)(
			ThreadHandle,
			ThreadInformationClass,
			ThreadInformation,
			ThreadInformationLength
			);
	}
	return status;
}

NTSTATUS DetourNtQueryInformationThread(
	__in HANDLE ThreadHandle,
	__in THREAD_INFORMATION_CLASS_SR ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength,
	__out_opt PULONG ReturnLength
)
{

	NTSTATUS status = ((PFNtQueryInformationThread)ssdt_fun_table_win10[37].fun_addr)(
		ThreadHandle,
		ThreadInformationClass,
		ThreadInformation,
		ThreadInformationLength,
		ReturnLength
		);
	if (!NT_SUCCESS(status)) return status;
	 
	if (ThreadInformationLength == sizeof(CONTEXT32_SR))
	{
		KDbgPrint("DetourNtQueryInformationThread ThreadInformationLength=%d ThreadInformationClass=%d\n ", ThreadInformationLength, ThreadInformationClass);
	}

	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		if (ThreadInformationClass == ThreadHideFromDebugger_Sr)
		{
			KDbgPrint("%s: pid=%d\n want to query ThreadHideFromDebugger info，the info has been seted!", __FUNCTION__, PsGetCurrentProcessId());
			*(BOOL*)ThreadInformation = TRUE;
		}
		if (ThreadInformationClass == 0x1d/*attention:32位进程获得线程的context*/)
		{
			KDbgPrint("%s: pid=%d\n want to get thread context, cleared dr0-dr7!", __FUNCTION__, PsGetCurrentProcessId());
			//CONTEXT SIZE =0X2cc
			//被调试进程才可以进行寄存器清0操作,调试器进程不可以清0，因为如果清0，调试器会认为已经设置的硬件断点不是自己下的。
			PCONTEXT32_SR pcontext32 = (PCONTEXT32_SR)ThreadInformation;
			pcontext32->Dr0 = 0;
			pcontext32->Dr1 = 0;
			pcontext32->Dr2 = 0;
			pcontext32->Dr3 = 0;
			pcontext32->Dr6 = 0;
			pcontext32->Dr7 = 0;
		}
	}

	return status;
}

NTSTATUS DetourNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS_SR SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
)
{
	NTSTATUS status = ((PFNtQuerySystemInformation)ssdt_fun_table_win10[54].fun_addr)(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
		);
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		KDbgPrint("%s: pid=%d\n want query debug info, has been cleared!", __FUNCTION__, PsGetCurrentProcessId());
		if (SystemInformationClass == SystemKernelDebuggerInformation_Sr)
		{
			if (SystemInformationLength >= 2)
			{
				*(BYTE*)SystemInformation = 0;			//KernelDebuggerEnabled
				*((BYTE*)SystemInformation + 1) = 1;	//KernelDebuggerNotPresent
			}
			else
				*(BYTE*)SystemInformation = 0;			//KernelDebuggerEnabled
		}
	}
	return status;
}


NTSTATUS DetourNtClose(HANDLE Handle)
{
	//针对用户层进程处于调试状态时调用ntclose函数关闭无效句柄时产生异常的反调试手段时通过在内核中修改代码完成的
	return ((PFNtClose)ssdt_fun_table_win10[15].fun_addr)(Handle);
}

NTSTATUS DetourNtYieldExecution()
{
	//强制让所有调用此函数的返回STATUS_NO_YIELD_PERFORMED
	//注意：32位的程序调用NtYieldExecution，的调用编号需要进行重定向
	auto status = ((PFNtYieldExecution)ssdt_fun_table_win10[70].fun_addr)();
	if (!NT_SUCCESS(status)) return status;
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		KDbgPrint("%s:status=0x%x\n", __FUNCTION__, status);
		return STATUS_NO_YIELD_PERFORMED;
	}
	return status;
}

NTSTATUS DetourNtGetContextThread(HANDLE hThread, PCONTEXT pContext)
{
	//只有64位的进程才会走这里,32位进程通过调用ntdll.NtQueryInformationThread 功能号为0X1D完成thread context获取
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur)) get_int3();

	NTSTATUS status = ((PFNtGetContextThread)ssdt_fun_table_win10[236].fun_addr)(hThread, pContext);
	if (!NT_SUCCESS(status)) return status;

	//PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		
		KDbgPrint("%s: debug info cleared!\n", __FUNCTION__);
		pContext->Dr0 = 0;
		pContext->Dr1 = 0;
		pContext->Dr2 = 0;
		pContext->Dr3 = 0;
		pContext->Dr6 = 0;
		pContext->Dr7 = 0;
	}
	return status;
}

NTSTATUS DetourNtSetContextThread(HANDLE ThreadHandle, PCONTEXT pContext)
{
	get_int3();
	NTSTATUS status = ((PFNtSetContextThread)ssdt_fun_table_win10[388].fun_addr)(ThreadHandle, pContext);
	return status;
}

NTSTATUS DetourNtCreateProcess(
	OUT PHANDLE           ProcessHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE             ParentProcess,
	IN BOOLEAN            InheritObjectTable,
	IN HANDLE             SectionHandle OPTIONAL,
	IN HANDLE             DebugPort OPTIONAL,
	IN HANDLE             ExceptionPort OPTIONAL
)
{
	//在win7及以后的64位操作系统上，用户层的CreateProcess函数已经不再调用此函数，目前尚未发现有此函数调用
	KDbgPrint("%s: call create process ", __FUNCTION__);
	NTSTATUS status = ((PFNtCreateProcess)ssdt_fun_table_win10[180].fun_addr)(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ParentProcess,
		InheritObjectTable,
		SectionHandle,
		DebugPort,
		ExceptionPort
		);
	return status;

}

NTSTATUS DetourNtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS_SR ProcessParameters,
	IN PVOID Parameter9,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST_SR AttributeList
)
{
	//win7及以后的64位windows操作系统，用户层的CreateProcess函数NtCreateUserProcess，但是目前尚有部分参数的含义不明确
	//ProcessParameters->ImagePathName记录了可执行文件的完整路径（用户层路径，例如"C：\\a.exe）
	KDbgPrint("%s: create process  %wZ\n", __FUNCTION__, ProcessParameters->ImagePathName);
	NTSTATUS status = ((PFNtCreateUserProcess)ssdt_fun_table_win10[195].fun_addr)(
		ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		CreateProcessFlags,
		CreateThreadFlags,
		ProcessParameters,
		Parameter9,
		AttributeList
		);
	return status;
}

NTSTATUS DetourNtOpenProcess(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
)
{
	//如果crack进程尝试打开protect进程则以无效的PID来拒绝
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	PEPROCESS peprocess_aim = NULL;
	NTSTATUS status_internel;
	if (is_crack_process(peprocess_cur))
	{
		status_internel = PsLookupProcessByProcessId(ClientId, &peprocess_aim);
		if (NT_SUCCESS(status_internel))
		{
			ObDereferenceObject(peprocess_aim);
			if (is_protect_process(peprocess_aim))
				return STATUS_INVALID_CID;
		}
	}

	NTSTATUS status = ((PFNtOpenProcess)ssdt_fun_table_win10[38].fun_addr)(
		ProcessHandle,
		AccessMask,
		ObjectAttributes,
		ClientId
		);

	return status;
}

NTSTATUS DetourNtOpenThread(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
)
{
	//如果crack进程尝试打开protect进程的线程则以无效的TID来拒绝
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	PEPROCESS peprocess_aim = NULL;
	PETHREAD  pethread_aim = NULL;
	NTSTATUS status_internel;
	if (is_crack_process(peprocess_cur))
	{
		//首先获得目标线程的ethread，然后根据ethread获得进程的eprocess
		status_internel = PsLookupThreadByThreadId(ClientId, &pethread_aim);
		if (NT_SUCCESS(status_internel))
		{
			ObDereferenceObject(pethread_aim);
			peprocess_aim = PsGetThreadProcess(pethread_aim);
			if (is_protect_process(peprocess_aim))
			{
				return STATUS_INVALID_CID;
			}
		}
	}
	NTSTATUS status = ((PFNtOpenThread)ssdt_fun_table_win10[296].fun_addr)(
		ThreadHandle,
		AccessMask,
		ObjectAttributes,
		ClientId
		);
	return status;
}

NTSTATUS DetourNtCreateTimer(
	OUT PHANDLE             TimerHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN TIMER_TYPE           TimerType
)
{
	//注意：32位和64位的NtCreateTimer都走这里，但是还有一个函数叫NtCreateTimer2，暂时不知道有何用途

	NTSTATUS status = ((PFNtCreateTimer)ssdt_fun_table_win10[189].fun_addr)(
		TimerHandle,
		DesiredAccess,
		ObjectAttributes,
		TimerType
		);
	return status;
}

NTSTATUS DetourNtDeviceIoControlFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
)
{
//WS2_32.DLL调用TCP或UDP函数发送和接收数据等操作在用户层会进入mswsock.dll而该dll的作用是做安全操作和管理，最终数据部分通过NtDeviceIoControlFile函数进入内核
//目前win10和win7中这些代码是不会变的
#define ControlCodeWspListen		0x1200b
#define ControlCodeWspBind			0x12003
#define ControlCodeWspSend			0x1201f
#define ControlCodeWspSendTo		0x12023
#define ControlCodeWspRecv			0x12017
#define ControlCodeWspRecvFrom		0x1201b

	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_protect_process(peprocess_cur))
	{
		switch (IoControlCode)
		{
		case ControlCodeWspSend:
			get_int3();
			break;
		case ControlCodeWspSendTo:
			get_int3();
			break;
		case ControlCodeWspRecv:
			get_int3();
			break;
		case ControlCodeWspRecvFrom:
			get_int3();
			break;
		}
	}

	NTSTATUS status = ((PFNtDeviceIoControlFile)ssdt_fun_table_win10[7].fun_addr)(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		IoControlCode,
		InputBuffer,
		InputBufferLength,
		OutputBuffer,
		OutputBufferLength
		);
	return status;
}


void CreateProcessNotify(
	__in HANDLE ParentId,
	__in HANDLE ProcessId,
	__in BOOLEAN Create
)
{
	NTSTATUS	status;
	PEPROCESS	process;

	status = PsLookupProcessByProcessId(ProcessId, &process);
	WCHAR image_name[522];
	if (NT_SUCCESS(status))
	{
		PUNICODE_STRING punicode_string = ((PUNICODE_STRING)(*(PUINT64)((UINT64)process + 0X468)));//0x468只针对win10_17763_253
		memset(image_name, 0, punicode_string->Length + sizeof(wchar_t));
		memcpy(image_name, punicode_string->Buffer, punicode_string->Length);
		if (Create)
		{
			if (can_protect(image_name))
				add_protect_process(process);
			if (can_crack(image_name))
				add_crack_process(process);
		}
		else
		{
			delete_crack_process(process);
			delete_protect_process(process);
		}
		ObDereferenceObject(process);
	}

}


NTSTATUS DriverEntry(PDRIVER_OBJECT pdriver_object, PUNICODE_STRING preg_path)
{
	//注意加载的顺序，所有的事情做完后才能进行改代码

	KDbgPrint("JcpDriver:loaded\n", preg_path->Buffer);

	pdriver_object->DriverUnload = (PDRIVER_UNLOAD)driver_unload;

	init_os_info();

	init_ssdt_fun_addr_table();

	init_shadow_ssdt_fun_addr_table();

	find_process("explorer.exe", &adps.explorer_pid);

	start_infinity_hook();

	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);

	test_add(1, 2);

	change_debug_port_offset(FALSE);

	replace_code(FALSE);

	disable_callback_register(FALSE);

	return STATUS_SUCCESS;
}

NTSTATUS driver_unload(PDRIVER_OBJECT pdriver_object)
{
	//卸载的时候注意：应当先恢复所有的代码，然后再完成后续操作

	KDbgPrint("JcpDriver:unloaded\n", pdriver_object->DriverName.Buffer);

	change_debug_port_offset(TRUE);

	replace_code(TRUE);

	disable_callback_register(TRUE);

	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, TRUE);

	IfhRelease();
	return STATUS_SUCCESS;
}

NTSTATUS communicate_to_user(DWORD type, PVOID data, DWORD length)
{
	//type的取值说明
	/*
	1-8需要带参数
	9-16不需要参数
		1：提供explorer.exe的pid
		2：设置一个白名单进程的完整路径（区分大小写）
		3：设置一个白名单的包含字符串（区分大小写）
		4：设置一个黑名单的进程的完整路径（区分大小写）
		5：设置一个黑名单的进程名包含的字符串（区分大小写）
		6：删除一个白名单设置项
		7：删除一个黑名单设置项
		8：读取所有设置项

		9：通过修改代码方式禁用 线程、进程、loadimage回调
		10：恢复通过改代码方式禁用的 线程、进程、loadimage回调
	*/
	if (type > 16 || type == 0) return STATUS_UNSUCCESSFUL;

	if (type < 9)
	{
		if (!MmIsAddressValid(data) || !MmIsAddressValid((PVOID)((DWORD)data + length))) return STATUS_UNSUCCESSFUL;
	}

	DWORD original = 0;

	switch (type)
	{
	case 1://修改explorer.exe进程的PID
		adps.explorer_pid = *(DWORD*)data;
		return STATUS_SUCCESS;
		break;
	case 2://设置一个白名单进程的完整路径（区分大小写）
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.protect_name_list[i].type == 0)
			{
				adps.protect_name_list[i].type = 1;
				wcscpy(adps.protect_name_list[i].str, (WCHAR*)data);
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 3://设置一个白名单的包含字符串（区分大小写）
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.protect_name_list[i].type == 0)
			{
				adps.protect_name_list[i].type = 2;
				wcscpy(adps.protect_name_list[i].str, (WCHAR*)data);
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 4://设置一个黑名单的进程的完整路径（区分大小写）
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.crack_name_list[i].type == 0)
			{
				adps.crack_name_list[i].type = 1;
				wcscpy(adps.crack_name_list[i].str, (WCHAR*)data);
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 5://设置一个黑名单的进程名包含的字符串（区分大小写）
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.crack_name_list[i].type == 0)
			{
				adps.crack_name_list[i].type = 2;
				wcscpy(adps.crack_name_list[i].str, (WCHAR*)data);
				return STATUS_SUCCESS;
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 6://删除一个白名单设置项
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.protect_name_list[i].type != 0)
			{
				if (wcscmp(adps.protect_name_list[i].str, (WCHAR*)data) == 0)
				{
					adps.protect_name_list[i].type = 0;
					memset(adps.protect_name_list[i].str, 0, 522 * sizeof(WCHAR));
					return STATUS_SUCCESS;
				}
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 7://删除一个黑名单设置项
		for (int i = 0; i < MAX_SIZE_WORK; i++)
		{
			if (adps.crack_name_list[i].type != 0)
			{
				if (wcscmp(adps.crack_name_list[i].str, (WCHAR*)data) == 0)
				{
					adps.crack_name_list[i].type = 0;
					memset(adps.crack_name_list[i].str, 0, 522 * sizeof(WCHAR));
					return STATUS_SUCCESS;
				}
			}
		}
		return STATUS_UNSUCCESSFUL;
		break;
	case 8:
		if (length != sizeof(ADPS)) return STATUS_UNSUCCESSFUL;
		memcpy(data, &adps, sizeof(ADPS));
		return STATUS_SUCCESS;
		break;
	case 9://通过修改代码方式禁用 线程、进程、loadimage回调
		disable_callback_register(FALSE);
		return STATUS_SUCCESS;
		break;
	case 10://恢复通过改代码方式禁用的 线程、进程、loadimage回调
		disable_callback_register(TRUE);
		return STATUS_SUCCESS;
		break;
	default:
		break;

	}

	return STATUS_UNSUCCESSFUL;
}

/*
todo:

黑名单openprocess白名单进程全部失败
黑名单openthread白名单线程全部失败
黑名单遍历白名单进程全部失败
黑名单遍历报名单线程全部失败
黑名单结束白名单进程全部失败
黑名单创建进程要进行提醒，交由操作人员判断
黑名单打开白名单文件全部拒绝
提供加载模块驱动级隐藏方案
驱动本身自动隐藏
禁止其它驱动注册EWT
“禁”止其他驱动注册回调
遍历进程时补充其他被隐藏的进程


debugobject的validmask清0问题
object hook问题解决
禁止注册回调
禁止infinate hook





需要hook的函数可以根据其他软件的习惯进行选择
*/