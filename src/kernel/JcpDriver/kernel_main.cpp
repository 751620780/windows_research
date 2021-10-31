#include "kernel_main.h"

/*
�û��㳣���ķ������ֶν��ܺ��ƽ�֮����
1.����peb.debugport��Ա�ķ����ԣ��ó�Աֵ���ں���ͨ��DbgkpMarkProcessPeb�����������ã��ƽ�֮����debugport��λʱ�ú�����������λ�ó�Ա���û���ʹ�õķ�ʽ�У�
		IsDebuggerPresentAPI
		IsDebuggerPresentPEB
		���HeapFlags
		���HeapForceFlags
		UnhandledExcepFilter
2.NtQueryInformationProcessϵ�У��ں˴��������̵�eprocess.DebugPort��Ա��ֵ���ƽ�֮����debugport��λʱ�ú�����������λ�������ڸú����н��й��ˡ���ssdt hook�Խ������
3.WUDFϵ�У�����64λ���̣����ں˴��������̵�eprocess.DebugPort��Ա��ֵ���ƽ�֮��ͬ��
4.NtSetInformationThread���ں˴�����޸�ethread.CrossThreadFlags.HideFromDebuggerλ���ƽ�֮����SSDT hook���˻����޸��ں˴����м��ñ���λ�Ĵ���
5.CloseHandle��close protected handle or illegal handel���ú�������NtClose�����������ں˴�����NtClose�������eprocess.DebugPort��ֵ���ƽ�֮����debugport��λʱ�ú�����������λ
6.NtYieldExecution���ú�����ⲻ�ȶ���һ�㲻�ᱻʹ�á��ƽ�֮����SSDT hook�ú�����ֱ�ӷ���STATUS_NO_YIELD_PERFORMED����
7.NtQueryObject��ͨ����ѯ����DebugObject������������ж��Ƿ��ڵ����У��ƽ�֮����SSDT hook�Խ�����й���
8.NtQuerySystemInformation�����Լ���Ƿ�����ں˵��������ƽ�֮����SSDT hook���Բ�ѯ��������޸�
9.SharedUserData��KernelDebugger��Ա���ں˻᲻�����޸ģ������Ҫ�޸��ں˴��룬�ƽ�֮�����޸��ں˴�����߲�ʹ���ں˵�����
10.Ӳ���ϵ㣺SSDT hook�Խ�����й���
11.���������ӽ��̡����������ض����̼��






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
	//debug port ��λ
	if (unload)
	{
		//�ָ�
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
	//�滻ָ���
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
	//32λ���̵�ϵͳ���ú�64λϵͳ���õ�ת����32λ���̵Ĳ��ֺ����ĵ��úŷ������ض��򣬵����ú����ı��ʲ�δ�����仯
	switch (SystemCallIndex)
	{
	case 0x10046:
		index = 0x46;
		break;
	case 0x3000f:
		index = 0xf;
		break;
	}

	//Shadow SSDT���� win10
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

	//SSDT ���� win10
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
	

	//�򿪻򴴽����ļ�������ʱ�����
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
	//ע��X86�µĺ���������X64�ں�̬�µĲ���������λ���ȷ����仯

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
	_In_    HANDLE  ProcessHandle,						//Ŀ����̵ľ��
	_Inout_ PVOID   *BaseAddress,						//�����ͷŵ��ڴ�Ļ�ַ��ָ��
	_Inout_ PSIZE_T RegionSize,							//�ͷŵ������С�������0��ϵͳ���ͷ������򡣷��غ��佫�����������ͷŴ�С
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
	//�Զ������û���ͨ�ŷ���
	if (ProcessInformationClass == 1000)
		return communicate_to_user((DWORD)ProcessHandle, ProcessInformation, ProcessInformationLength);
	//������������ϵͳ����
	NTSTATUS status = ((PFNtQueryInformationProcess)ssdt_fun_table_win10[25].fun_addr)(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength
		);
	if (!NT_SUCCESS(status)) return status;
	//������Ҫ�ƻ��Ľ��̣����������ع���
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur))
	{
		KDbgPrint("%s: pid=%d want to get process debug info, we cleared debug info!\n", __FUNCTION__, PsGetCurrentProcessId());
		switch (ProcessInformationClass)
		{
		case ProcessBasicInformation_Sr:
			if (ProcessInformationLength == sizeof(PROCESS_BASIC_INFORMATION64_SR))//64λ
			{
				auto p = (PPROCESS_BASIC_INFORMATION64_SR)ProcessInformation;
				if (adps.explorer_pid != 0)
					p->InheritedFromUniqueProcessId = adps.explorer_pid;
			}
			else if (ProcessInformationLength == sizeof(PROCESS_BASIC_INFORMATION32_SR))//32λ
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
			//�����Է�����queryobject������ѯdebugobject�����������������ʱ����Ҫ����
		}
		else if (ObjectInformationClass == ObjectTypesInformation_Sr)
		{
			//�����Է�����queryobject������ѯ�����ں˶���������������ҵ�debugobject����󽫶��������;��������0
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
	//32λ���������߳�������ʹ�õ���0x1d���ܺţ���ʱ��CONTEXT32��СΪ716�ֽ�
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pethread = NULL;
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	if (is_crack_process(peprocess_cur) && ThreadInformationClass == ThreadHideFromDebugger_Sr)
	{
		//У������Ϸ����������ʵ�������,��Ϊ���ط������α��������鿴�ú����Ƿ�hook

		//�߳̾�����Ϸ�
		status = ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, UserMode, &pethread, NULL);
		if (!NT_SUCCESS(status)) goto ORINGINAL_NTSETINFORMATIONTHREAD;
		ObDereferenceObject(pethread);
		//���Ȳ���ȷ
		if (ThreadInformationLength > 1) goto ORINGINAL_NTSETINFORMATIONTHREAD;
		//�ṩ��д���ַ��������ȷ
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
			KDbgPrint("%s: pid=%d\n want to query ThreadHideFromDebugger info��the info has been seted!", __FUNCTION__, PsGetCurrentProcessId());
			*(BOOL*)ThreadInformation = TRUE;
		}
		if (ThreadInformationClass == 0x1d/*attention:32λ���̻���̵߳�context*/)
		{
			KDbgPrint("%s: pid=%d\n want to get thread context, cleared dr0-dr7!", __FUNCTION__, PsGetCurrentProcessId());
			//CONTEXT SIZE =0X2cc
			//�����Խ��̲ſ��Խ��мĴ�����0����,���������̲�������0����Ϊ�����0������������Ϊ�Ѿ����õ�Ӳ���ϵ㲻���Լ��µġ�
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
	//����û�����̴��ڵ���״̬ʱ����ntclose�����ر���Ч���ʱ�����쳣�ķ������ֶ�ʱͨ�����ں����޸Ĵ�����ɵ�
	return ((PFNtClose)ssdt_fun_table_win10[15].fun_addr)(Handle);
}

NTSTATUS DetourNtYieldExecution()
{
	//ǿ�������е��ô˺����ķ���STATUS_NO_YIELD_PERFORMED
	//ע�⣺32λ�ĳ������NtYieldExecution���ĵ��ñ����Ҫ�����ض���
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
	//ֻ��64λ�Ľ��̲Ż�������,32λ����ͨ������ntdll.NtQueryInformationThread ���ܺ�Ϊ0X1D���thread context��ȡ
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
	//��win7���Ժ��64λ����ϵͳ�ϣ��û����CreateProcess�����Ѿ����ٵ��ô˺�����Ŀǰ��δ�����д˺�������
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
	//win7���Ժ��64λwindows����ϵͳ���û����CreateProcess����NtCreateUserProcess������Ŀǰ���в��ֲ����ĺ��岻��ȷ
	//ProcessParameters->ImagePathName��¼�˿�ִ���ļ�������·�����û���·��������"C��\\a.exe��
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
	//���crack���̳��Դ�protect����������Ч��PID���ܾ�
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
	//���crack���̳��Դ�protect���̵��߳�������Ч��TID���ܾ�
	PEPROCESS peprocess_cur = PsGetCurrentProcess();
	PEPROCESS peprocess_aim = NULL;
	PETHREAD  pethread_aim = NULL;
	NTSTATUS status_internel;
	if (is_crack_process(peprocess_cur))
	{
		//���Ȼ��Ŀ���̵߳�ethread��Ȼ�����ethread��ý��̵�eprocess
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
	//ע�⣺32λ��64λ��NtCreateTimer����������ǻ���һ��������NtCreateTimer2����ʱ��֪���к���;

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
//WS2_32.DLL����TCP��UDP�������ͺͽ������ݵȲ������û�������mswsock.dll����dll������������ȫ�����͹����������ݲ���ͨ��NtDeviceIoControlFile���������ں�
//Ŀǰwin10��win7����Щ�����ǲ�����
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
		PUNICODE_STRING punicode_string = ((PUNICODE_STRING)(*(PUINT64)((UINT64)process + 0X468)));//0x468ֻ���win10_17763_253
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
	//ע����ص�˳�����е������������ܽ��иĴ���

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
	//ж�ص�ʱ��ע�⣺Ӧ���Ȼָ����еĴ��룬Ȼ������ɺ�������

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
	//type��ȡֵ˵��
	/*
	1-8��Ҫ������
	9-16����Ҫ����
		1���ṩexplorer.exe��pid
		2������һ�����������̵�����·�������ִ�Сд��
		3������һ���������İ����ַ��������ִ�Сд��
		4������һ���������Ľ��̵�����·�������ִ�Сд��
		5������һ���������Ľ������������ַ��������ִ�Сд��
		6��ɾ��һ��������������
		7��ɾ��һ��������������
		8����ȡ����������

		9��ͨ���޸Ĵ��뷽ʽ���� �̡߳����̡�loadimage�ص�
		10���ָ�ͨ���Ĵ��뷽ʽ���õ� �̡߳����̡�loadimage�ص�
	*/
	if (type > 16 || type == 0) return STATUS_UNSUCCESSFUL;

	if (type < 9)
	{
		if (!MmIsAddressValid(data) || !MmIsAddressValid((PVOID)((DWORD)data + length))) return STATUS_UNSUCCESSFUL;
	}

	DWORD original = 0;

	switch (type)
	{
	case 1://�޸�explorer.exe���̵�PID
		adps.explorer_pid = *(DWORD*)data;
		return STATUS_SUCCESS;
		break;
	case 2://����һ�����������̵�����·�������ִ�Сд��
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
	case 3://����һ���������İ����ַ��������ִ�Сд��
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
	case 4://����һ���������Ľ��̵�����·�������ִ�Сд��
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
	case 5://����һ���������Ľ������������ַ��������ִ�Сд��
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
	case 6://ɾ��һ��������������
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
	case 7://ɾ��һ��������������
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
	case 9://ͨ���޸Ĵ��뷽ʽ���� �̡߳����̡�loadimage�ص�
		disable_callback_register(FALSE);
		return STATUS_SUCCESS;
		break;
	case 10://�ָ�ͨ���Ĵ��뷽ʽ���õ� �̡߳����̡�loadimage�ص�
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

������openprocess����������ȫ��ʧ��
������openthread�������߳�ȫ��ʧ��
��������������������ȫ��ʧ��
�����������������߳�ȫ��ʧ��
��������������������ȫ��ʧ��
��������������Ҫ�������ѣ����ɲ�����Ա�ж�
�������򿪰������ļ�ȫ���ܾ�
�ṩ����ģ�����������ط���
���������Զ�����
��ֹ��������ע��EWT
������ֹ��������ע��ص�
��������ʱ�������������صĽ���


debugobject��validmask��0����
object hook������
��ֹע��ص�
��ֹinfinate hook





��Ҫhook�ĺ������Ը������������ϰ�߽���ѡ��
*/