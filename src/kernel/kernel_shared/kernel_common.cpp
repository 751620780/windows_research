#include "kernel_common.h"


NTSTATUS get_nt_driver_info(PSYSTEM_MODULE_INFORMATION_SR pnt_driver_info)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PSYSTEM_MODULE_INFO_LIST_SR pnt_module_info_list = NULL;
	ULONG ulLength = 0;

	status = ZwQuerySystemInformation(SystemModuleInformation_Sr, pnt_module_info_list, ulLength, &ulLength);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return STATUS_UNSUCCESSFUL;
	}

	pnt_module_info_list = (PSYSTEM_MODULE_INFO_LIST_SR)ExAllocatePool(NonPagedPool, ulLength);
	if (NULL == pnt_module_info_list)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation_Sr, pnt_module_info_list, ulLength, &ulLength);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pnt_module_info_list);
		return STATUS_UNSUCCESSFUL;
	}

	memcpy(pnt_driver_info, &pnt_module_info_list->smi[0], sizeof(SYSTEM_MODULE_INFORMATION_SR));

	ExFreePool(pnt_module_info_list);

	return STATUS_SUCCESS;
}

UINT64 walk_driver_ldr(PDRIVER_OBJECT pdriver_object)
{
	//todo：校验参数
	PDRIVER_OBJECT_SR pdrobj = (PDRIVER_OBJECT_SR)pdriver_object;
	UINT64 ret = 0;
	LDR_DATA_TABLE_ENTRY_SR *pldr = NULL;

	for (
		PLIST_ENTRY plist = pdrobj->DriverSection->InLoadOrderLinks.Flink;
		plist != &(pdrobj->DriverSection->InLoadOrderLinks);
		plist = plist->Flink)
	{
		if (plist == NULL) continue;
		pldr = (PLDR_DATA_TABLE_ENTRY_SR)plist;
		
	}

	return 0;
}

PEPROCESS find_process(IN const char* process_image_file_name, OUT OPTIONAL PDWORD pprocess_pid)
{
	ULONG pid;
	NTSTATUS status;
	PEPROCESS peprocess_find,peprocess_ret=NULL;
	for (pid = 0; pid <= 240000; pid += 4)
	{
		status = PsLookupProcessByProcessId((HANDLE)pid, &peprocess_find);
		if (NT_SUCCESS(status))
		{
			if (strcmp((CHAR*)PsGetProcessImageFileName(peprocess_find), process_image_file_name) == 0)
			{
				peprocess_ret = peprocess_find;
				if(pprocess_pid) *pprocess_pid = pid;
			}
			ObDereferenceObject(peprocess_find);
		}
		if (peprocess_ret) return peprocess_ret;
	}
	return NULL;
}


PVOID get_system_service_descriptor_table_addr_x64()
{
	PUCHAR start_search_addr = NULL;
	PUCHAR end_search_addr = NULL;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	LONG tmp_long = 0;
	ULONGLONG addr = 0;
	RTL_OSVERSIONINFOW ver = { 0 };

	ver.dwOSVersionInfoSize = sizeof(ver);

	RtlGetVersion(&ver);
	start_search_addr = (PUCHAR)__readmsr(0XC0000082);
	if (ver.dwBuildNumber >= 17763)//1809版本以后jmp 过去了
	{

		for (i = start_search_addr; i < start_search_addr + 0x500; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				b1 = *i;
				b2 = *(i + 5);
				if (b1 == 0xe9 && b2 == 0xc3)
				{
					memcpy(&tmp_long, i + 1, 4);
					start_search_addr = i + 5 + tmp_long;
					break;
				}
			}
		}
	}
	for (i = start_search_addr; i < start_search_addr + 0x500; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&tmp_long, i + 3, 4);
				addr = (ULONGLONG)tmp_long + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	KDbgPrint("%s SSDT addr=0x%p\n", __FUNCTION__, addr);
	return (PVOID)addr;
}

PVOID get_ssdt_fun_addr_by_index_x64(ULONG index)
{
	static PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR pssdt = NULL;
	if (pssdt == NULL)pssdt = (PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR)get_system_service_descriptor_table_addr_x64();
	if (pssdt == NULL) return NULL;
	PULONG fun_array = pssdt->ServiceTableBase;
	if (index >= pssdt->NumberOfService) return NULL;
	LONG tmp = fun_array[index];
	tmp = tmp >> 4;
	PVOID ret = (PVOID)((UINT64)tmp + (UINT64)fun_array);
	KDbgPrint("%s line=%d fun_index=%d fun_addr=0x%p\n", __FUNCTION__, __LINE__, index, ret);
	return ret;
}

PVOID get_shadow_system_service_descriptor_table_addr_x64()
{
	PUCHAR start_search_addr = NULL;
	PUCHAR end_search_addr = NULL;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	LONG tmp_long = 0;
	ULONGLONG addr = 0;
	RTL_OSVERSIONINFOW ver = { 0 };

	ver.dwOSVersionInfoSize = sizeof(ver);

	RtlGetVersion(&ver);
	start_search_addr = (PUCHAR)__readmsr(0XC0000082);
	if (ver.dwBuildNumber >= 17763)//1809版本以后
	{

		for (i = start_search_addr; i < start_search_addr + 0x500; i++)
		{
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
			{
				b1 = *i;
				b2 = *(i + 5);
				if (b1 == 0xe9 && b2 == 0xc3)
				{
					memcpy(&tmp_long, i + 1, 4);
					start_search_addr = i + 5 + tmp_long;
					break;
				}
			}
		}
	}
	for (i = start_search_addr; i < start_search_addr + 0x500; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d)
			{
				memcpy(&tmp_long, i + 3, 4);
				addr = (ULONGLONG)tmp_long + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	KDbgPrint("%s Shadow SSDT addr=0x%p\n", __FUNCTION__, addr);
	//当前获得了shadow ssdt的地址但是里面保存的是ssdt的描述符，不过没关系，增加一个结构体大小后就是shadow ssdt描述符的地址
	return (PVOID)(addr+sizeof(SYSTEM_SERVICE_DESCIPTOR_TABLE_SR));
}

PVOID get_shadow_ssdt_fun_addr_by_index_x64(ULONG index)
{
	static PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR pshadow_ssdt = NULL;
	//win10中不能正确的获得SSSDT表的地址里的函数原因：
	//win32k.sys的内存地址只有GUI线程才会被映射该内存
	//windows中获得的shadow ssdt描述符地址后只有在GUI线程中才会映射真正的数据，否则该地址映射的实际上依然是ssdt描述符表的内容
	//因此获得之前应当切换到一个GUI进程中，然后再读取地址内的数据
	//切换到目标进程的方法是：首先调用KeStackAttachProcess切换到目标进程，然后再调用KeUnstackDetachProcess返回到当前进程
	//当获得了地址后，还需要做函数的地址的转换（如果需要的话），因为对于来自用户层的函数调用实际上会通过jmp跳转到win32kfull.sys中进行后续任务
	if (pshadow_ssdt == NULL)pshadow_ssdt = (PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR)get_shadow_system_service_descriptor_table_addr_x64();

	PEPROCESS peprocess_csrss=find_process("csrss.exe");
	KAPC_STATE apc_old = { 0 ,};
	KeStackAttachProcess(peprocess_csrss, &apc_old);
	if (pshadow_ssdt == NULL) return NULL;
	PULONG fun_array = pshadow_ssdt->ServiceTableBase;
	if (index >= pshadow_ssdt->NumberOfService) return NULL;
	LONG tmp = fun_array[index];
	tmp = tmp >> 4;
	PVOID ret = (PVOID)((UINT64)tmp + (UINT64)fun_array);
	KeUnstackDetachProcess(&apc_old);
	KDbgPrint("%s line=%d fun_index=%d fun_addr=0x%p\n", __FUNCTION__,__LINE__, index, ret);
	return ret;
}


//未完成
NTSTATUS create_device(PDRIVER_OBJECT pdriver_object, PUNICODE_STRING pdevice_name, PUNICODE_STRING psymbolic_link_name, PDEVICE_OBJECT pdevice_object)
{
	NTSTATUS status = IoCreateDevice(pdriver_object, 0, pdevice_name, FILE_DEVICE_UNKNOWN, 0, TRUE, &pdevice_object);
	if (!NT_SUCCESS(status))
	{
		KDbgPrint("%s:IoCreateDevice failed!\n", __FUNCTION__);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	pdevice_object->Flags |= DO_BUFFERED_IO;

	status = IoCreateSymbolicLink(psymbolic_link_name, pdevice_name);
	if (!NT_SUCCESS(status))
	{
		KDbgPrint("%s:IoCreateSymbolicLink failed!\n", __FUNCTION__);
		IoDeleteDevice(pdevice_object);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	
	return STATUS_UNSUCCESSFUL;
}


KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}


void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

NTSTATUS write_kernel_memory(PVOID target_addr, PVOID data_addr, int length)
{
	//创建一个虚拟内存描述符表
	PMDL pmdl_new = IoAllocateMdl((PVOID)target_addr, length, FALSE, FALSE, NULL);
	PVOID paddr = NULL;
	if (pmdl_new == NULL)
	{
		KDbgPrint("%s: line=%d call IoAllocateMdl fun failed!\n", __FUNCTION__,__LINE__);
		return STATUS_UNSUCCESSFUL;
	}
	//为虚拟内存描述符表创建非分页池
	MmBuildMdlForNonPagedPool(pmdl_new);
	//获得虚拟的起始地址
	paddr = MmMapLockedPages(pmdl_new, KernelMode);
	KIRQL kirql = WPOFFx64();
	RtlCopyMemory(paddr, data_addr, length);
	WPONx64(kirql);
	MmUnmapLockedPages(paddr, pmdl_new);
	IoFreeMdl(pmdl_new);
	return STATUS_SUCCESS;

}

//仅仅只是测试
int basic_add(int a)
{
	return a + 1;
}



NTSTATUS delete_file(const wchar_t * pfile_path)
{
	//删除文件的文件名格式参考：pfile_path=L"\\??\\C:\\123.exe"
	UNICODE_STRING file_path = {0};
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES obja = { 0 };
	RtlInitUnicodeString(&file_path, pfile_path);
	InitializeObjectAttributes(&obja, &file_path, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwDeleteFile(&obja);
	if (!NT_SUCCESS(status))
	{
		KDbgPrint("delete file failed! status = [%d]", status);
	}
	return status;
}

NTSTATUS copy_file(const wchar_t *psource_file_path, const wchar_t *ptarget_file_path)
{
	//todo
	return STATUS_UNSUCCESSFUL;
}

//KeStackAttachProcess
//KeUnstackDetachProcess
//PsGetProcessPeb			返回PEB64的地址
//PsGetProcessWow64Process	如果进程是wow64进程，将返回peb32的地址

/*
todo:
内核读写用户层代码
内核层和用户层的通信（通过内核回调方式完成通信）
内核层dll注入
实现用户层的代码在x64和x86下的调用转换

内核回调：
nt!KeUserModeCallback->nt!KiCallUserMode->nt!KiSystemServiceExit(...,nt!KeUserCallbackDispatcher,...)注意：nt!KeUserCallbackDispatcher保存了ntdll!KeUserCallbackDispatcher函数的地址
->swapgs;sysret;指令返回到用户层的ntdll!KeUserCallbackDispatcher函数处->call xxx;然后在xxx函数中通过jmp rax指令调用回调函数
->回调函数调用完毕后会回到ntdll!KeUserCallbackDispatcher->call ntdll!ZwCallbackReturn返回内核层

*/
