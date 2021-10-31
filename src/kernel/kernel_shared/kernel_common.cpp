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
	//todo��У�����
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
	if (ver.dwBuildNumber >= 17763)//1809�汾�Ժ�jmp ��ȥ��
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
	if (ver.dwBuildNumber >= 17763)//1809�汾�Ժ�
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
	//��ǰ�����shadow ssdt�ĵ�ַ�������汣�����ssdt��������������û��ϵ������һ���ṹ���С�����shadow ssdt�������ĵ�ַ
	return (PVOID)(addr+sizeof(SYSTEM_SERVICE_DESCIPTOR_TABLE_SR));
}

PVOID get_shadow_ssdt_fun_addr_by_index_x64(ULONG index)
{
	static PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR pshadow_ssdt = NULL;
	//win10�в�����ȷ�Ļ��SSSDT��ĵ�ַ��ĺ���ԭ��
	//win32k.sys���ڴ��ַֻ��GUI�̲߳Żᱻӳ����ڴ�
	//windows�л�õ�shadow ssdt��������ַ��ֻ����GUI�߳��вŻ�ӳ�����������ݣ�����õ�ַӳ���ʵ������Ȼ��ssdt�������������
	//��˻��֮ǰӦ���л���һ��GUI�����У�Ȼ���ٶ�ȡ��ַ�ڵ�����
	//�л���Ŀ����̵ķ����ǣ����ȵ���KeStackAttachProcess�л���Ŀ����̣�Ȼ���ٵ���KeUnstackDetachProcess���ص���ǰ����
	//������˵�ַ�󣬻���Ҫ�������ĵ�ַ��ת���������Ҫ�Ļ�������Ϊ���������û���ĺ�������ʵ���ϻ�ͨ��jmp��ת��win32kfull.sys�н��к�������
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


//δ���
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
	//����һ�������ڴ���������
	PMDL pmdl_new = IoAllocateMdl((PVOID)target_addr, length, FALSE, FALSE, NULL);
	PVOID paddr = NULL;
	if (pmdl_new == NULL)
	{
		KDbgPrint("%s: line=%d call IoAllocateMdl fun failed!\n", __FUNCTION__,__LINE__);
		return STATUS_UNSUCCESSFUL;
	}
	//Ϊ�����ڴ������������Ƿ�ҳ��
	MmBuildMdlForNonPagedPool(pmdl_new);
	//����������ʼ��ַ
	paddr = MmMapLockedPages(pmdl_new, KernelMode);
	KIRQL kirql = WPOFFx64();
	RtlCopyMemory(paddr, data_addr, length);
	WPONx64(kirql);
	MmUnmapLockedPages(paddr, pmdl_new);
	IoFreeMdl(pmdl_new);
	return STATUS_SUCCESS;

}

//����ֻ�ǲ���
int basic_add(int a)
{
	return a + 1;
}



NTSTATUS delete_file(const wchar_t * pfile_path)
{
	//ɾ���ļ����ļ�����ʽ�ο���pfile_path=L"\\??\\C:\\123.exe"
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
//PsGetProcessPeb			����PEB64�ĵ�ַ
//PsGetProcessWow64Process	���������wow64���̣�������peb32�ĵ�ַ

/*
todo:
�ں˶�д�û������
�ں˲���û����ͨ�ţ�ͨ���ں˻ص���ʽ���ͨ�ţ�
�ں˲�dllע��
ʵ���û���Ĵ�����x64��x86�µĵ���ת��

�ں˻ص���
nt!KeUserModeCallback->nt!KiCallUserMode->nt!KiSystemServiceExit(...,nt!KeUserCallbackDispatcher,...)ע�⣺nt!KeUserCallbackDispatcher������ntdll!KeUserCallbackDispatcher�����ĵ�ַ
->swapgs;sysret;ָ��ص��û����ntdll!KeUserCallbackDispatcher������->call xxx;Ȼ����xxx������ͨ��jmp raxָ����ûص�����
->�ص�����������Ϻ��ص�ntdll!KeUserCallbackDispatcher->call ntdll!ZwCallbackReturn�����ں˲�

*/
