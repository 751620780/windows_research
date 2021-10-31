#pragma once
//���ͷ�ļ���Ҫ�����һЩ�������ܵ�ʵ�ֺͲ�����Ҫ���ں˵���ĺ���
#ifndef COMMON_H
#define COMMON_H
#include "kernel_pch.h"
#include "kernel_sr.h"

struct _OS_INFO;
struct _CODE_MODIFY_ENTRY;
struct _CODE_REPLACE_ENTRY;
struct _CODE_NOP_ENTRY;
struct _INLINE_HOOK_ENTRY;
struct _FUN_INFO_ENTRY;
struct _REG_STRING;
struct _ADPS;

#define MAX_SIZE_WORK 15

#ifdef DBG
#define KDbgPrint DbgPrint													//debug����ģʽ�½����������Ϣ
#else
#define KDbgPrint(format,...)												//Release����ģʽ�²������������Ϣ
#endif



typedef struct _OS_INFO
{
	UINT		os_version;													//��ǰ����ϵͳ�İ汾
	SYSTEM_MODULE_INFORMATION_SR	nt_driver_info;							//nt�ں�ģ��Ļ�ַ,��С����Ϣ
	struct
	{
		ULONG major;														//���汾��
		ULONG minor;														//�ΰ汾��
		ULONG build;														//build�汾�ţ���Ҫ
		UNICODE_STRING csd;													//??
	};
	UINT		debug_object_index;											//�����ں˶����index
	UINT		process_object_index;										//�����ں˶����index
	UINT		thread_object_index;										//�߳��ں˶����index
	PVOID		pob_type_index_table;										//����nt!ObTypeIndexTable�ĵ�ַ��nt!ObTypeIndexTable��¼��һ������ĵ�ַ����������������ں˶���� _OBJECT_TYPE��
	PVOID		pdbgk_debug_object_type;									//����nt!DbgkDebugObjectType�ĵ�ַ��nt!DbgkDebugObjectType�ǵ����ں˶���� POBJECT_TYPE��
	PVOID		pps_process_type;											//����nt!PsProcessType�ĵ�ַ��nt!PsProcessType�����˽����ں˶���� POBJECT_TYPE��
	PVOID		pps_thread_type;											//����nt!PsThreadType�ĵ�ַ��nt!PsThreadType�������߳��ں˶���� POBJECT_TYPE��
	PVOID		ppsp_cid_table;												//����nt!PspCidTable�ĵ�ַ��nt!PspCidTable������nt!_HANDLE_TABLE�ĵ�ַ
	PVOID		pPspNotifyEnableMask;										//����PspNotifyEnableMask�ĵ�ַ��win10_17763_offset=FFFFF8073A778534-0xFFFFF80739E0B000
}OS_INFO, *POS_INFO;


typedef struct _CODE_MODIFY_ENTRY											//ָ��ӹ̣�ֻ���޸Ĳ����������޸Ĳ����룬���Ҳ�����һ����ƫ��
{
	UINT64		code_rva;													//�ӹ�ָ���rva
	char		operate_code[8];											//va����ָ�������											
	UINT8		offset;														//��Ҫ�ӹ̵Ĵ���λ��ָ���ƫ��(��������ĳ���)
	UINT8		data_length;												//�޸ĵ����ݵĳ���
	UINT64		ori_data;													//ԭʼ���ݣ���code_va+offset���޸ģ�д�����ݳ���λdata_length
	UINT64		new_data;													//�����ݣ��ӹ̺�����ݣ���new_data���ܻ����ʵ�������Ҫ��̬����
	UINT8		status;														//�������
}CODE_MODIFY_ENTRY, *PCODE_MODIFY_ENTRY;


typedef struct _CODE_REPLACE_ENTRY											//ָ���滻�����޸�ָ�����Ҳ���ܷ����ı�
{
	UINT64		code_rva;													//Ҫ�޸ĵĴ����rva
	UINT8		ori_length;													//ԭʼ���볤��
	UINT8		new_length;													//�´��볤��
	char		ori_code[30];												//ԭʼ������ֽ���
	char		new_code[30];												//�´�����ֽ���
	UINT8		status;														//�������
}CODE_REPLACE_ENTRY, *PCODE_REPLACE_ENTRY;


typedef struct _CODE_NOP_ENTRY												//ָ��nop
{
	UINT64		code_rva;													//Ҫ�޸ĵĴ����rva
	UINT8		ori_length;													//ԭʼ���볤��,����У��
	UINT8		new_length;													//�´��볤�ȣ��Ὣ�ó��ȵ��ֽ����滻��90h
	char		ori_code[30];												//ԭʼ������ֽ��룬������дori_length���ֽ�
	UINT8		status;														//�������
}CODE_NOP_ENTRY, *PCODE_NOP_ENTRY;

typedef struct _INLINE_HOOK_ENTRY
{
	UINT64		code_rva;													//��hook�ĺ�������ʼ��ַ
	UINT64		jmp_addr;													//hook��ɺ�Ҫ��ת����detour������ַ
	char		original_data[15];											//hook��ɺ�����hookǰ���ֽ���
	UINT8		status;														//�������
}INLINE_HOOK_ENTRY, PINLINE_HOOK_ENTRY;

typedef struct _FUN_INFO_ENTRY
{
	PVOID fun_addr;															//������ַ
	PVOID detour_fun_addr;													//��������hookʱ���������detour����
	UNICODE_STRING fun_name;												//����������
}FUN_INFO_ENTRY, *PFUN_INFO_ENTRY;

typedef struct _REG_STRING
{
	UINT8  type;															//0:��Ч��1��ƥ�����ȫ·�������ִ�Сд����2������·���а����ַ��������ִ�Сд��
	WCHAR  str[261*2];														//�����ַ����Ļ�����
}REG_STRING,*PREG_STRING;

typedef struct _HOOK_ENTRY
{
	UINT64  hook_addr_rva;
	UINT64	detour_addr;
}HOOK_ENTRY,*PHOOK_ENTRY;

typedef struct _ADPS														//ANDY DEBUG PROTECT SYSTEM
{
	UINT8			kernel_mode_debug_port_protect;							//�Ƿ����ں˵�debugport����
	UINT8			user_mode_debug_port_protect;							//�Ƿ����û����debugport����
	DWORD			explorer_pid;											//����explorer.exe���̵�pid
	PEPROCESS		process_protect[MAX_SIZE_WORK];							//��Ҫ�����ĵ��������̵�EPROCESS��ַ����
	PEPROCESS		process_crack[MAX_SIZE_WORK];							//��Ҫ�������ԵĽ��̵�EPROCESS��ַ����
	REG_STRING		protect_name_list[MAX_SIZE_WORK];
	REG_STRING		crack_name_list[MAX_SIZE_WORK];
	REG_STRING		process_name_create_forbid[MAX_SIZE_WORK];				//��ֹ�������Ľ��̵���������������û��������·��

}ADPS,*PADPS;




NTSTATUS get_nt_driver_info(PSYSTEM_MODULE_INFORMATION_SR pnt_driver_info);

UINT64 walk_driver_ldr(PDRIVER_OBJECT pdriver_object);

extern "C" int basic_add(int a);

PEPROCESS find_process(IN const char* process_image_file_name, OUT OPTIONAL PDWORD pprocess_pid=NULL);

//�ر�д����
extern "C" KIRQL WPOFFx64();
//����д����
extern "C" void WPONx64(KIRQL irql);

NTSTATUS write_kernel_memory(PVOID target_addr, PVOID data_addr, int length);

extern "C" PVOID get_system_service_descriptor_table_addr_x64();

extern "C" PVOID get_ssdt_fun_addr_by_index_x64(ULONG index);

extern "C" PVOID get_shadow_system_service_descriptor_table_addr_x64();

extern "C" PVOID get_shadow_ssdt_fun_addr_by_index_x64(ULONG index);

//���ڲ��Ի������ܷ�����ʹ��
extern "C" DWORD  test_add(int a, int b);

//���һ��int 3�ϵ�
extern "C" void get_int3();

//ʹ��ZwDeleteFile����ļ���ɾ�����ú����޷�ǿ��ɾ���ļ�
//ɾ���ļ����ļ�����ʽ�ο���pfile_path=L"\\??\\C:\\123.exe"
NTSTATUS delete_file(const wchar_t * pfile_path);

NTSTATUS copy_file(const wchar_t *psource_file_path, const wchar_t *ptarget_file_path);

extern "C" NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS_SR SystemInformationClass,						//���õĹ��ܺ�
	PVOID SystemInformation,												//�������ڴ�����ݵĵ�ַ
	ULONG SystemInformationLength,											//���ڴ�����ݵ��ڴ��С
	PULONG ReturnLength														//�ɹ���ɹ��ܵ�������Ҫ��ʵ���ڴ��С
);


extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(											//ͨ�����������ֵõ������Ķ���ָ��
	PUNICODE_STRING ObjectName,												//�����豸�����֣����硰L"\\Driver\\Kbdclass"������ע�����������·��
	ULONG Attributes,														//
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,												//�ṩ��������object_type�ṹ��ĵ�ַ����object_type�ṹ���ɲ���ϵͳ�ں�����¼��
	KPROCESSOR_MODE AccessMod,												//��дKernelMode
	PVOID ParseContext,														//NULL
	PVOID *Object															//�������������ָ�룬��driver_object*
);

extern "C" NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

#endif


/*
���ܽ��ܣ�
�ں���ǰ����Ϻ� _IRQL_requires_max_(APC_LEVEL) ������ߺ���ִ�е�APC���𣬷�ֹ����ϡ�
*/


//nt!DbgkDebugObjectType��win7 ntģ��+208F40���õ�ַ��¼�˵��Զ����_OBJECT_TYPE�ṹ��ĵ�ַ,_OBJECT_TYPE.TypeInfo.ValidAccessMask��Ա��ֵ�ᱻ��0����ȷ��ֵӦ����0x1f000f
//pdriver_object->DriverSection->InLoadOrderLink�����������ں�ģ��
//ZwQuerySystemInformation���������е�ģ����Ϣ
//nt!PsLoadedModuleList ��һ��ldr��list_entry�����driver_object.DriverSection->InLoadOrderLink����һ�¡�ֻ����������һ��ȫ�ֱ���������˫�������ͷ
//���е��ں˶���������;�������ĸ���Ӧ�����ɸýṹ���е�padding1��padding2
//���еĶ��ں˶���ethread.debugobject�Ķ�ȡ��д��Ĵ����ƫ�ƶ�Ӧ��������λ���ƶ���eprocess��ʹ�õ��ڴ�����_PADDING0_�������Ԫ�صĵ�ַһ�㲻��ʹ��
//����������еĶ�ĳ�ṹ���ĳ�����ʹ�ã�
		//1.���pdb��SymbolTypeViewer���߽�����c����ͷ�ļ����������������е�ƫ��Ϊxxx�ĳ�Ա�����ж���
		//2.��IDA��ͬ����������������С��ģ������еĴ��롣
		//3.ʹ��Ӳ���ϵ��ȡ�����жϺ�ȷ��
//����Ŀ����������̲����򿪣���֤�����Խ����Ƿ��н��̱���
//�滻���е��ں��жϱ�
//SSDT hook������µķ�����
//�ں����أ�
//ȥ��object hook
//�ӹ����еĻص�������̴����ص���ģ����ػص�
//���ڽ����ڵ��ں˻ص�Ӧ�������޸�
//���Ŀ����̵��û���Ĳ��������¼��Ĵ����Ƿ�۸Ľ����޸�
//���IDT hook��취��ԭ
//����������������ͨ�ŷ�ʽ



/*
1.������е����͵��ں˶����_OBJECT_TYPE��
nt!ObTypeIndexTable=nt+22A340 ��һ��8�ֽ�Ϊ��λ�����飬���±�Ϊ2��ʼ��¼��ÿһ���ں˶����_OBJECT_TYPE��Ϣ

*/