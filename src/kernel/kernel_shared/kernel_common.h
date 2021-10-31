#pragma once
//这个头文件主要完成了一些基本功能的实现和部分需要从内核导入的函数
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
#define KDbgPrint DbgPrint													//debug生成模式下将输出调试信息
#else
#define KDbgPrint(format,...)												//Release生成模式下不会输出调试信息
#endif



typedef struct _OS_INFO
{
	UINT		os_version;													//当前操作系统的版本
	SYSTEM_MODULE_INFORMATION_SR	nt_driver_info;							//nt内核模块的基址,大小等信息
	struct
	{
		ULONG major;														//主版本号
		ULONG minor;														//次版本号
		ULONG build;														//build版本号，重要
		UNICODE_STRING csd;													//??
	};
	UINT		debug_object_index;											//调试内核对象的index
	UINT		process_object_index;										//进程内核对象的index
	UINT		thread_object_index;										//线程内核对象的index
	PVOID		pob_type_index_table;										//保存nt!ObTypeIndexTable的地址，nt!ObTypeIndexTable记录了一个数组的地址，该数组包含所有内核对象的 _OBJECT_TYPE，
	PVOID		pdbgk_debug_object_type;									//保存nt!DbgkDebugObjectType的地址，nt!DbgkDebugObjectType是调试内核对象的 POBJECT_TYPE，
	PVOID		pps_process_type;											//保存nt!PsProcessType的地址，nt!PsProcessType保存了进程内核对象的 POBJECT_TYPE，
	PVOID		pps_thread_type;											//保存nt!PsThreadType的地址，nt!PsThreadType保存了线程内核对象的 POBJECT_TYPE，
	PVOID		ppsp_cid_table;												//保存nt!PspCidTable的地址，nt!PspCidTable保存了nt!_HANDLE_TABLE的地址
	PVOID		pPspNotifyEnableMask;										//保存PspNotifyEnableMask的地址，win10_17763_offset=FFFFF8073A778534-0xFFFFF80739E0B000
}OS_INFO, *POS_INFO;


typedef struct _CODE_MODIFY_ENTRY											//指令加固，只能修改操作数，不修改操作码，而且操作数一般是偏移
{
	UINT64		code_rva;													//加固指令的rva
	char		operate_code[8];											//va处的指令操作码											
	UINT8		offset;														//需要加固的代码位于指令的偏移(即操作码的长度)
	UINT8		data_length;												//修改的数据的长度
	UINT64		ori_data;													//原始数据，从code_va+offset处修改，写入数据长度位data_length
	UINT64		new_data;													//新数据（加固后的数据），new_data可能会根据实际情况需要动态计算
	UINT8		status;														//操作结果
}CODE_MODIFY_ENTRY, *PCODE_MODIFY_ENTRY;


typedef struct _CODE_REPLACE_ENTRY											//指令替换，将修改指令，长度也可能发生改变
{
	UINT64		code_rva;													//要修改的代码的rva
	UINT8		ori_length;													//原始代码长度
	UINT8		new_length;													//新代码长度
	char		ori_code[30];												//原始代码的字节码
	char		new_code[30];												//新代码的字节码
	UINT8		status;														//操作结果
}CODE_REPLACE_ENTRY, *PCODE_REPLACE_ENTRY;


typedef struct _CODE_NOP_ENTRY												//指令nop
{
	UINT64		code_rva;													//要修改的代码的rva
	UINT8		ori_length;													//原始代码长度,用于校验
	UINT8		new_length;													//新代码长度，会将该长度的字节码替换成90h
	char		ori_code[30];												//原始代码的字节码，至少填写ori_length个字节
	UINT8		status;														//操作结果
}CODE_NOP_ENTRY, *PCODE_NOP_ENTRY;

typedef struct _INLINE_HOOK_ENTRY
{
	UINT64		code_rva;													//被hook的函数的起始地址
	UINT64		jmp_addr;													//hook完成后要跳转到的detour函数地址
	char		original_data[15];											//hook完成后保留的hook前的字节码
	UINT8		status;														//操作结果
}INLINE_HOOK_ENTRY, PINLINE_HOOK_ENTRY;

typedef struct _FUN_INFO_ENTRY
{
	PVOID fun_addr;															//函数地址
	PVOID detour_fun_addr;													//当函数被hook时，保存的是detour函数
	UNICODE_STRING fun_name;												//函数的名字
}FUN_INFO_ENTRY, *PFUN_INFO_ENTRY;

typedef struct _REG_STRING
{
	UINT8  type;															//0:无效，1：匹配进程全路径（区分大小写），2：进程路径中包含字符串（区分大小写）
	WCHAR  str[261*2];														//保存字符串的缓冲区
}REG_STRING,*PREG_STRING;

typedef struct _HOOK_ENTRY
{
	UINT64  hook_addr_rva;
	UINT64	detour_addr;
}HOOK_ENTRY,*PHOOK_ENTRY;

typedef struct _ADPS														//ANDY DEBUG PROTECT SYSTEM
{
	UINT8			kernel_mode_debug_port_protect;							//是否开启内核的debugport保护
	UINT8			user_mode_debug_port_protect;							//是否开启用户层的debugport保护
	DWORD			explorer_pid;											//保存explorer.exe进程的pid
	PEPROCESS		process_protect[MAX_SIZE_WORK];							//需要保护的调试器进程的EPROCESS地址数组
	PEPROCESS		process_crack[MAX_SIZE_WORK];							//需要反反调试的进程的EPROCESS地址数组
	REG_STRING		protect_name_list[MAX_SIZE_WORK];
	REG_STRING		crack_name_list[MAX_SIZE_WORK];
	REG_STRING		process_name_create_forbid[MAX_SIZE_WORK];				//禁止被创建的进程的名单，保存的是用户层的完整路径

}ADPS,*PADPS;




NTSTATUS get_nt_driver_info(PSYSTEM_MODULE_INFORMATION_SR pnt_driver_info);

UINT64 walk_driver_ldr(PDRIVER_OBJECT pdriver_object);

extern "C" int basic_add(int a);

PEPROCESS find_process(IN const char* process_image_file_name, OUT OPTIONAL PDWORD pprocess_pid=NULL);

//关闭写保护
extern "C" KIRQL WPOFFx64();
//开启写保护
extern "C" void WPONx64(KIRQL irql);

NTSTATUS write_kernel_memory(PVOID target_addr, PVOID data_addr, int length);

extern "C" PVOID get_system_service_descriptor_table_addr_x64();

extern "C" PVOID get_ssdt_fun_addr_by_index_x64(ULONG index);

extern "C" PVOID get_shadow_system_service_descriptor_table_addr_x64();

extern "C" PVOID get_shadow_ssdt_fun_addr_by_index_x64(ULONG index);

//用于测试汇编代码能否正常使用
extern "C" DWORD  test_add(int a, int b);

//获得一个int 3断点
extern "C" void get_int3();

//使用ZwDeleteFile完成文件的删除。该函数无法强制删除文件
//删除文件的文件名格式参考：pfile_path=L"\\??\\C:\\123.exe"
NTSTATUS delete_file(const wchar_t * pfile_path);

NTSTATUS copy_file(const wchar_t *psource_file_path, const wchar_t *ptarget_file_path);

extern "C" NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS_SR SystemInformationClass,						//调用的功能号
	PVOID SystemInformation,												//传入用于存放数据的地址
	ULONG SystemInformationLength,											//用于存放数据的内存大小
	PULONG ReturnLength														//成功完成功能调用所需要的实际内存大小
);


extern "C" NTKERNELAPI NTSTATUS ObReferenceObjectByName(											//通过驱动的名字得到驱动的对象指针
	PUNICODE_STRING ObjectName,												//驱动设备的名字，形如“L"\\Driver\\Kbdclass"”，即注册表下驱动的路径
	ULONG Attributes,														//
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,												//提供该驱动的object_type结构体的地址。此object_type结构体由操作系统内核所记录。
	KPROCESSOR_MODE AccessMod,												//填写KernelMode
	PVOID ParseContext,														//NULL
	PVOID *Object															//返回驱动对象的指针，即driver_object*
);

extern "C" NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

#endif


/*
功能介绍：
在函数前面加上宏 _IRQL_requires_max_(APC_LEVEL) 可以提高函数执行到APC级别，防止被打断。
*/


//nt!DbgkDebugObjectType：win7 nt模块+208F40，该地址记录了调试对象的_OBJECT_TYPE结构体的地址,_OBJECT_TYPE.TypeInfo.ValidAccessMask成员的值会被清0，正确的值应当是0x1f000f
//pdriver_object->DriverSection->InLoadOrderLink来遍历所有内核模块
//ZwQuerySystemInformation来遍历所有的模块信息
//nt!PsLoadedModuleList 是一个ldr的list_entry，这和driver_object.DriverSection->InLoadOrderLink含义一致。只不过这里用一个全局变量保存了双向链表的头
//所有的内核对象的数量和句柄数量的更新应当换成该结构体中的padding1个padding2
//所有的对内核对象ethread.debugobject的读取和写入的代码的偏移都应当进行移位，移动到eprocess不使用的内存区域_PADDING0_及其后面元素的地址一般不会使用
//如果搜索所有的对某结构体的某对象的使用：
		//1.获得pdb用SymbolTypeViewer工具解析的c语言头文件，在里面搜索所有的偏移为xxx的成员看看有多少
		//2.在IDA中同样进行搜索，进行小规模获得所有的代码。
		//3.使用硬件断点读取进行判断和确认
//保护目标调试器进程不被打开，验证被调试进程是否有进程保护
//替换所有的内核中断表
//SSDT hook和添加新的服务函数
//内核重载？
//去除object hook
//接管所有的回调表，如进程创建回调、模块加载回调
//对于进程内的内核回调应当进行修复
//检查目标进程的用户层的产生调试事件的代码是否篡改进行修复
//针对IDT hook想办法还原
//创建进程与驱动的通信方式



/*
1.获得所有的类型的内核对象的_OBJECT_TYPE：
nt!ObTypeIndexTable=nt+22A340 是一个8字节为单位的数组，从下标为2开始记录了每一种内核对象的_OBJECT_TYPE信息

*/