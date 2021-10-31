#pragma once
#ifndef SR_H
#define SR_H
//这个头文件里面包含了windows 系统下的一些未文档化的通用的结构体的定义（或是结构体的完整版本）和内核未导出的函数的导入，因此想要很好的实现功能不妨导入此文件试试。
#include "kernel_pch.h"


struct _SYSTEM_MODULE_INFORMATION_SR;
enum _SYSTEM_INFORMATION_CLASS_SR;
struct _SYSTEM_MODULE_INFO_LIST_SR;
struct _SYSTEM_SERVICE_DESCIPTOR_TABLE_SR;
enum _PROCESS_INFORMATION_CLASS_SR;
enum _OBJECT_INFORMATION_CLASS_SR;
enum _MEMORY_INFORMATION_CLASS_SR;
enum _THREAD_INFORMATION_CLASS_SR;
struct _FLOATING_SAVE_AREA32_SR;
struct _CONTEXT32_SR;
struct _DRIVER_OBJECT_SR;
struct _LDR_DATA_TABLE_ENTRY_SR;
struct _CURDIR_SR;
struct _RTL_DRIVE_LETTER_CURDIR_SR;
struct _RTL_USER_PROCESS_PARAMETERS_SR;
struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY_SR;
struct _NT_PROC_THREAD_ATTRIBUTE_LIST;

typedef struct _SYSTEM_MODULE_INFORMATION_SR								//调用NtQuerySystemInformation函数使用_SYSTEM_INFORMATION_CLASS.SystemModuleInformation=11功能号时使用的结构体
{
	ULONG		Reserved[4];
	PVOID		Base;														//模块的imagebase
	ULONG		Size;														//模块的imagesize
	ULONG		Flags;
	USHORT		Index;														//驱动模块的加载顺序，例如nt内核模块加载顺序是0
	USHORT		Unknown;
	USHORT		LoadCount;
	USHORT		ModuleNameOffset;											//放在ImageName中的是完整路径（内核路径格式），这个是模块的文件名的起始位置下标
	CHAR		ImageName[256];												//保存了模块的完整内核路径格式的路径
} SYSTEM_MODULE_INFORMATION_SR, *PSYSTEM_MODULE_INFORMATION_SR;

typedef enum _SYSTEM_INFORMATION_CLASS_SR									//调用NtQuerySystemInformation函数时使用的枚举，即功能号
{
	SystemBasicInformation_Sr,
	SystemProcessorInformation_Sr,											// obsolete...delete
	SystemPerformanceInformation_Sr,
	SystemTimeOfDayInformation_Sr,
	SystemPathInformation_Sr,
	SystemProcessInformation_Sr,
	SystemCallCountInformation_Sr,
	SystemDeviceInformation_Sr,
	SystemProcessorPerformanceInformation_Sr,
	SystemFlagsInformation_Sr,
	SystemCallTimeInformation_Sr,
	SystemModuleInformation_Sr,
	SystemLocksInformation_Sr,
	SystemStackTraceInformation_Sr,
	SystemPagedPoolInformation_Sr,
	SystemNonPagedPoolInformation_Sr,
	SystemHandleInformation_Sr,
	SystemObjectInformation_Sr,
	SystemPageFileInformation_Sr,
	SystemVdmInstemulInformation_Sr,
	SystemVdmBopInformation_Sr,
	SystemFileCacheInformation_Sr,
	SystemPoolTagInformation_Sr,
	SystemInterruptInformation_Sr,
	SystemDpcBehaviorInformation_Sr,
	SystemFullMemoryInformation_Sr,
	SystemLoadGdiDriverInformation_Sr,
	SystemUnloadGdiDriverInformation_Sr,
	SystemTimeAdjustmentInformation_Sr,
	SystemSummaryMemoryInformation_Sr,
	SystemMirrorMemoryInformation_Sr,
	SystemPerformanceTraceInformation_Sr,
	SystemObsolete0_Sr,
	SystemExceptionInformation_Sr,
	SystemCrashDumpStateInformation_Sr,
	SystemKernelDebuggerInformation_Sr,
	SystemContextSwitchInformation_Sr,
	SystemRegistryQuotaInformation_Sr,
	SystemExtendServiceTableInformation_Sr,
	SystemPrioritySeperation_Sr,
	SystemVerifierAddDriverInformation_Sr,
	SystemVerifierRemoveDriverInformation_Sr,
	SystemProcessorIdleInformation_Sr,
	SystemLegacyDriverInformation_Sr,
	SystemCurrentTimeZoneInformation_Sr,
	SystemLookasideInformation_Sr,
	SystemTimeSlipNotification_Sr,
	SystemSessionCreate_Sr,
	SystemSessionDetach_Sr,
	SystemSessionInformation_Sr,
	SystemRangeStartInformation_Sr,
	SystemVerifierInformation_Sr,
	SystemVerifierThunkExtend_Sr,
	SystemSessionProcessInformation_Sr,
	SystemLoadGdiDriverInSystemSpace_Sr,
	SystemNumaProcessorMap_Sr,
	SystemPrefetcherInformation_Sr,
	SystemExtendedProcessInformation_Sr,									//使用SYSTEM_PROCESS_INFORMATION_SR结构体
	SystemRecommendedSharedDataAlignment_Sr,
	SystemComPlusPackage_Sr,
	SystemNumaAvailableMemory_Sr,
	SystemProcessorPowerInformation_Sr,
	SystemEmulationBasicInformation_Sr,
	SystemEmulationProcessorInformation_Sr,
	SystemExtendedHandleInformation_Sr,
	SystemLostDelayedWriteInformation_Sr,
	SystemBigPoolInformation_Sr,
	SystemSessionPoolTagInformation_Sr,
	SystemSessionMappedViewInformation_Sr,
	SystemHotpatchInformation_Sr,
	SystemObjectSecurityMode_Sr,
	SystemWatchdogTimerHandler_Sr,
	SystemWatchdogTimerInformation_Sr,
	SystemLogicalProcessorInformation_Sr,
	SystemWow64SharedInformation_Sr,
	SystemRegisterFirmwareTableInformationHandler_Sr,
	SystemFirmwareTableInformation_Sr,
	SystemModuleInformationEx_Sr,
	SystemVerifierTriageInformation_Sr,
	SystemSuperfetchInformation_Sr,
	SystemMemoryListInformation_Sr,
	SystemFileCacheInformationEx_Sr,
	MaxSystemInfoClass_Sr													// MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS_SR;

typedef struct _SYSTEM_MODULE_INFO_LIST_SR									//调用ZwQuerySystemInformation函数时使用
{
	ULONG ulCount;															//这个list后面数组的长度
	SYSTEM_MODULE_INFORMATION_SR smi[1];									//一个数组
} SYSTEM_MODULE_INFO_LIST_SR, *PSYSTEM_MODULE_INFO_LIST_SR;

typedef struct _SYSTEM_SERVICE_DESCIPTOR_TABLE_SR							//系统描述符表（SSDT）占用32字节
{
	PULONG ServiceTableBase;												//SSDT数组的基址，8字节大小，数组中每个元素占4字节，保存的内容左移4位得到的是地址相对偏移量，是服务函数地址相对SSDT起始地址的偏移量
	PVOID ServiceCounterTableBase;											//SSDT中服务被调用次数计数器，8字节大小
	ULONGLONG NumberOfService;												//SSDT服务函数的个数，8字节大小
	PVOID ParamTableBase;													//系统服务参数表基址，8字节大小。实际指向的数组是以字节为单位的记录着对应服务函数的参数个数
}SYSTEM_SERVICE_DESCIPTOR_TABLE_SR, *PSYSTEM_SERVICE_DESCIPTOR_TABLE_SR;

//combase!_PROCESS_BASIC_INFORMATION
//+ 0x000 ExitStatus       : Int4B
//+ 0x004 PebBaseAddress : Ptr32 _PEB
//+ 0x008 AffinityMask : Uint4B
//+ 0x00c BasePriority : Int4B
//+ 0x010 UniqueProcessId : Uint4B
//+ 0x014 InheritedFromUniqueProcessId : Uint4B
typedef struct _PROCESS_BASIC_INFORMATION32_SR
{
	UINT32 ExitStatus;
	UINT32 PebBaseAddress;
	UINT32 AffinityMask;
	UINT32 BasePriority;
	UINT32 UniqueProcessId;
	UINT32 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32_SR, *PPROCESS_BASIC_INFORMATION32_SR;

//dt combase!_PROCESS_BASIC_INFORMATION
//+ 0x000 ExitStatus       : Int4B
//+ 0x008 PebBaseAddress : Ptr64 _PEB
//+ 0x010 AffinityMask : Uint8B
//+ 0x018 BasePriority : Int4B
//+ 0x020 UniqueProcessId : Uint8B
//+ 0x028 InheritedFromUniqueProcessId : Uint8B
typedef struct _PROCESS_BASIC_INFORMATION64_SR
{
	NTSTATUS	ExitStatus;
	ULONG32		Pad1;
	ULONG64		PebBaseAddress;
	ULONG64		AffinityMask;
	UINT32		BasePriority;
	ULONG32		Pad2;
	ULONG64		UniqueProcessId;
	ULONG64		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64_SR, *PPROCESS_BASIC_INFORMATION64_SR;


typedef enum _PROCESS_INFORMATION_CLASS_SR//用于NtQueryInformationProcess函数时参数使用的枚举
{
	ProcessBasicInformation_Sr,
	ProcessQuotaLimits_Sr,
	ProcessIoCounters_Sr,
	ProcessVmCounters_Sr,
	ProcessTimes_Sr,
	ProcessBasePriority_Sr,
	ProcessRaisePriority_Sr,
	ProcessDebugPort_Sr,
	ProcessExceptionPort_Sr,
	ProcessAccessToken_Sr,
	ProcessLdtInformation_Sr,
	ProcessLdtSize_Sr,
	ProcessDefaultHardErrorMode_Sr,
	ProcessIoPortHandlers_Sr,				// Note: this is kernel mode only
	ProcessPooledUsageAndLimits_Sr,
	ProcessWorkingSetWatch_Sr,
	ProcessUserModeIOPL_Sr,
	ProcessEnableAlignmentFaultFixup_Sr,
	ProcessPriorityClass_Sr,
	ProcessWx86Information_Sr,
	ProcessHandleCount_Sr,
	ProcessAffinityMask_Sr,
	ProcessPriorityBoost_Sr,
	ProcessDeviceMap_Sr,
	ProcessSessionInformation_Sr,
	ProcessForegroundInformation_Sr,
	ProcessWow64Information_Sr,
	ProcessImageFileName_Sr,
	ProcessLUIDDeviceMapsEnabled_Sr,
	ProcessBreakOnTermination_Sr,
	ProcessDebugObjectHandle_Sr,
	ProcessDebugFlags_Sr,
	ProcessHandleTracing_Sr,
	ProcessIoPriority_Sr,
	ProcessExecuteFlags_Sr,
	ProcessTlsInformation_Sr,
	ProcessCookie_Sr,
	ProcessImageInformation_Sr,
	ProcessCycleTime_Sr,
	ProcessPagePriority_Sr,
	ProcessInstrumentationCallback_Sr,
	ProcessThreadStackAllocation_Sr,
	ProcessWorkingSetWatchEx_Sr,
	ProcessImageFileNameWin32_Sr,
	ProcessImageFileMapping_Sr,
	ProcessAffinityUpdateMode_Sr,
	ProcessMemoryAllocationMode_Sr,
	ProcessGroupInformation_Sr,
	ProcessTokenVirtualizationEnabled_Sr,
	ProcessConsoleHostProcess_Sr,
	ProcessWindowInformation_Sr,
	MaxProcessInfoClass_Sr					// MaxProcessInfoClass should always be the last enum
} PROCESS_INFORMATION_CLASS_SR;

typedef enum _OBJECT_INFORMATION_CLASS_SR//调用NtQueryObject函数时使用的枚举
{
	ObjectBasicInformation_Sr,
	ObjectNameInformation_Sr,
	ObjectTypeInformation_Sr,
	ObjectTypesInformation_Sr,
	ObjectHandleFlagInformation_Sr,
	ObjectSessionInformation_Sr,
	MaxObjectInfoClass_Sr  // MaxObjectInfoClass should always be the last enum
} OBJECT_INFORMATION_CLASS_SR;

typedef enum _MEMORY_INFORMATION_CLASS_SR
{
	MemoryBasicInformation_Sr,
	MemoryWorkingSetInformation_Sr,
	MemoryMappedFilenameInformation_Sr,
	MemoryRegionInformation_Sr,
	MemoryWorkingSetExInformation_Sr
} MEMORY_INFORMATION_CLASS_SR;

typedef enum _THREAD_INFORMATION_CLASS_SR //调用NtQueryInformationThread函数时参数使用的枚举
{
	ThreadBasicInformation_Sr,
	ThreadTimes_Sr,
	ThreadPriority_Sr,
	ThreadBasePriority_Sr,
	ThreadAffinityMask_Sr,
	ThreadImpersonationToken_Sr,
	ThreadDescriptorTableEntry_Sr,
	ThreadEnableAlignmentFaultFixup_Sr,
	ThreadEventPair_Sr,
	ThreadQuerySetWin32StartAddress_Sr,
	ThreadZeroTlsCell_Sr,
	ThreadPerformanceCount_Sr,
	ThreadAmILastThread_Sr,
	ThreadIdealProcessor_Sr,
	ThreadPriorityBoost_Sr,
	ThreadSetTlsArrayAddress_Sr,
	ThreadIsIoPending_Sr,
	ThreadHideFromDebugger_Sr
} THREAD_INFORMATION_CLASS_SR, *PTHREAD_INFORMATION_CLASS_SR;

typedef struct _OBJECT_TYPE_INFORMATION_SR //ObjectTypeInformation_Sr
{
	UNICODE_STRING	        TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION_SR, *POBJECT_TYPE_INFORMATION_SR;

typedef struct _OBJECT_ALL_INFORMATION_SR {
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION_SR ObjectTypeInformation[1];
}OBJECT_ALL_INFORMATION_SR, *POBJECT_ALL_INFORMATION_SR;

typedef struct _FLOATING_SAVE_AREA32_SR
{
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[80];
	DWORD   Spare0;
} FLOATING_SAVE_AREA32_SR, *PFLOATING_SAVE_AREA32_SR;

typedef struct _CONTEXT32_SR
{

	//
	// The flags values within this flag control the contents of
	// a CONTEXT record.
	//
	// If the context record is used as an input parameter, then
	// for each portion of the context record controlled by a flag
	// whose value is set, it is assumed that that portion of the
	// context record contains valid context. If the context record
	// is being used to modify a threads context, then only that
	// portion of the threads context will be modified.
	//
	// If the context record is used as an IN OUT parameter to capture
	// the context of a thread, then only those portions of the thread's
	// context corresponding to set flags will be returned.
	//
	// The context record is never used as an OUT only parameter.
	//

	DWORD ContextFlags;

	//
	// This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
	// set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
	// included in CONTEXT_FULL.
	//

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
	//

	FLOATING_SAVE_AREA32_SR FloatSave;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_SEGMENTS.
	//

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_INTEGER.
	//

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_CONTROL.
	//

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;

	//
	// This section is specified/returned if the ContextFlags word
	// contains the flag CONTEXT_EXTENDED_REGISTERS.
	// The format and contexts are processor specific
	//

	BYTE    ExtendedRegisters[512];

} CONTEXT32_SR, *PCONTEXT32_SR;


typedef NTSTATUS(*PFNtCreateFile)(
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
	);

typedef NTSTATUS(NTAPI *PFNtMapViewOfSection)(//注意：64位环境下参数的长度应当发生变化
	IN HANDLE               SectionHandle,
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress OPTIONAL,
	IN UINT64               ZeroBits OPTIONAL,
	IN UINT64               CommitSize,
	IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
	IN OUT PUINT64          ViewSize,
	IN SECTION_INHERIT		InheritDisposition,
	IN UINT64               AllocationType OPTIONAL,
	IN ULONG                Protect
	);


typedef NTSTATUS(*PFNtReadFile)(
	_In_     HANDLE				FileHandle,
	_In_opt_ HANDLE				Event,
	_In_opt_ PIO_APC_ROUTINE	ApcRoutine,
	_In_opt_ PVOID				ApcContext,
	_Out_    PIO_STATUS_BLOCK	IoStatusBlock,
	_Out_    PVOID				Buffer,
	_In_     ULONG				Length,
	_In_opt_ PLARGE_INTEGER		ByteOffset,
	_In_opt_ PULONG				Key
	);

typedef NTSTATUS(*PFNtUnmapViewOfSection)(
	HANDLE				ProcessHandle,
	PVOID				BaseAddress
	);

typedef NTSTATUS(*PFNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(*PFNtFreeVirtualMemory)(
	_In_    HANDLE  ProcessHandle,
	_Inout_ PVOID   *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_    ULONG   FreeType
	);

typedef NTSTATUS(*PFNtProtectVirtualMemory)(
	IN HANDLE		ProcessHandle,
	IN OUT PVOID	*UnsafeBaseAddress,
	IN OUT SIZE_T	*UnsafeNumberOfBytesToProtect,
	IN ULONG		NewAccessProtection,
	OUT PULONG		UnsafeOldAccessProtection
	);

typedef NTSTATUS(*PFNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS_SR SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(*PFNtQueryInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESS_INFORMATION_CLASS_SR ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(*PFNtQueryInformationThread)(
	__in HANDLE ThreadHandle,
	__in THREAD_INFORMATION_CLASS_SR ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength,
	__out_opt PULONG ReturnLength
	);


typedef NTSTATUS(*PFNtQueryVirtualMemory)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_SR MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
	);

typedef NTSTATUS(*PFNtQueryObject)(
	__in HANDLE Handle,
	__in OBJECT_INFORMATION_CLASS_SR ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
	__in ULONG ObjectInformationLength,
	__out_opt PULONG ReturnLength
	);


typedef NTSTATUS(*PFNtSetInformationThread)(
	IN HANDLE               ThreadHandle,
	IN THREAD_INFORMATION_CLASS_SR ThreadInformationClass,
	IN PVOID                ThreadInformation,
	IN ULONG                ThreadInformationLength
	);

typedef NTSTATUS(WINAPI* PFNtClose)(HANDLE Handle);

typedef NTSTATUS(WINAPI * PFNtGetContextThread)(HANDLE hThread, PCONTEXT pContext);
typedef NTSTATUS(WINAPI * PFNtSetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
typedef NTSTATUS(*PFNtCreateProcess)(//win7 开始所有的createprocess函数不再调用此函数，而是调用NtCreateUserProcess
	OUT PHANDLE           ProcessHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE             ParentProcess,
	IN BOOLEAN            InheritObjectTable,
	IN HANDLE             SectionHandle OPTIONAL,
	IN HANDLE             DebugPort OPTIONAL,
	IN HANDLE             ExceptionPort OPTIONAL
	);

typedef struct _LDR_DATA_TABLE_ENTRY_SR															// 24 elements, 0xE0 bytes (sizeof) 
{
	/*0x000*/     LIST_ENTRY InLoadOrderLinks;													// 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     LIST_ENTRY InMemoryOrderLinks;												// 2 elements, 0x10 bytes (sizeof)  
	/*0x020*/     LIST_ENTRY InInitializationOrderLinks;										// 2 elements, 0x10 bytes (sizeof)  
	/*0x030*/     VOID*        DllBase;
	/*0x038*/     VOID*        EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     UNICODE_STRING FullDllName;													// 3 elements, 0x10 bytes (sizeof)  
	/*0x058*/     UNICODE_STRING BaseDllName;													// 3 elements, 0x10 bytes (sizeof)  
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;														//
	/*0x06E*/     UINT16       TlsIndex;
	union																						// 2 elements, 0x10 bytes (sizeof)  
	{
		/*0x070*/         LIST_ENTRY HashLinks;													// 2 elements, 0x10 bytes (sizeof)  
		struct																					// 2 elements, 0x10 bytes (sizeof)  
		{
			/*0x070*/             VOID*        SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union																						// 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID*        LoadedImports;
	};
	/*0x088*/     VOID* EntryPointActivationContext;											//struct ACTIVATION_CONTEXT has no element
	/*0x090*/     VOID*        PatchInformation;
	/*0x098*/     LIST_ENTRY ForwarderLinks;													// 2 elements, 0x10 bytes (sizeof)  
	/*0x0A8*/     LIST_ENTRY ServiceTagLinks;													// 2 elements, 0x10 bytes (sizeof)  
	/*0x0B8*/     LIST_ENTRY StaticLinks;														// 2 elements, 0x10 bytes (sizeof)  
	/*0x0C8*/     VOID*        ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     LARGE_INTEGER LoadTime;														// 4 elements, 0x8 bytes (sizeof)   
}LDR_DATA_TABLE_ENTRY_SR, *PLDR_DATA_TABLE_ENTRY_SR;

typedef struct _DRIVER_OBJECT_SR																// 15 elements, 0x150 bytes (sizeof) 
{
	/*0x000*/     INT16			Type;
	/*0x002*/     INT16			Size;
	/*0x004*/     UINT8			_PADDING0_[0x4];
	/*0x008*/     DEVICE_OBJECT* DeviceObject;
	/*0x010*/     ULONG32		Flags;
	/*0x014*/     UINT8			_PADDING1_[0x4];
	/*0x018*/     VOID*			DriverStart;
	/*0x020*/     ULONG32		DriverSize;
	/*0x024*/     UINT8			_PADDING2_[0x4];
	/*0x028*/     PLDR_DATA_TABLE_ENTRY_SR  DriverSection;
	/*0x030*/     DRIVER_EXTENSION* DriverExtension;
	/*0x038*/     UNICODE_STRING DriverName;													// 3 elements, 0x10 bytes (sizeof)   
	/*0x048*/     UNICODE_STRING* HardwareDatabase;
	/*0x050*/     FAST_IO_DISPATCH* FastIoDispatch;
	/*0x058*/     PDRIVER_INITIALIZE DriverInit;
	/*0x060*/     PDRIVER_STARTIO DriverStartIo;
	/*0x068*/     PDRIVER_UNLOAD DriverUnload;
	/*0x070*/     PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];					//arrary length=28
}DRIVER_OBJECT_SR, *PDRIVER_OBJECT_SR;


typedef struct _CURDIR_SR              // 2 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     struct _UNICODE_STRING DosPath; // 3 elements, 0x10 bytes (sizeof) 
	/*0x010*/     VOID*        Handle;
}CURDIR_SR, *PCURDIR_SR;

typedef struct _RTL_DRIVE_LETTER_CURDIR_SR // 4 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     UINT16       Flags;
	/*0x002*/     UINT16       Length;
	/*0x004*/     ULONG32      TimeStamp;
	/*0x008*/     struct _STRING DosPath;             // 3 elements, 0x10 bytes (sizeof) 
}RTL_DRIVE_LETTER_CURDIR_SR, *PRTL_DRIVE_LETTER_CURDIR_SR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_SR                // 34 elements, 0x420 bytes (sizeof) 
{
	/*0x000*/     ULONG32      MaximumLength;
	/*0x004*/     ULONG32      Length;
	/*0x008*/     ULONG32      Flags;
	/*0x00C*/     ULONG32      DebugFlags;
	/*0x010*/     VOID*        ConsoleHandle;
	/*0x018*/     ULONG32      ConsoleFlags;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	/*0x020*/     VOID*        StandardInput;
	/*0x028*/     VOID*        StandardOutput;
	/*0x030*/     VOID*        StandardError;
	/*0x038*/     struct _CURDIR_SR CurrentDirectory;                    // 2 elements, 0x18 bytes (sizeof)   
	/*0x050*/     struct _UNICODE_STRING DllPath;                        // 3 elements, 0x10 bytes (sizeof)   
	/*0x060*/     struct _UNICODE_STRING ImagePathName;                  // 3 elements, 0x10 bytes (sizeof)   
	/*0x070*/     struct _UNICODE_STRING CommandLine;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x080*/     VOID*        Environment;
	/*0x088*/     ULONG32      StartingX;
	/*0x08C*/     ULONG32      StartingY;
	/*0x090*/     ULONG32      CountX;
	/*0x094*/     ULONG32      CountY;
	/*0x098*/     ULONG32      CountCharsX;
	/*0x09C*/     ULONG32      CountCharsY;
	/*0x0A0*/     ULONG32      FillAttribute;
	/*0x0A4*/     ULONG32      WindowFlags;
	/*0x0A8*/     ULONG32      ShowWindowFlags;
	/*0x0AC*/     UINT8        _PADDING1_[0x4];
	/*0x0B0*/     struct _UNICODE_STRING WindowTitle;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0C0*/     struct _UNICODE_STRING DesktopInfo;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0D0*/     struct _UNICODE_STRING ShellInfo;                      // 3 elements, 0x10 bytes (sizeof)   
	/*0x0E0*/     struct _UNICODE_STRING RuntimeData;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0F0*/     struct _RTL_DRIVE_LETTER_CURDIR_SR CurrentDirectores[32];
	/*0x3F0*/     UINT64       EnvironmentSize;
	/*0x3F8*/     UINT64       EnvironmentVersion;
	/*0x400*/     VOID*        PackageDependencyData;
	/*0x408*/     ULONG32      ProcessGroupId;
	/*0x40C*/     ULONG32      LoaderThreads;
	/*0x410*/     struct _UNICODE_STRING RedirectionDllName;             // 3 elements, 0x10 bytes (sizeof)   
}RTL_USER_PROCESS_PARAMETERS_SR, *PRTL_USER_PROCESS_PARAMETERS_SR;


typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY_SR
{
	ULONG Attribute;											// PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明
	SIZE_T Size;												// Value的大小
	ULONG_PTR Value;											// 保存4字节数据（比如一个Handle）或数据指针
	ULONG Unknown;												// 总是0，可能是用来返回数据给调用者
} PROC_THREAD_ATTRIBUTE_ENTRY_SR, *PPROC_THREAD_ATTRIBUTE_ENTRY_SR;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
	ULONG Length;												// 结构总大小
	PROC_THREAD_ATTRIBUTE_ENTRY_SR Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST_SR, *PNT_PROC_THREAD_ATTRIBUTE_LIST_SR;

typedef NTSTATUS(*PFNtCreateUserProcess)(
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
	);

typedef NTSTATUS(*PFNtYieldExecution)();

typedef NTSTATUS(*PFNtOpenProcess)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
	);

typedef NTSTATUS(*PFNtOpenThread)(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PCLIENT_ID           ClientId
	);

typedef NTSTATUS(*PFNtCreateTimer)(
	OUT PHANDLE             TimerHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN TIMER_TYPE           TimerType
	);

typedef VOID(*PFTimerProc)(
	IN HWND hwnd,
	IN UINT uMsg,
	IN UINT_PTR idEvent,
	IN DWORD dwTime
	);

typedef UINT_PTR (*PFNtUserSetTimer)(//user32.dll!SetTimer
	HWND hWnd,
	UINT_PTR nIDEvent,
	UINT uElapse,
	PFTimerProc lpTimerFunc
	);

typedef NTSTATUS (*PFNtDeviceIoControlFile)(
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
);

#endif