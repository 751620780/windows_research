#pragma once
//这个头文件定义了一些数据结构用于ntdll中使用。为了防止数据类型的名字和引入的其他头文件重复，这里统一在末尾加上Sr/SR
//Sr的意思是Self-realization，自实现
//如果一个结构体定义包含3种情况：
//	A：仅适用于自身进程,如果当前程序是32位的那么其等同于A32，如果当前程序是64位的那么其等同于A64
//	A32：强制认为使用者认为目标操作是针对32位，可以访问32位的目标进程
//	A64：强制认为使用者认为目标操作时针对64位，可以访问64位的目标进程
//	todo:根据http://undocumented.ntinternals.net/index.html网站提供的信息进行完善
#ifndef SR_H
#define SR_H

typedef LONG NTSTATUS;
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) 

typedef LONG KPRIORITY_SR;


typedef enum _SYSTEM_INFORMATION_CLASS_SR//调用NtQuerySystemInformation函数时使用的枚举
{
	SystemBasicInformation_Sr,
	SystemProcessorInformation_Sr,             // obsolete...delete
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
	SystemExtendedProcessInformation_Sr,//使用SYSTEM_PROCESS_INFORMATION_SR结构体
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
	MaxSystemInfoClass_Sr  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS_SR;

typedef enum _PROCESSINFOCLASS_SR//用于NtQueryInformationProcess函数时参数使用的枚举
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
} PROCESSINFOCLASS_SR;



typedef enum _THREADINFOCLASS_SR//调用NtQueryInformationThread函数时参数使用的枚举
{
	ThreadBasicInformation_Sr,
	ThreadTimes_Sr,
	ThreadPriority_Sr,
	ThreadBasePriority_Sr,
	ThreadAffinityMask_Sr,
	ThreadImpersonationToken_Sr,
	ThreadDescriptorTableEntry_Sr,
	ThreadEnableAlignmentFaultFixup_Sr,
	ThreadEventPair_Reusable_Sr,
	ThreadQuerySetWin32StartAddress_Sr,
	ThreadZeroTlsCell_Sr,
	ThreadPerformanceCount_Sr,
	ThreadAmILastThread_Sr,
	ThreadIdealProcessor_Sr,
	ThreadPriorityBoost_Sr,
	ThreadSetTlsArrayAddress_Sr,
	ThreadIsIoPending_Sr,
	ThreadHideFromDebugger_Sr,
	ThreadBreakOnTermination_Sr,
	ThreadSwitchLegacyState_Sr,
	ThreadIsTerminated_Sr,
	MaxThreadInfoClass_Sr
} THREADINFOCLASS_SR;

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

typedef struct _MEMORY_BASIC_INFORMATION_SR //调用ntdll!NtQueryVirtualMemory函数并传递MemoryBasicInformation_Sr查询内容时使用
{
	PVOID BaseAddress;			//内存块的基址,调用ntdll!NtQueryVirtualMemory函数时,提供的查询地址即使不是基址查询后也会自动对齐到基址
	PVOID AllocationBase;		//区域的基址，当初分配内存块时所属的区域内存的基址
	DWORD AllocationProtect;	//初始分配的这个区域内存时的初始保护属性
	SIZE_T RegionSize;			//以BaseAddress开始的属性一致的虚拟内存的大小（字节），即这个内存块的大小
	DWORD State;				//当前这个RegionSize的状态MEM_COMMIT、MEM_FREE、MEM_RESERVE
	DWORD Protect;				//保护属性，读写执行权限，有PAGE_NOACCESS、PAGE_READONLY、PAGE_READWRITE、PAGE_WRITECOPY、PAGE_EXECUTE、PAGE_EXECUTE_READ、PAGE_EXECUTE_READWRITE、PAGE_EXECUTE_WRITECOPY、PAGE_GUARD、PAGE_NOCACHE、PAGE_WRITECOMBINE
	DWORD Type;					//内存用途：MEM_IMAGE（文件映射，包括普通文件、pe文件，可共享）、MEM_MAPPED（内存映射，可共享）、MEM_PRIVATE（私有）
} MEMORY_BASIC_INFORMATION_SR, *PMEMORY_BASIC_INFORMATION_SR;

typedef NTSTATUS(__stdcall *PFNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS_SR SystemInformationClass,
	__out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(__stdcall *PFNtQueryInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS_SR ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);

typedef NTSTATUS(__stdcall *PFNtQueryInformationThread)(
	__in HANDLE ThreadHandle,
	__in THREADINFOCLASS_SR ThreadInformationClass,
	__out_bcount(ThreadInformationLength) PVOID ThreadInformation,
	__in ULONG ThreadInformationLength,
	__out_opt PULONG ReturnLength
	);

//注意VirtualQuery函数实际调用的是这个函数
typedef NTSTATUS(__stdcall *PFNtQueryVirtualMemory)(
	__in HANDLE ProcessHandle,
	__in PVOID BaseAddress,
	__in MEMORY_INFORMATION_CLASS_SR MemoryInformationClass,
	__out_bcount(MemoryInformationLength) PVOID MemoryInformation,
	__in SIZE_T MemoryInformationLength,
	__out_opt PSIZE_T ReturnLength
);

typedef NTSTATUS(__stdcall *PFNtQueryObject)(
	__in HANDLE Handle,
	__in OBJECT_INFORMATION_CLASS_SR ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID ObjectInformation,
	__in ULONG ObjectInformationLength,
	__out_opt PULONG ReturnLength
	);


typedef struct _STRING_SR
{
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength), length_is(Length)]
#endif // MIDL_PASS
	PCHAR Buffer;
} STRING_SR;

typedef struct _STRING32_SR
{
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32_SR, *PSTRING32_SR;

typedef struct _STRING64_SR
{
	USHORT   Length;
	USHORT   MaximumLength;
	ULONGLONG  Buffer;
} STRING64_SR,*PSTRING64_SR;

typedef struct _UNICODE_STRING_SR
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING_SR, *PUNICODE_STRING_SR;
typedef const _UNICODE_STRING_SR *PCUNICODE_STRING_SR;

typedef struct _UNICODE_STRING32_SR
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG  Buffer;
} UNICODE_STRING32_SR, *PUNICODE_STRING32_SR;

typedef STRING64_SR UNICODE_STRING64_SR;

typedef UNICODE_STRING64_SR *PUNICODE_STRING64_SR;

typedef STRING_SR *PSTRING_SR;

typedef STRING_SR ANSI_STRING_SR;

typedef PSTRING_SR PANSI_STRING_SR;

typedef struct _LIST_ENTRY_SR//LSIT_ENTRY
{
   struct _LIST_ENTRY_SR *Flink;
   struct _LIST_ENTRY_SR *Blink;
} LIST_ENTRY_SR, *PLIST_ENTRY_SR;

typedef struct LIST_ENTRY32_SR//LIST_ENTRY32
{
	DWORD Flink;
	DWORD Blink;
} LIST_ENTRY32_SR, *PLIST_ENTRY32_SR;

typedef struct LIST_ENTRY64_SR//LSIT_ENTRY64
{
	ULONGLONG Flink;
	ULONGLONG Blink;
} LIST_ENTRY64_SR, *PLIST_ENTRY64_SR;

typedef struct _CURDIR_SR
{
	UNICODE_STRING_SR DosPath;
	HANDLE Handle;
} CURDIR_SR, *PCURDIR_SR;

typedef struct _CURDIR64_SR
{
	UNICODE_STRING64_SR DosPath;
	LONGLONG Handle;
} CURDIR64_SR, *PCURDIR64_SR;

typedef struct _RTL_DRIVE_LETTER_CURDIR_SR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING_SR DosPath;
} RTL_DRIVE_LETTER_CURDIR_SR, *PRTL_DRIVE_LETTER_CURDIR_SR;

typedef struct _RTL_DRIVE_LETTER_CURDIR64_SR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING64_SR DosPath;
} RTL_DRIVE_LETTER_CURDIR64_SR, *PRTL_DRIVE_LETTER_CURDIR64_SR;

#define RTL_MAX_DRIVE_LETTERS_SR 32

typedef struct _RTL_USER_PROCESS_PARAMETERS_SR
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR_SR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING_SR DllPath;         // ProcessParameters
	UNICODE_STRING_SR ImagePathName;   // ProcessParameters
	UNICODE_STRING_SR CommandLine;     // ProcessParameters
	PVOID Environment;				   // NtAllocateVirtualMemory

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING_SR WindowTitle;     // ProcessParameters
	UNICODE_STRING_SR DesktopInfo;     // ProcessParameters
	UNICODE_STRING_SR ShellInfo;       // ProcessParameters
	UNICODE_STRING_SR RuntimeData;     // ProcessParameters
	RTL_DRIVE_LETTER_CURDIR_SR CurrentDirectores[RTL_MAX_DRIVE_LETTERS_SR];
} RTL_USER_PROCESS_PARAMETERS_SR, *PRTL_USER_PROCESS_PARAMETERS_SR;

typedef struct _RTL_USER_PROCESS_PARAMETERS64_SR
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	LONGLONG ConsoleHandle;
	ULONG  ConsoleFlags;
	LONGLONG StandardInput;
	LONGLONG StandardOutput;
	LONGLONG StandardError;

	CURDIR64_SR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING64_SR DllPath;         // ProcessParameters
	UNICODE_STRING64_SR ImagePathName;   // ProcessParameters
	UNICODE_STRING64_SR CommandLine;     // ProcessParameters
	ULONGLONG Environment;              // NtAllocateVirtualMemory

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING64_SR WindowTitle;     // ProcessParameters
	UNICODE_STRING64_SR DesktopInfo;     // ProcessParameters
	UNICODE_STRING64_SR ShellInfo;       // ProcessParameters
	UNICODE_STRING64_SR RuntimeData;     // ProcessParameters
	RTL_DRIVE_LETTER_CURDIR64_SR CurrentDirectores[RTL_MAX_DRIVE_LETTERS_SR];

} RTL_USER_PROCESS_PARAMETERS64_SR, *PRTL_USER_PROCESS_PARAMETERS64_SR;

typedef struct _PEB_LDR_DATA_SR
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY_SR InLoadOrderModuleList;
	LIST_ENTRY_SR InMemoryOrderModuleList;
	LIST_ENTRY_SR InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA_SR, *PPEB_LDR_DATA_SR;

typedef struct _PEB_LDR_DATA32_SR
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32_SR InLoadOrderModuleList;
	LIST_ENTRY32_SR InMemoryOrderModuleList;
	LIST_ENTRY32_SR InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32_SR, *PPEB_LDR_DATA32_SR;

typedef struct _PEB_LDR_DATA64_SR
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONGLONG SsHandle;
	LIST_ENTRY64_SR InLoadOrderModuleList;
	LIST_ENTRY64_SR InMemoryOrderModuleList;
	LIST_ENTRY64_SR InInitializationOrderModuleList;
	ULONGLONG EntryInProgress;
} PEB_LDR_DATA64_SR, *PPEB_LDR_DATA64_SR;

typedef struct _PEB_SR
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA_SR Ldr;
	PRTL_USER_PROCESS_PARAMETERS_SR ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	PVOID ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID ProcessHeaps;

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PVOID LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	ULONG GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;

	UNICODE_STRING_SR CSDVersion;

	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;

	SIZE_T MinimumStackCommit;

	PVOID* FlsCallback;
	LIST_ENTRY_SR FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pContextData;
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
} PEB_SR, *PPEB_SR;

typedef struct _PEB32_SR
{
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	union
	{
		BOOLEAN BitField;               //
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess	: 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	ULONG Mutant;      // INITIAL_PEB structure is also updated.

	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	//其它成员请使用dt -a _peb32命令在windbg中查询
} PEB32_SR, *PPEB32_SR;

typedef struct _PEB64_SR
{
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	union
	{
		BOOLEAN BitField;               //
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	ULONGLONG Mutant;      // INITIAL_PEB structure is also updated.

	ULONGLONG ImageBaseAddress;
	ULONGLONG Ldr;
	ULONGLONG ProcessParameters;
	ULONGLONG SubSystemData;
	ULONGLONG ProcessHeap;
} PEB64_SR, *PPEB64_SR;

typedef struct _PROCESS_BASIC_INFORMATION_SR
{
	NTSTATUS ExitStatus;
	PPEB_SR PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY_SR BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_SR, *PPROCESS_BASIC_INFORMATION_SR;

typedef struct _PROCESS_BASIC_INFORMATION64_SR
{
	NTSTATUS ExitStatus;
	ULONG32 Pad1;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	KPRIORITY_SR BasePriority;
	ULONG32 Pad2;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64_SR;

typedef struct _LDR_DATA_TABLE_ENTRY_SR//PEB_SR.Ldr成员指向的3个链表中的每一个表项的数据结构
{
	LIST_ENTRY_SR InLoadOrderLinks;
	LIST_ENTRY_SR InMemoryOrderLinks;
	LIST_ENTRY_SR InInitializationOrderLinks;
	PVOID DllBase;								//模块的基址
	PVOID EntryPoint;							//EP的RVA
	ULONG SizeOfImage;							//镜像的大小
	UNICODE_STRING_SR FullDllName;				//模块的完整路径（绝对路径)
	UNICODE_STRING_SR BaseDllName;				//模块的名字（xxx.dll）
	ULONG Flags;
	USHORT LoadCount;							//加载次序，一般不正确
	USHORT TlsIndex;
	union {
		LIST_ENTRY_SR HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;

	PVOID PatchInformation;
	//以下成员在VISTA及以后有效
	LIST_ENTRY_SR ForwarderLinks;
	LIST_ENTRY_SR ServiceTagLinks;
	LIST_ENTRY_SR StaticLinks;
	PVOID ContextInformation;
	PVOID OriginalBase;
	LARGE_INTEGER LoadTime;

} LDR_DATA_TABLE_ENTRY_SR, *PLDR_DATA_TABLE_ENTRY_SR;

typedef struct _LDR_DATA_TABLE_ENTRY32_SR
{
	LIST_ENTRY32_SR InLoadOrderLinks;
	LIST_ENTRY32_SR InMemoryOrderLinks;
	LIST_ENTRY32_SR InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32_SR FullDllName;
	UNICODE_STRING32_SR BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY32_SR HashLinks;
		struct {
			ULONG SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			ULONG LoadedImports;
		};
	};
	ULONG EntryPointActivationContext;

	ULONG PatchInformation;

} LDR_DATA_TABLE_ENTRY32_SR, *PLDR_DATA_TABLE_ENTRY32_SR;

typedef struct _LDR_DATA_TABLE_ENTRY64_SR
{
	LIST_ENTRY64_SR InLoadOrderLinks;
	LIST_ENTRY64_SR InMemoryOrderLinks;
	LIST_ENTRY64_SR InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64_SR FullDllName;
	UNICODE_STRING64_SR BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY64_SR HashLinks;
		struct {
			ULONG64 SectionPointer;
			ULONG   CheckSum;
		};
	};
	union {
		struct {
			ULONG   TimeDateStamp;
		};
		struct {
			ULONG64 LoadedImports;
		};
	};

	//
	// NOTE : Do not grow this structure at the dump files used a packed
	// array of these structures.
	//

} LDR_DATA_TABLE_ENTRY64_SR, *PLDR_DATA_TABLE_ENTRY64_SR;

typedef struct _KERNEL_USER_TIMES_SR//在调用NtQueryInformationThread函数时使用THREADINFOCLASS_SR.ThreadTimes_Sr时返回值的数据结构
{
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES_SR,*PKERNEL_USER_TIMES_SR;

typedef struct _CLIENT_ID_SR
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID_SR,*PCLIENT_ID_SR;

typedef struct _CLIENT_ID32_SR
{
	DWORD UniqueProcess;
	DWORD UniqueThread;
} CLIENT_ID32_SR, *PCLIENT_ID32_SR;

typedef struct _CLIENT_ID64_SR
{
	ULONGLONG UniqueProcess;
	ULONGLONG UniqueThread;
} CLIENT_ID64_SR,*PCLIENT_ID64_SR;

typedef struct _NT_TIB_SR {
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
	union {
		PVOID FiberData;
		DWORD Version;
	};
#else
	PVOID FiberData;
#endif
	PVOID ArbitraryUserPointer;
	struct _NT_TIB_SR *Self;
} NT_TIB_SR;
typedef NT_TIB_SR *PNT_TIB_SR;

typedef struct _TEB_SR
{
	NT_TIB_SR NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID_SR ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB_SR ProcessEnvironmentBlock;		//Peb指针
	ULONG LastErrorValue;					//GetLastError or SetLastError
} TEB_SR, *PTEB_SR;

typedef struct _TEB32_SR
{
	NT_TIB32 NtTib;
	ULONG EnvironmentPointer;
	CLIENT_ID32_SR ClientId;
	ULONG ActiveRpcHandle;
	ULONG ThreadLocalStoragePointer;
	ULONG ProcessEnvironmentBlock;			//PPeb
	ULONG LastErrorValue;					//GetLastError or SetLastError
} TEB32_SR, *PTEB32_SR;

#define LDR_DLL_NOTIFICATION_REASON_LOADED_SR		1   
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED_SR		2  

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA_SR {
	ULONG Flags;						//Reserved.
	PCUNICODE_STRING_SR FullDllName;	//The full path name of the DLL module.
	PCUNICODE_STRING_SR BaseDllName;	//The base file name of the DLL module.
	PVOID DllBase;						//A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;					//The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA_SR, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA_SR;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA_SR {
	ULONG Flags;						//Reserved.
	PCUNICODE_STRING_SR FullDllName;	//The full path name of the DLL module.
	PCUNICODE_STRING_SR BaseDllName;	//The base file name of the DLL module.
	PVOID DllBase;						//A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;					//The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA_SR, *PLDR_DLL_LOADED_NOTIFICATION_DATA_SR;

typedef union _LDR_DLL_NOTIFICATION_DATA_SR {
	LDR_DLL_LOADED_NOTIFICATION_DATA_SR Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA_SR Unloaded;
} LDR_DLL_NOTIFICATION_DATA_SR, *PLDR_DLL_NOTIFICATION_DATA_SR;
typedef const _LDR_DLL_NOTIFICATION_DATA_SR *PCLDR_DLL_NOTIFICATION_DATA_SR;

typedef struct _THREAD_BASIC_INFORMATION_SR {//used for THREADINFOCLASS_SR::ThreadBasicInformation_Sr,referenced from http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTHREAD_INFORMATION_CLASS.html
	NTSTATUS		ExitStatus;
	PVOID			TebBaseAddress;
	CLIENT_ID_SR	ClientId;
	KAFFINITY		AffinityMask;
	KPRIORITY_SR	Priority;
	KPRIORITY_SR	BasePriority;
} THREAD_BASIC_INFORMATION_SR, *PTHREAD_BASIC_INFORMATION_SR;

typedef struct _SYSTEM_THREAD_INFORMATION_SR
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID_SR ClientId;
	KPRIORITY_SR Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_SR, *PSYSTEM_THREAD_INFORMATION_SR;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION_SR
{
	SYSTEM_THREAD_INFORMATION_SR ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	ULONG_PTR Reserved1;
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION_SR, *PSYSTEM_EXTENDED_THREAD_INFORMATION_SR;


typedef struct _SYSTEM_PROCESS_INFORMATION_SR
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING_SR ImageName;
	KPRIORITY_SR BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

	union
	{
		SYSTEM_THREAD_INFORMATION_SR Thread[1];
		SYSTEM_EXTENDED_THREAD_INFORMATION_SR ThreadEx[1];
	};

} SYSTEM_PROCESS_INFORMATION_SR, *PSYSTEM_PROCESS_INFORMATION_SR;

//定义在ntdlldll中常用的函数的函数指针

typedef NTSTATUS(__stdcall *PFNtWow64QueryInformationProcess64)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS_SR ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(__stdcall *PFNtWow64ReadVirtualMemory64)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID64 BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in ULONGLONG BufferSize,
	__out_opt PULONGLONG NumberOfBytesRead
	);

typedef NTSTATUS(__stdcall *PFNtWow64WriteVirtualMemory64)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID64 BaseAddress,
	__in_bcount(BufferSize) PVOID Buffer,
	__in ULONGLONG BufferSize,
	__out_opt PULONGLONG NumberOfBytesWritten
	);

typedef NTSTATUS(__stdcall *PFRtlUnicodeStringToAnsiString)(
	PANSI_STRING_SR DestinationString,
	PUNICODE_STRING_SR SourceString,
	BOOLEAN AllocateDestinationString
);

typedef VOID (__stdcall *PFRtlFreeAnsiString)(
	PANSI_STRING_SR AnsiString
);

typedef NTSTATUS(__stdcall *PFNtProtectVirtualMemory)(
	_In_	HANDLE		ProcessHandle,
	_Inout_ PVOID		*UnsafeBaseAddress,
	_Inout_ SIZE_T		*UnsafeNumberOfBytesToProtect,
	_In_	ULONG		NewAccessProtection,
	_Out_	PULONG		UnsafeOldAccessProtection
	);

typedef enum _SECTION_INHERIT_SR
{
	ViewShare_Sr = 1,
	ViewUnmap_Sr = 2
} SECTION_INHERIT_SR;

typedef NTSTATUS(__stdcall *PFNtMapViewOfSection) (
	HANDLE				SectionHandle,
	HANDLE				ProcessHandle,
	PVOID				*BaseAddress,
	ULONG_PTR			ZeroBits,
	SIZE_T				CommitSize,
	PLARGE_INTEGER		SectionOffset,
	PSIZE_T				ViewSize,
	SECTION_INHERIT_SR	InheritDisposition,
	ULONG				AllocationType,
	ULONG				Win32Protect
	);

typedef NTSTATUS(__stdcall *PFNtUnmapViewOfSection)(
	HANDLE				ProcessHandle,
	PVOID				BaseAddress
	);

typedef NTSTATUS(__stdcall *PFNtFreeVirtualMemory)(
	_In_    HANDLE  ProcessHandle,
	_Inout_ PVOID   *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_    ULONG   FreeType
	);

typedef NTSTATUS(__stdcall *PFNtAllocateVirtualMemory)(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);

typedef PVOID(__stdcall * PFRtlGetCallersAddress)(
	OUT PVOID               *CallersAddress,
	OUT PVOID               *CallersCaller
	);

typedef ULONG(__stdcall *PFRtlWalkFrameChain)(
	OUT PVOID *Callers,
	IN ULONG Count, 
	IN ULONG Flags
	);

//用ntdll!LdrRegisterDllNotification函数注册模块加载回调时，添加的回调函数的原型
typedef VOID(CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION_SR)(
	_In_     ULONG							NotificationReason,	//1是加载模块，2是卸载模块
	_In_     PCLDR_DLL_NOTIFICATION_DATA_SR NotificationData,
	_In_opt_ PVOID							Context				//传递过来的附加参数
	);

//ntdll!PFLdrRegisterDllNotification
//向系统注册回调函数，用以监控模块的加载和卸载。貌似这个函数没有进内核
//https://soft-app.iteye.com/blog/922617
typedef NTSTATUS(__stdcall *PFLdrRegisterDllNotification)(
	_In_     ULONG									Flags,					//参数必须为0
	_In_     PLDR_DLL_NOTIFICATION_FUNCTION_SR		NotificationFunction,	//回调函数的地址
	_In_opt_ PVOID									Context,				//想要向回调函数附加的参数的指针，类似于线程创建时允许附加一个参数
	_Out_    PVOID									*Cookie					//注册模块回调后的返回标识，在卸载回调时将使用此标识
);

typedef NTSTATUS(__stdcall *PFLdrUnregisterDllNotification)(void *Cookie);	//卸载向系统提交的进程模块加载回调

//enum SECTION_INFORMATION_CLASS_SR//ntdll!NtQuerySection函数调用
//{
//	SectionBasicInformation_Sr,
//	SectionImageInformation_Sr
//};
//
//typedef struct _SECTION_BASIC_INFORMATION_SR {
//
//	ULONG                   Unknown;
//	size_t                   SectionAttributes;
//	LARGE_INTEGER           SectionSize;
//
//} SECTION_BASIC_INFORMATION_SR, *PSECTION_BASIC_INFORMATION_SR;
//
//
//typedef struct _SECTION_IMAGE_INFORMATION_SR {
//	PVOID                   EntryPoint;
//	ULONG                   StackZeroBits;
//	ULONG                   StackReserved;
//	ULONG                   StackCommit;
//	ULONG                   ImageSubsystem;
//	WORD                    SubSystemVersionLow;
//	WORD                    SubSystemVersionHigh;
//	ULONG                   Unknown1;
//	ULONG                   ImageCharacteristics;
//	ULONG                   ImageMachineType;
//	ULONG                   Unknown2[3];
//
//} SECTION_IMAGE_INFORMATION_SR, *PSECTION_IMAGE_INFORMATION_SR;
//
//typedef NTSTATUS(__stdcall *PFNtQuerySection)(
//	IN HANDLE               SectionHandle,
//	IN SECTION_INFORMATION_CLASS_SR InformationClass,
//	OUT PVOID               InformationBuffer,
//	IN ULONG                InformationBufferSize,
//	OUT PULONG              ResultLength OPTIONAL
//	);

#endif//SR_H