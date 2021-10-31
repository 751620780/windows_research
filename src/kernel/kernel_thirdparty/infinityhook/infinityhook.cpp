
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <intrin.h>
#include "infinityhook.h"



#define EtwpStartTrace		1
#define EtwpStopTrace		2
#define EtwpQueryTrace		3
#define EtwpUpdateTrace		4
#define EtwpFlushTrace		5

#define WNODE_FLAG_TRACED_GUID			0x00020000								// denotes a trace

// 设置不同的标志位开启不同的etw记录日志的方式，以下内容参考自：https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
// The following constants represent the possible logging modes for an event tracing session.
// The constants are used in the LogFileMode members of EVENT_TRACE_LOGFILE, EVENT_TRACE_PROPERTIES and TRACE_LOGFILE_HEADER structures.These constants are defined in the Evntrace.h header file.
//	Mode												Description
//	EVENT_TRACE_FILE_MODE_NONE(0x00000000)				Same as EVENT_TRACE_FILE_MODE_SEQUENTIAL with no maximum file size specified.
//	EVENT_TRACE_FILE_MODE_SEQUENTIAL(0x00000001)		Writes events to a log file sequentially; stops when the file reaches its maximum size.Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR or EVENT_TRACE_FILE_MODE_NEWFILE.
//	EVENT_TRACE_FILE_MODE_CIRCULAR(0x00000002)			Writes events to a log file.After the file reaches the maximum size, the oldest events are replaced with incoming events.Note that the contents of the circular log file may appear out of order on multiprocessor computers.
//														Do not use with EVENT_TRACE_FILE_MODE_APPEND, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
//	EVENT_TRACE_FILE_MODE_APPEND(0x00000004)			Appends events to an existing sequential log file.If the file does not exist, it is created.Use only if you specify system time for the clock resolution, otherwise, ProcessTrace will return events with incorrect time stamps.When using EVENT_TRACE_FILE_MODE_APPEND, the values for BufferSize, NumberOfProcessors, and ClockType must be explicitly provided and must be the same in both the logger and the file being appended.
//														Do not use with EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_PRIVATE_LOGGER_MODE.
//														Windows 2000: This value is not supported.
//	EVENT_TRACE_FILE_MODE_NEWFILE(0x00000008)			Automatically switches to a new log file when the file reaches the maximum size.The MaximumFileSize member of EVENT_TRACE_PROPERTIES must be set.The specified file name must be a formatted string(for example, the string contains a %d, such as c : \test%d.etl).Each time a new file is created, a counter is incremented and its value is used, the formatted string is updated, and the resulting string is used as the file name.
//														This option is not allowed for private event tracing sessions and should not be used for NT kernel logger sessions.
//														Do not use with EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_APPEND or EVENT_TRACE_FILE_MODE_SEQUENTIAL.
//														Windows 2000 : This value is not supported.
//	EVENT_TRACE_FILE_MODE_PREALLOCATE(0x00000020)		Reserves EVENT_TRACE_PROPERTIES.MaximumFileSize bytes of disk space for the log file in advance.The file occupies the entire space during logging, for both circular and sequential log files.When you stop the session, the log file is reduced to the size needed.You must set EVENT_TRACE_PROPERTIES.MaximumFileSize.
//														You cannot use the mode for private event tracing sessions.
//														Windows 2000 : This value is not supported.
//														EVENT_TRACE_NONSTOPPABLE_MODE(0x00000040)	The logging session cannot be stopped.This mode is only supported by Autologger.This option is supported on Windows Vista and later.
//														.
//	EVENT_TRACE_SECURE_MODE(0X00000080)					Restricts who can log events to the session to those with TRACELOG_LOG_EVENT permission.This option is supported on Windows Vista and later.
//	EVENT_TRACE_REAL_TIME_MODE(0x00000100)				Delivers the events to consumers in real - time.Events are delivered when the buffers are flushed, not at the time the provider writes the event.You should not enable real - time mode if there are no consumers to consume the events because calls to log events will eventually fail when the buffers become full.Prior to Windows Vista, if the events were not being consumed, the events were discarded.Do not specify more than one real - time consumer in one process on Windows XP orWindows Server 2003. Instead, have one thread consume events and distribute the events to others.
//														Prior to Windows Vista : You should not use real - time mode because the supported event rate is much lower than reading from the log file(events may be dropped).Also, the event order is not guaranteed on computers with multiple processors.The real - time mode is more suitable for low - traffic, notification type events.
//
//														You can combine this mode with other log file modes; however, do not use this mode with EVENT_TRACE_PRIVATE_LOGGER_MODE.Note that if you combine this mode with other log file modes, buffers will be flushed once every second, resulting in partially filled buffers being written to your log file.For example if you use 64k buffers and your logging rate is 1 event every second, the service will write 64k / second to your log file.
//														EVENT_TRACE_DELAY_OPEN_FILE_MODE(0x00000200)	This mode is used to delay opening the log file until an event occurs.
//														[!Note]
//														On Windows Vista or later, this mode is not applicable should not be used.
//
//	EVENT_TRACE_BUFFERING_MODE(0x00000400)				This mode writes events to a circular memory buffer.Events written beyond the total size of the buffer evict the oldest events still remaining in the buffer.The size of this memory buffer is the product of MinimumBuffers and BufferSize(see EVENT_TRACE_PROPERTIES).As a consequence of this formula, any buffer that uses EVENT_TRACE_BUFFERING_MODE will ignore the MaximumBuffers value.
//														Events are not written to a log file or delivered in real - time, and ETW does not flush the buffers.To get a snapshot of the buffer, call the FlushTrace function.
//														This mode is particularly useful for debugging device drivers in conjunction with the ability to view the contents of in - memory buffers with the WMITrace kernel debugger extension.
//														Do not use with EVENT_TRACE_FILE_MODE_SEQUENTIAL, EVENT_TRACE_FILE_MODE_CIRCULAR, EVENT_TRACE_FILE_MODE_APPEND, EVENT_TRACE_FILE_MODE_NEWFILE, or EVENT_TRACE_REAL_TIME_MODE.
//	EVENT_TRACE_PRIVATE_LOGGER_MODE(0x00000800)			Creates a user - mode event tracing session that runs in the same process as its event trace provider.The memory for buffers comes from the process's memory. Processes that do not require data from the kernel can eliminate the overhead associated with kernel-mode transitions by using a private event tracing session.
//														If the provider is registered by multiple processes, ETW appends the process identifier to the log file name to create a unique log file name.For example, if the controller specifies the log file names as c : \mylogs\myprivatelog.etl, ETW creates the log file as c : \mylogs\myprivatelog.etl_nnnn, where nnnn is the process identifier.The process identifier is not appended to the first process that registers the provider, it is appended to only the subsequent processes that register the provider.
//														Private event tracing sessions have the following limitations :
//														A private session can record events only for the threads of the process in which it is executing.
//														There can be up to eight private session per process.
//														Private sessions cannot be used with real - time delivery.
//														Events that are generated by a private session do not include execution time for kernel - mode versus user - mode instructions, or thread - level detail of the CPU time used.
//														Process ID filters and executable name filters can now be passed in to session control APIs when system wide private loggers are started.For the best results in cross process scenarios, the same filters should be passed to every control operation during the session, including provider enable / diasble calls.Note that the filters have the same format as those consumed by EnableTraceEx2.
//														You can use this mode in conjunction with the EVENT_TRACE_PRIVATE_IN_PROC mode.
//														Prior to Windows 10, version 1703: Only LocalSystem, the administrator, and users in the administrator group that run in an elevated process can create a private session.If you include the EVENT_TRACE_PRIVATE_IN_PROC flag, any user can create an in - process private session.Also, in prior versions of Windows, there can only be one private session per process(unless the EVENT_TRACE_PRIVATE_IN_PROC mode is also specified, in which case you can create up to three in - process private sessions).
//														Prior to Windows Vista : Users in the Performance Log Users group could also create a private session.
//
//														Do not use with EVENT_TRACE_REAL_TIME_MODE.
//														Prior to Windows 7 and Windows Server 2008 R2 : Do not use with EVENT_TRACE_FILE_MODE_NEWFILE.
//	EVENT_TRACE_ADD_HEADER_MODE(0x00001000)				This option adds a header to the log file.
//														[!Note]
//														On Windows Vista or later, this mode is not applicable should not be used.
//
//	EVENT_TRACE_USE_KBYTES_FOR_SIZE(0x00002000)			Use kilobytes as the unit of measure for specifying the size of a file.The default unit of measure is megabytes.This mode applies to the MaxFileSize registry value for an AutoLogger session and the MaximumFileSize member of EVENT_TRACE_PROPERTIES.This option is supported on Windows Vista and later.
//	EVENT_TRACE_USE_GLOBAL_SEQUENCE(0x00004000)			Uses sequence numbers that are unique across event tracing sessions.This mode only applies to events logged using the TraceMessage function.For more information, see TraceMessage for usage details.
//														EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
//														Windows 2000: This value is not supported.
//	EVENT_TRACE_USE_LOCAL_SEQUENCE(0x00008000)			Uses sequence numbers that are unique only for an individual event tracing session.This mode only applies to events logged using the TraceMessage function.For more information, see TraceMessage for usage details.
//														EVENT_TRACE_USE_GLOBAL_SEQUENCE and EVENT_TRACE_USE_LOCAL_SEQUENCE are mutually exclusive.
//														Windows 2000 : This value is not supported.
//	EVENT_TRACE_RELOG_MODE(0x00010000)					Logs the event without including EVENT_TRACE_HEADER.
//														[!Note]
//														This mode should not be used.It is reserved for internal use.
//
//														Windows 2000 : This value is not supported.
//	EVENT_TRACE_PRIVATE_IN_PROC(0x00020000)				Use in conjunction with the EVENT_TRACE_PRIVATE_LOGGER_MODE mode to start a private session.This mode enforces that only the process that registered the provider GUID can start the logger session with that GUID.
//														You can create up to three in - process private sessions per process.
//														This option is supported on Windows Vista and later.
//	EVENT_TRACE_MODE_RESERVED(0x00100000)				This option is used to signal heap and critical section tracing.This option is supported on Windows Vista and later.
//	EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN(0x00400000)		This option stops logging on hybrid shutdown.If neither EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN or EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN is specified, ETW will chose a default based on whether the caller is coming from Session 0 or not.This option is supported on Windows 8 and Windows Server 2012.
//	EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN(0x00800000)	This option continues logging on hybrid shutdown.If neither EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN or EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN is specified, ETW will chose a default based on whether the caller is coming from Session 0 or not.This option is supported on Windows 8 and Windows Server 2012.
//	EVENT_TRACE_USE_PAGED_MEMORY(0x01000000)			Uses paged memory.This setting is recommended so that events do not use up the nonpaged memory.Nonpaged buffers use nonpaged memory for buffer space.Because nonpaged buffers are never paged out, a logging session performs well.Using pageable buffers is less resource - intensive.
//														Kernel - mode providers and system loggers cannot log events to sessions that specify this logging mode.
//														This mode is ignored if EVENT_TRACE_PRIVATE_LOGGER_MODE is set.
//														You cannot use this mode with the NT Kernel Logger.
//														Windows 2000: This value is not supported.
//	EVENT_TRACE_SYSTEM_LOGGER_MODE(0x02000000)			This option will receive events from SystemTraceProvider.If the StartTraceProperties parameter LogFileMode includes this flag, the logger will be a system logger.This option is supported on Windows 8 and Windows Server 2012.
//	EVENT_TRACE_INDEPENDENT_SESSION_MODE(0x08000000)	Indicates that a logging session should not be affected by EventWrite failures in other sessions.Without this flag, if an event cannot be published to one of the sessions that a provider is enabled to, the event will not get published to any of the sessions.When this flag is set, a failure to write an event to one session will not cause the EventWrite function to return an error code in other sessions.
//														Do not use with EVENT_TRACE_PRIVATE_LOGGER_MODE.
//														This option is supported on Windows 8.1, Windows Server 2012 R2, and later.
//	EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING(0x10000000)	Writes events that were logged on different processors to a common buffer.Using this mode can eliminate the issue of events appearing out of order when events are being published on different processors using system time.This mode can also eliminate the issue with circular logs appearing to drop events on multiple processor computers.
//														If you do not use this mode and you use system time, the events may appear out of order on multiple processor computers.This is because ETW buffers are associated with a processor instead of a thread.As a result, if a thread is switched from one CPU to another, the buffer associated with the latter CPU can be flushed to disk before the one associated with the former CPU.
//														If you expect a high volume of events(for example, more than 1, 000 events per second), you should not use this mode.
//														Note that the processor number is not included with the event.
//														This option is supported on Windows 7, Windows Server 2008 R2, and later.
//	EVENT_TRACE_ADDTO_TRIAGE_DUMP(0x80000000)			This option adds ETW buffers to triage dumps.This option is supported on Windows 8 and Windows Server 2012.
//
#define EVENT_TRACE_BUFFERING_MODE      0x00000400								// Buffering mode only

// ETW的类型，参考自：https://docs.microsoft.com/en-us/windows/win32/etw/event-trace-properties

#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080								// system calls

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES	16
#define IMAGE_SIZEOF_SHORT_NAME             8

#define IA32_LSTAR_MSR 0xC0000082

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)			\
    ((ULONG_PTR)(ntheader) +FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader\
	) +((ntheader))->FileHeader.SizeOfOptionalHeader))

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,															// q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation,														// q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation,
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation, // q: ULONG
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // 180
	SystemSupportedProcessorArchitectures,
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed, // s: ULONG
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG		VirtualAddress;
	ULONG		Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR		Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		ULONG	PhysicalAddress;
		ULONG	VirtualSize;
	} Misc;
	ULONG   VirtualAddress;
	ULONG   SizeOfRawData;
	ULONG   PointerToRawData;
	ULONG   PointerToRelocations;
	ULONG   PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT      Magic;
	UCHAR       MajorLinkerVersion;
	UCHAR       MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT      MajorOperatingSystemVersion;
	USHORT      MinorOperatingSystemVersion;
	USHORT      MajorImageVersion;
	USHORT      MinorImageVersion;
	USHORT      MajorSubsystemVersion;
	USHORT      MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT      Subsystem;
	USHORT      DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
	USHORT		Machine;
	USHORT		NumberOfSections;
	ULONG		TimeDateStamp;
	ULONG		PointerToSymbolTable;
	ULONG		NumberOfSymbols;
	USHORT		SizeOfOptionalHeader;
	USHORT		Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, *PWNODE_HEADER;

//参考：https://docs.microsoft.com/en-us/windows/win32/etw/event-trace-properties
typedef struct _EVENT_TRACE_PROPERTIES {
	// A WNODE_HEADER structure.You must specify the BufferSize, Flags, and Guid members, and optionally the ClientContext
	WNODE_HEADER	Wnode;					
	// Amount of memory allocated for each event tracing session buffer, in kilobytes.The maximum buffer size is 1 MB.ETW uses the size of physical memory to calculate this value.For more information, see Remarks.
	// If an application expects a relatively low event rate, the buffer size should be set to the memory page size. If the event rate is expected to be relatively high, the application should specify a larger buffer size, and should increase the maximum number of buffers.
	// The buffer size affects the rate at which buffers fill and must be flushed. Although a small buffer size requires less memory, it increases the rate at which buffers must be flushed.
	ULONG			BufferSize;				
	// Minimum number of buffers allocated for the event tracing session's buffer pool. The minimum number of buffers that you can specify is two buffers per processor. 
	// For example, on a single processor computer, the minimum number of buffers is two. Note that if you use the EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING logging mode, the number of processors is assumed to be 1.											
	ULONG			MinimumBuffers;	
	// Maximum number of buffers allocated for the event tracing session's buffer pool. Typically, this value is the minimum number of buffers plus twenty. ETW uses the buffer size and the size of physical memory to calculate this value. 
	// This value must be greater than or equal to the value for MinimumBuffers.
	// Note that you do not need to set this value if LogFileMode contains EVENT_TRACE_BUFFERING_MODE; instead, the total memory buffer size is instead the product of MinimumBuffers and BufferSize.
	ULONG			MaximumBuffers;
	// Maximum size of the file used to log events, in megabytes. Typically, you use this member to limit the size of a circular log file when you set LogFileMode to EVENT_TRACE_FILE_MODE_CIRCULAR. 
	// This member must be specified if LogFileMode contains EVENT_TRACE_FILE_MODE_PREALLOCATE, EVENT_TRACE_FILE_MODE_CIRCULAR or EVENT_TRACE_FILE_MODE_NEWFILE
	// If you are using the system drive(the drive that contains the operating system) for logging, ETW checks for an additional 200MB of disk space, regardless of whether you are using the maximum file size parameter.
	// Therefore, if you specify 100MB as the maximum file size for the trace file in the system drive, you need to have 300MB of free space on the drive.
	ULONG			MaximumFileSize;
	// Logging modes for the event tracing session. You use this member to specify that you want events written to a log file, a real-time consumer, or both. You can also use this member to specify that the session is a private logger session.
	// You can specify one or more modes. For a list of possible modes, see Logging Mode Constants.
	// Do not specify real - time logging unless there are real - time consumers ready to consume the events.If there are no real - time consumers, ETW writes the events to a playback file.However, the size of the playback file is limited.If the limit is reached, no new events are logged(to the log file or playback file) and the logging functions fail with STATUS_LOG_FILE_FULL.
	// Prior to Windows Vista : If there was no real - time consumer, the events were discarded and logging continues.
	// If a consumer begins processing real - time events, the events in the playback file are consumed first.After all events in the playback file are consumed, the session will begin logging new events.
	ULONG			LogFileMode;
	// How often, in seconds, the trace buffers are forcibly flushed. The minimum flush time is 1 second. This forced flush is in addition to the automatic flush that occurs whenever a buffer is full and when the trace session stops.
	// If zero, ETW flushes buffers as soon as they become full.If nonzero, ETW flushes all buffers that contain events based on the timer value.Typically, you want to flush buffers only when they become full.Forcing the buffers to flush(either by setting this member to a nonzero value or by calling FlushTrace) can increase the file size of the log file with unfilled buffer space.
	// If the consumer is consuming events in real time, you may want to set this member to a nonzero value if the event rate is low to force events to be delivered before the buffer is full.
	// For the case of a realtime logger, a value of zero(the default value) means that the flush time will be set to 1 second.A realtime logger is when LogFileMode is set to EVENT_TRACE_REAL_TIME_MODE.
	ULONG			FlushTimer;
	// A system logger must set EnableFlags to indicate which SystemTraceProvider events should be included in the trace.
	// This is also used for NT Kernel Logger sessions. This member can contain one or more of the following values. 
	// In addition to the events you specify, the kernel logger also logs hardware configuration events on Windows XP or system configuration events on Windows Server 2003.
	//		Flag									Meaning
	//		EVENT_TRACE_FLAG_ALPC
	//		0x00100000
	//												Enables the ALPC event types.
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_CSWITCH
	//		0x00000010
	//												Enables the following Thread event type:
	//													CSwitch
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_DBGPRINT
	//		0x00040000
	//												Enables the DbgPrint and DbgPrintEx calls to be converted to ETW events.
	//		EVENT_TRACE_FLAG_DISK_FILE_IO
	//		0x00000200
	//												Enables the following FileIo event type(you must also enable EVENT_TRACE_FLAG_DISK_IO) :
	//													FileIo_Name
	//		EVENT_TRACE_FLAG_DISK_IO
	//		0x00000100
	//												Enables the following DiskIo event types :
	//													DiskIo_TypeGroup1
	//													DiskIo_TypeGroup3
	//		EVENT_TRACE_FLAG_DISK_IO_INIT
	//		0x00000400
	//												Enables the following DiskIo event type :
	//													DiskIo_TypeGroup2
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_DISPATCHER
	//		0x00000800
	//												Enables the following Thread event type:
	//													ReadyThread
	//	
	//												This value is supported on Windows 7, Windows Server 2008 R2, and later.
	//		EVENT_TRACE_FLAG_DPC
	//		0x00000020
	//												Enables the following PerfInfo event type:
	//													DPC
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_DRIVER
	//		0x00800000
	//												Enables the following DiskIo event types:
	//													DriverCompleteRequest
	//													DriverCompleteRequestReturn
	//													DriverCompletionRoutine
	//													DriverMajorFunctionCall
	//													DriverMajorFunctionReturn
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_FILE_IO
	//		0x02000000
	//												Enables the following FileIo event types:
	//													FileIo_OpEnd
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_FILE_IO_INIT
	//		0x04000000
	//												Enables the following FileIo event type:
	//													FileIo_Create
	//													FileIo_DirEnum
	//													FileIo_Info
	//													FileIo_ReadWrite
	//													FileIo_SimpleOp
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_IMAGE_LOAD
	//		0x00000004
	//												Enables the following Image event type:
	//													Image_Load
	//		EVENT_TRACE_FLAG_INTERRUPT
	//		0x00000040
	//												Enables the following PerfInfo event type :
	//													ISR
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_JOB
	//		0x00080000
	//												This value is supported on Windows 10
	//		EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS
	//		0x00002000
	//												Enables the following PageFault_V2 event type:
	//													PageFault_HardFault
	//		EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS
	//		0x00001000
	//												Enables the following PageFault_V2 event type :
	//													PageFault_TypeGroup1
	//		EVENT_TRACE_FLAG_NETWORK_TCPIP
	//		0x00010000
	//												Enables the TcpIp and UdpIp event types.
	//		EVENT_TRACE_FLAG_NO_SYSCONFIG
	//		0x10000000
	//												Do not do a system configuration rundown.
	//												This value is supported on Windows 8, Windows Server 2012, and later.
	//		EVENT_TRACE_FLAG_PROCESS
	//		0x00000001
	//												Enables the following Process event type:
	//													Process_TypeGroup1
	//		EVENT_TRACE_FLAG_PROCESS_COUNTERS
	//		0x00000008
	//												Enables the following Process_V2 event type :
	//													Process_V2_TypeGroup2
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_PROFILE
	//		0x01000000
	//												Enables the following PerfInfo event type:
	//													SampledProfile
	//	
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_REGISTRY
	//		0x00020000
	//												Enables the Registry event types.
	//		EVENT_TRACE_FLAG_SPLIT_IO
	//		0x00200000
	//												Enables the SplitIo event types.
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_SYSTEMCALL
	//		0x00000080
	//												Enables the following PerfInfo event type:
	//													SysCallEnter
	//													SysCallExit
	//
	//												This value is supported on Windows Vista and later.
	//		EVENT_TRACE_FLAG_THREAD
	//		0x00000002
	//												Enables the following Thread event type:
	//													Thread_TypeGroup1
	//		EVENT_TRACE_FLAG_VAMAP
	//		0x00008000
	//												Enables the map and unmap(excluding image files) event type.
	//												This value is supported on Windows 8, Windows Server 2012, and later.
	//		EVENT_TRACE_FLAG_VIRTUAL_ALLOC
	//		0x00004000
	//												Enables the following PageFault_V2 event type:
	//													PageFault_VirtualAlloc
	//
	//												This value is supported on Windows 7, Windows Server 2008 R2, and later.
	ULONG			EnableFlags;

	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

/* 54dea73a-ed1f-42a4-af713e63d056f174 */
const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

EXTERN_C
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID ModuleAddress
);



#define C_NONE    0x00
#define C_MODRM   0x01
#define C_IMM8    0x02
#define C_IMM16   0x04
#define C_IMM_P66 0x10
#define C_REL8    0x20
#define C_REL32   0x40
#define C_GROUP   0x80
#define C_ERROR   0xff

#define PRE_ANY  0x00
#define PRE_NONE 0x01
#define PRE_F2   0x02
#define PRE_F3   0x04
#define PRE_66   0x08
#define PRE_67   0x10
#define PRE_LOCK 0x20
#define PRE_SEG  0x40
#define PRE_ALL  0xff

#define DELTA_OPCODES      0x4a
#define DELTA_FPU_REG      0xfd
#define DELTA_FPU_MODRM    0x104
#define DELTA_PREFIXES     0x13c
#define DELTA_OP_LOCK_OK   0x1ae
#define DELTA_OP2_LOCK_OK  0x1c6
#define DELTA_OP_ONLY_MEM  0x1d8
#define DELTA_OP2_ONLY_MEM 0x1e7

unsigned char hde64_table[] = {
  0xa5,0xaa,0xa5,0xb8,0xa5,0xaa,0xa5,0xaa,0xa5,0xb8,0xa5,0xb8,0xa5,0xb8,0xa5,
  0xb8,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xc0,0xac,0xc0,0xcc,0xc0,0xa1,0xa1,
  0xa1,0xa1,0xb1,0xa5,0xa5,0xa6,0xc0,0xc0,0xd7,0xda,0xe0,0xc0,0xe4,0xc0,0xea,
  0xea,0xe0,0xe0,0x98,0xc8,0xee,0xf1,0xa5,0xd3,0xa5,0xa5,0xa1,0xea,0x9e,0xc0,
  0xc0,0xc2,0xc0,0xe6,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0xab,
  0x8b,0x90,0x64,0x5b,0x5b,0x5b,0x5b,0x5b,0x92,0x5b,0x5b,0x76,0x90,0x92,0x92,
  0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x6a,0x73,0x90,
  0x5b,0x52,0x52,0x52,0x52,0x5b,0x5b,0x5b,0x5b,0x77,0x7c,0x77,0x85,0x5b,0x5b,
  0x70,0x5b,0x7a,0xaf,0x76,0x76,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,0x5b,
  0x5b,0x5b,0x86,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xd5,0x03,0xcc,0x01,0xbc,
  0x03,0xf0,0x03,0x03,0x04,0x00,0x50,0x50,0x50,0x50,0xff,0x20,0x20,0x20,0x20,
  0x01,0x01,0x01,0x01,0xc4,0x02,0x10,0xff,0xff,0xff,0x01,0x00,0x03,0x11,0xff,
  0x03,0xc4,0xc6,0xc8,0x02,0x10,0x00,0xff,0xcc,0x01,0x01,0x01,0x00,0x00,0x00,
  0x00,0x01,0x01,0x03,0x01,0xff,0xff,0xc0,0xc2,0x10,0x11,0x02,0x03,0x01,0x01,
  0x01,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0x00,0x00,0xff,0xff,0xff,0xff,0x10,
  0x10,0x10,0x10,0x02,0x10,0x00,0x00,0xc6,0xc8,0x02,0x02,0x02,0x02,0x06,0x00,
  0x04,0x00,0x02,0xff,0x00,0xc0,0xc2,0x01,0x01,0x03,0x03,0x03,0xca,0x40,0x00,
  0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,0x00,0x00,0x00,
  0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0xff,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,
  0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7f,0x00,0x00,
  0xff,0x40,0x40,0x40,0x40,0x41,0x49,0x40,0x40,0x40,0x40,0x4c,0x42,0x40,0x40,
  0x40,0x40,0x40,0x40,0x40,0x40,0x4f,0x44,0x53,0x40,0x40,0x40,0x44,0x57,0x43,
  0x5c,0x40,0x60,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
  0x40,0x40,0x64,0x66,0x6e,0x6b,0x40,0x40,0x6a,0x46,0x40,0x40,0x44,0x46,0x40,
  0x40,0x5b,0x44,0x40,0x40,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x06,0x01,0x06,
  0x06,0x02,0x06,0x06,0x00,0x06,0x00,0x0a,0x0a,0x00,0x00,0x00,0x02,0x07,0x07,
  0x06,0x02,0x0d,0x06,0x06,0x06,0x0e,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
  0x04,0x04,0x05,0x06,0x06,0x06,0x00,0x00,0x00,0x0e,0x00,0x00,0x08,0x00,0x10,
  0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,0x86,0x00,
  0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,0xf8,0xbb,
  0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,0xc4,0xff,
  0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,0x13,0x09,
  0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,0xb2,0xff,
  0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,0xe7,0x08,
  0x00,0xf0,0x02,0x00
};

typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#define F_MODRM         0x00000001
#define F_SIB           0x00000002
#define F_IMM8          0x00000004
#define F_IMM16         0x00000008
#define F_IMM32         0x00000010
#define F_IMM64         0x00000020
#define F_DISP8         0x00000040
#define F_DISP16        0x00000080
#define F_DISP32        0x00000100
#define F_RELATIVE      0x00000200
#define F_ERROR         0x00001000
#define F_ERROR_OPCODE  0x00002000
#define F_ERROR_LENGTH  0x00004000
#define F_ERROR_LOCK    0x00008000
#define F_ERROR_OPERAND 0x00010000
#define F_PREFIX_REPNZ  0x01000000
#define F_PREFIX_REPX   0x02000000
#define F_PREFIX_REP    0x03000000
#define F_PREFIX_66     0x04000000
#define F_PREFIX_67     0x08000000
#define F_PREFIX_LOCK   0x10000000
#define F_PREFIX_SEG    0x20000000
#define F_PREFIX_REX    0x40000000
#define F_PREFIX_ANY    0x7f000000

#define PREFIX_SEGMENT_CS   0x2e
#define PREFIX_SEGMENT_SS   0x36
#define PREFIX_SEGMENT_DS   0x3e
#define PREFIX_SEGMENT_ES   0x26
#define PREFIX_SEGMENT_FS   0x64
#define PREFIX_SEGMENT_GS   0x65
#define PREFIX_LOCK         0xf0
#define PREFIX_REPNZ        0xf2
#define PREFIX_REPX         0xf3
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67

#pragma pack(push,1)

typedef struct {
	uint8_t len;
	uint8_t p_rep;
	uint8_t p_lock;
	uint8_t p_seg;
	uint8_t p_66;
	uint8_t p_67;
	uint8_t rex;
	uint8_t rex_w;
	uint8_t rex_r;
	uint8_t rex_x;
	uint8_t rex_b;
	uint8_t opcode;
	uint8_t opcode2;
	uint8_t modrm;
	uint8_t modrm_mod;
	uint8_t modrm_reg;
	uint8_t modrm_rm;
	uint8_t sib;
	uint8_t sib_scale;
	uint8_t sib_index;
	uint8_t sib_base;
	union {
		uint8_t imm8;
		uint16_t imm16;
		uint32_t imm32;
		uint64_t imm64;
	} imm;
	union {
		uint8_t disp8;
		uint16_t disp16;
		uint32_t disp32;
	} disp;
	uint32_t flags;
} hde64s;

#pragma pack(pop)

unsigned int hde64_disasm(const void *code, hde64s *hs);



PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName,
	_Out_opt_ PULONG SizeOfImage);

PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection);

PVOID ImgGetSyscallEntry();

const void* MmSearchMemory(
	_In_ const void* Buffer,
	_In_ size_t SizeOfBuffer,
	_In_ const void* Signature,
	_In_ size_t SizeOfSignature);


#define OPCODE_JMP_NEAR 0xE9


unsigned int hde64_disasm(const void *code, hde64s *hs)
{
	uint8_t x, c, *p = (uint8_t *)code, cflags, opcode, pref = 0;
	uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
	uint8_t op64 = 0;

	// Avoid using memset to reduce the footprint.
	memset(hs, 0, sizeof(hde64s));

	for (x = 16; x; x--)
		switch (c = *p++) {
		case 0xf3:
			hs->p_rep = c;
			pref |= PRE_F3;
			break;
		case 0xf2:
			hs->p_rep = c;
			pref |= PRE_F2;
			break;
		case 0xf0:
			hs->p_lock = c;
			pref |= PRE_LOCK;
			break;
		case 0x26: case 0x2e: case 0x36:
		case 0x3e: case 0x64: case 0x65:
			hs->p_seg = c;
			pref |= PRE_SEG;
			break;
		case 0x66:
			hs->p_66 = c;
			pref |= PRE_66;
			break;
		case 0x67:
			hs->p_67 = c;
			pref |= PRE_67;
			break;
		default:
			goto pref_done;
		}
pref_done:

	hs->flags = (uint32_t)pref << 23;

	if (!pref)
		pref |= PRE_NONE;

	if ((c & 0xf0) == 0x40) {
		hs->flags |= F_PREFIX_REX;
		if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
			op64++;
		hs->rex_r = (c & 7) >> 2;
		hs->rex_x = (c & 3) >> 1;
		hs->rex_b = c & 1;
		if (((c = *p++) & 0xf0) == 0x40) {
			opcode = c;
			goto error_opcode;
		}
	}

	if ((hs->opcode = c) == 0x0f) {
		hs->opcode2 = c = *p++;
		ht += DELTA_OPCODES;
	}
	else if (c >= 0xa0 && c <= 0xa3) {
		op64++;
		if (pref & PRE_67)
			pref |= PRE_66;
		else
			pref &= ~PRE_66;
	}

	opcode = c;
	cflags = ht[ht[opcode / 4] + (opcode % 4)];

	if (cflags == C_ERROR) {
	error_opcode:
		hs->flags |= F_ERROR | F_ERROR_OPCODE;
		cflags = 0;
		if ((opcode & -3) == 0x24)
			cflags++;
	}

	x = 0;
	if (cflags & C_GROUP) {
		uint16_t t;
		t = *(uint16_t *)(ht + (cflags & 0x7f));
		cflags = (uint8_t)t;
		x = (uint8_t)(t >> 8);
	}

	if (hs->opcode2) {
		ht = hde64_table + DELTA_PREFIXES;
		if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
			hs->flags |= F_ERROR | F_ERROR_OPCODE;
	}

	if (cflags & C_MODRM) {
		hs->flags |= F_MODRM;
		hs->modrm = c = *p++;
		hs->modrm_mod = m_mod = c >> 6;
		hs->modrm_rm = m_rm = c & 7;
		hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

		if (x && ((x << m_reg) & 0x80))
			hs->flags |= F_ERROR | F_ERROR_OPCODE;

		if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
			uint8_t t = opcode - 0xd9;
			if (m_mod == 3) {
				ht = hde64_table + DELTA_FPU_MODRM + t * 8;
				t = ht[m_reg] << m_rm;
			}
			else {
				ht = hde64_table + DELTA_FPU_REG;
				t = ht[t] << m_reg;
			}
			if (t & 0x80)
				hs->flags |= F_ERROR | F_ERROR_OPCODE;
		}

		if (pref & PRE_LOCK) {
			if (m_mod == 3) {
				hs->flags |= F_ERROR | F_ERROR_LOCK;
			}
			else {
				uint8_t *table_end, op = opcode;
				if (hs->opcode2) {
					ht = hde64_table + DELTA_OP2_LOCK_OK;
					table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
				}
				else {
					ht = hde64_table + DELTA_OP_LOCK_OK;
					table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
					op &= -2;
				}
				for (; ht != table_end; ht++)
					if (*ht++ == op) {
						if (!((*ht << m_reg) & 0x80))
							goto no_lock_error;
						else
							break;
					}
				hs->flags |= F_ERROR | F_ERROR_LOCK;
			no_lock_error:
				;
			}
		}

		if (hs->opcode2) {
			switch (opcode) {
			case 0x20: case 0x22:
				m_mod = 3;
				if (m_reg > 4 || m_reg == 1)
					goto error_operand;
				else
					goto no_error_operand;
			case 0x21: case 0x23:
				m_mod = 3;
				if (m_reg == 4 || m_reg == 5)
					goto error_operand;
				else
					goto no_error_operand;
			}
		}
		else {
			switch (opcode) {
			case 0x8c:
				if (m_reg > 5)
					goto error_operand;
				else
					goto no_error_operand;
			case 0x8e:
				if (m_reg == 1 || m_reg > 5)
					goto error_operand;
				else
					goto no_error_operand;
			}
		}

		if (m_mod == 3) {
			uint8_t *table_end;
			if (hs->opcode2) {
				ht = hde64_table + DELTA_OP2_ONLY_MEM;
				table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
			}
			else {
				ht = hde64_table + DELTA_OP_ONLY_MEM;
				table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
			}
			for (; ht != table_end; ht += 2)
				if (*ht++ == opcode) {
					if (*ht++ & pref && !((*ht << m_reg) & 0x80))
						goto error_operand;
					else
						break;
				}
			goto no_error_operand;
		}
		else if (hs->opcode2) {
			switch (opcode) {
			case 0x50: case 0xd7: case 0xf7:
				if (pref & (PRE_NONE | PRE_66))
					goto error_operand;
				break;
			case 0xd6:
				if (pref & (PRE_F2 | PRE_F3))
					goto error_operand;
				break;
			case 0xc5:
				goto error_operand;
			}
			goto no_error_operand;
		}
		else
			goto no_error_operand;

	error_operand:
		hs->flags |= F_ERROR | F_ERROR_OPERAND;
	no_error_operand:

		c = *p++;
		if (m_reg <= 1) {
			if (opcode == 0xf6)
				cflags |= C_IMM8;
			else if (opcode == 0xf7)
				cflags |= C_IMM_P66;
		}

		switch (m_mod) {
		case 0:
			if (pref & PRE_67) {
				if (m_rm == 6)
					disp_size = 2;
			}
			else
				if (m_rm == 5)
					disp_size = 4;
			break;
		case 1:
			disp_size = 1;
			break;
		case 2:
			disp_size = 2;
			if (!(pref & PRE_67))
				disp_size <<= 1;
		}

		if (m_mod != 3 && m_rm == 4) {
			hs->flags |= F_SIB;
			p++;
			hs->sib = c;
			hs->sib_scale = c >> 6;
			hs->sib_index = (c & 0x3f) >> 3;
			if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
				disp_size = 4;
		}

		p--;
		switch (disp_size) {
		case 1:
			hs->flags |= F_DISP8;
			hs->disp.disp8 = *p;
			break;
		case 2:
			hs->flags |= F_DISP16;
			hs->disp.disp16 = *(uint16_t *)p;
			break;
		case 4:
			hs->flags |= F_DISP32;
			hs->disp.disp32 = *(uint32_t *)p;
		}
		p += disp_size;
	}
	else if (pref & PRE_LOCK)
		hs->flags |= F_ERROR | F_ERROR_LOCK;

	if (cflags & C_IMM_P66) {
		if (cflags & C_REL32) {
			if (pref & PRE_66) {
				hs->flags |= F_IMM16 | F_RELATIVE;
				hs->imm.imm16 = *(uint16_t *)p;
				p += 2;
				goto disasm_done;
			}
			goto rel32_ok;
		}
		if (op64) {
			hs->flags |= F_IMM64;
			hs->imm.imm64 = *(uint64_t *)p;
			p += 8;
		}
		else if (!(pref & PRE_66)) {
			hs->flags |= F_IMM32;
			hs->imm.imm32 = *(uint32_t *)p;
			p += 4;
		}
		else
			goto imm16_ok;
	}


	if (cflags & C_IMM16) {
	imm16_ok:
		hs->flags |= F_IMM16;
		hs->imm.imm16 = *(uint16_t *)p;
		p += 2;
	}
	if (cflags & C_IMM8) {
		hs->flags |= F_IMM8;
		hs->imm.imm8 = *p++;
	}

	if (cflags & C_REL32) {
	rel32_ok:
		hs->flags |= F_IMM32 | F_RELATIVE;
		hs->imm.imm32 = *(uint32_t *)p;
		p += 4;
	}
	else if (cflags & C_REL8) {
		hs->flags |= F_IMM8 | F_RELATIVE;
		hs->imm.imm8 = *p++;
	}

disasm_done:

	if ((hs->len = (uint8_t)(p - (uint8_t *)code)) > 15) {
		hs->flags |= F_ERROR | F_ERROR_LENGTH;
		hs->len = 15;
	}

	return (unsigned int)hs->len;
}



/*
*	Returns the base address and size of the specified image.
*/
PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName,
	_Out_opt_ PULONG SizeOfImage)
{
	if (SizeOfImage)
	{
		*SizeOfImage = 0;
	}

	PVOID Buffer = NULL;
	ULONG SizeOfBuffer = 0;
	do
	{
		//
		// Get the list of all kernel drivers that are loaded.
		//
		ULONG ReturnLength = 0;
		NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, SizeOfBuffer, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			break;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL)
		{
			//
			// Need a bigger buffer.
			//

			SizeOfBuffer = ReturnLength;

			if (Buffer)
			{
				ExFreePool(Buffer);
				Buffer = NULL;
			}

			Buffer = ExAllocatePool(NonPagedPool, SizeOfBuffer);
			if (!Buffer)
			{
				break;
			}
		}
		else
		{
			break;
		}
	} while (TRUE);

	if (!Buffer)
	{
		return NULL;
	}

	//
	// Find the one we're looking for...
	//
	PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)Buffer;
	for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];

		//
		// If you don't supply an image name, you'll get the first 
		// loaded driver which should be ntoskrnl.
		//
		if (!ImageName || !_stricmp(ImageName, (const char*)& ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName]))
		{
			if (SizeOfImage)
			{
				*SizeOfImage = ModuleInformation->ImageSize;
			}

			PVOID ImageBase = ModuleInformation->ImageBase;

			//
			// Free the buffer. Thanks to @tandasat for catching my 
			// silly mistake.
			//
			ExFreePool(Buffer);

			return ImageBase;
		}
	}

	ExFreePool(Buffer);

	return NULL;
}

/*
*	Retrieves the start of a PE section and its size within an
*	image.
*/
PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection)
{
	//
	// Get the IMAGE_NT_HEADERS.
	//
	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(ImageBase);
	if (!NtHeaders)
	{
		return NULL;
	}

	//
	// Walk the PE sections, looking for our target section.
	//
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME))
		{
			if (SizeOfSection)
			{
				*SizeOfSection = SectionHeader->SizeOfRawData;
			}

			return (PVOID)((uintptr_t)ImageBase + SectionHeader->VirtualAddress);
		}
	}

	return NULL;
}

/*
*	Retrieves the address of the non-KVA shadow system call entry.
*/
PVOID ImgGetSyscallEntry()
{
	//
	// Get the base address of the kernel.
	//
	PVOID NtBaseAddress = ImgGetBaseAddress(NULL, NULL);
	if (!NtBaseAddress)
	{
		return NULL;
	}

	// 在用户层调用syscall指令后进入内核执行的代码是KiSystemCall64Shadow，这段代码在KVASCODE节区，该节区在此CR3下可以访问
	// 代码从KiSystemCall64Shadow继续执行会按照代码顺序执行到KiSystemCall64ShadowCommon
	// 然后通过跳转指令执行KiSystemServiceUser（两种可能前者直接jmp过去，后则经历多次call调用最终依然jmp过去）
	// 而KiSystemServiceUser代码在text段，本函数完成KiSystemServiceUser起始地址的定位

	//
	// Get the LSTAR MSR. This should be KiSystemCall64 if KVA shadowing
	// is not enabled.
	//
	PVOID SyscallEntry = (PVOID)__readmsr(IA32_LSTAR_MSR);

	//
	// Get the PE section for KVASCODE. If one doesn't exit, KVA 
	// shadowing doesn't exist. This can be queried using 
	// NtQuerySystemInformation alternatively.
	//
	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, "KVASCODE", &SizeOfSection);
	if (!SectionBase)
	{
		return SyscallEntry;
	}

	//
	// Is the value within this KVA shadow region? If not, we're done.
	//
	if (!(SyscallEntry >= SectionBase && SyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection)))
	{
		return SyscallEntry;
	}

	//
	// This is KiSystemCall64Shadow.
	//
	hde64s HDE;
	for (PCHAR KiSystemServiceUser = (PCHAR)SyscallEntry; /* */; KiSystemServiceUser += HDE.len)
	{
		//
		// Disassemble every instruction till the first near jmp (E9).
		//
		if (!hde64_disasm(KiSystemServiceUser, &HDE))
		{
			break;
		}

		if (HDE.opcode != OPCODE_JMP_NEAR)
		{
			continue;
		}

		//
		// Ignore jmps within the KVA shadow region.
		//
		PVOID PossibleSyscallEntry = (PVOID)((intptr_t)KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32);
		if (PossibleSyscallEntry >= SectionBase && PossibleSyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection))
		{
			continue;
		}

		//
		// Found KiSystemServiceUser.
		//
		SyscallEntry = PossibleSyscallEntry;
		break;
	}

	return SyscallEntry;
}

/*
*	Search a memory buffer for the input signature.
*/
const void* MmSearchMemory(
	_In_ const void* Buffer,
	_In_ size_t SizeOfBuffer,
	_In_ const void* Signature,
	_In_ size_t SizeOfSignature)
{
	//
	// Sanity check...
	//
	if (SizeOfSignature > SizeOfBuffer)
	{
		return NULL;
	}

	PCHAR Memory = (PCHAR)Buffer;

	//
	// The +1 is necessary or there will be an off-by-one error. 
	// Thanks to @milabs for reporting.
	//
	for (size_t i = 0; i < ((SizeOfBuffer - SizeOfSignature) + 1); ++i)
	{
		if (!memcmp(&Memory[i], Signature, SizeOfSignature))
		{
			return &Memory[i];
		}
	}

	return NULL;
}

//
// Used internally for IfhpModifyTraceSettings.
//
typedef enum _CKCL_TRACE_OPERATION
{
	CKCL_TRACE_START,
	CKCL_TRACE_SYSCALL,
	CKCL_TRACE_END
}CKCL_TRACE_OPERATION;

//
// To enable/disable tracing on the circular kernel context logger.
//
typedef struct _CKCL_TRACE_PROPERIES :EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

static BOOLEAN IfhpResolveSymbols();

static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation);

static ULONG64 IfhpInternalGetCpuClock();

//
// Works from Windows 7+. You can backport this to Vista if you
// include an OS check and add the Vista appropriate signature.
//
UCHAR EtwpDebuggerDataPattern[] =
{
	0x2c,
	0x08,
	0x04,
	0x38,
	0x0c
};

//
// _WMI_LOGGER_CONTEXT.GetCpuClock.
//
#define OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK 0x28

//
// _KPCR.Prcb.RspBase.
//
#define OFFSET_KPCR_RSP_BASE 0x1A8

//
// _KPCR.Prcb.CurrentThread.
//
#define OFFSET_KPCR_CURRENT_THREAD 0x188

//
// _KTHREAD.SystemCallNumber.
//
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80

//
// EtwpDebuggerData silos.
//
#define OFFSET_ETW_DEBUGGER_DATA_SILO 0x10

//
// The index of the circular kernel context logger.
//
#define INDEX_CKCL_LOGGER 2

//
// Magic values on the stack. We use this to filter out system call 
// exit events.
//
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

static UINT8 IfhpInitialized = FALSE;
static INFINITYHOOKCALLBACK IfhpCallback = NULL;

static const void* EtwpDebuggerData = NULL;
static PVOID CkclWmiLoggerContext = NULL;
static PVOID SystemCallEntryPage = NULL;

/*
*	Initialize infinity hook: executes your user defined callback on
*	each syscall. You can extend this functionality to do other things
*	like trap on page faults, context switches, and more... This demo
*	only does syscalls.
*/
NTSTATUS IfhInitialize(_In_
	INFINITYHOOKCALLBACK InfinityHookCallback)
{
	if (IfhpInitialized == TRUE)
	{
		return STATUS_ACCESS_DENIED;
	}

	//
	// 先默认CKCL已经被启动了（windows下默认CKCL是启动的），我们尝试开启系统调用
	//
	NTSTATUS Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
	if (!NT_SUCCESS(Status))
	{
		//
		// 如果失败，表明CKCL没开启，那么开启后再次尝试
		//
		Status = IfhpModifyTraceSettings(CKCL_TRACE_START);

		//
		// Failed again... We exit here, but it's possible to setup
		// a custom logger instead and use SystemTraceProvider instead
		// of hijacking the circular kernel context logger.
		//
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}

		Status = IfhpModifyTraceSettings(CKCL_TRACE_SYSCALL);
		if (!NT_SUCCESS(Status))
		{
			return Status;
		}
	}

	//
	// 首先定位一些nt模块未导出的符号
	//
	if (!IfhpResolveSymbols())
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	IfhpCallback = InfinityHookCallback;

	//
	// CkclWmiLoggerContext is a WMI_LOGGER_CONTEXT structure:
	//
	/*
		windows 系统中该结构体大小可能发生变化，但目前看来相对偏移没有显著变化
		0: kd> dt nt!_WMI_LOGGER_CONTEXT
			   +0x000 LoggerId         : Uint4B
			   +0x004 BufferSize       : Uint4B
			   +0x008 MaximumEventSize : Uint4B
			   +0x00c LoggerMode       : Uint4B
			   +0x010 AcceptNewEvents  : Int4B
			   +0x014 EventMarker      : [2] Uint4B
			   +0x01c ErrorMarker      : Uint4B
			   +0x020 SizeMask         : Uint4B
			   +0x028 GetCpuClock      : Ptr64     int64						//修改此结构体的GetCpuClock成员内保存的函数地址，即address hook完成hook
			   +0x030 LoggerThread     : Ptr64 _ETHREAD
			   +0x038 LoggerStatus     : Int4B
			   +0x03c FailureReason    : Uint4B
			   +0x040 BufferQueue      : _ETW_BUFFER_QUEUE
			   +0x050 OverflowQueue    : _ETW_BUFFER_QUEUE
			   +0x060 GlobalList       : _LIST_ENTRY
			   +0x070 DebugIdTrackingList : _LIST_ENTRY
			   +0x080 DecodeControlList : Ptr64 _ETW_DECODE_CONTROL_ENTRY
			   +0x088 DecodeControlCount : Uint4B
			   +0x090 BatchedBufferList : Ptr64 _WMI_BUFFER_HEADER
			   +0x090 CurrentBuffer    : _EX_FAST_REF
			   +0x098 LoggerName       : _UNICODE_STRING
			   +0x0a8 LogFileName      : _UNICODE_STRING
			   +0x0b8 LogFilePattern   : _UNICODE_STRING
			   +0x0c8 NewLogFileName   : _UNICODE_STRING
			   +0x0d8 ClockType        : Uint4B
			   +0x0dc LastFlushedBuffer : Uint4B
			   +0x0e0 FlushTimer       : Uint4B
			   +0x0e4 FlushThreshold   : Uint4B
			   +0x0e8 ByteOffset       : _LARGE_INTEGER
			   +0x0f0 MinimumBuffers   : Uint4B
			   +0x0f4 BuffersAvailable : Int4B
			   +0x0f8 NumberOfBuffers  : Int4B
			   +0x0fc MaximumBuffers   : Uint4B
			   +0x100 EventsLost       : Uint4B
			   +0x104 PeakBuffersCount : Int4B
			   +0x108 BuffersWritten   : Uint4B
			   +0x10c LogBuffersLost   : Uint4B
			   +0x110 RealTimeBuffersDelivered : Uint4B
			   +0x114 RealTimeBuffersLost : Uint4B
			   +0x118 SequencePtr      : Ptr64 Int4B
			   +0x120 LocalSequence    : Uint4B
			   +0x124 InstanceGuid     : _GUID
			   +0x134 MaximumFileSize  : Uint4B
			   +0x138 FileCounter      : Int4B
			   +0x13c PoolType         : _POOL_TYPE
			   +0x140 ReferenceTime    : _ETW_REF_CLOCK
			   +0x150 CollectionOn     : Int4B
			   +0x154 ProviderInfoSize : Uint4B
			   +0x158 Consumers        : _LIST_ENTRY
			   +0x168 NumConsumers     : Uint4B
			   +0x170 TransitionConsumer : Ptr64 _ETW_REALTIME_CONSUMER
			   +0x178 RealtimeLogfileHandle : Ptr64 Void
			   +0x180 RealtimeLogfileName : _UNICODE_STRING
			   +0x190 RealtimeWriteOffset : _LARGE_INTEGER
			   +0x198 RealtimeReadOffset : _LARGE_INTEGER
			   +0x1a0 RealtimeLogfileSize : _LARGE_INTEGER
			   +0x1a8 RealtimeLogfileUsage : Uint8B
			   +0x1b0 RealtimeMaximumFileSize : Uint8B
			   +0x1b8 RealtimeBuffersSaved : Uint4B
			   +0x1c0 RealtimeReferenceTime : _ETW_REF_CLOCK
			   +0x1d0 NewRTEventsLost  : _ETW_RT_EVENT_LOSS
			   +0x1d8 LoggerEvent      : _KEVENT
			   +0x1f0 FlushEvent       : _KEVENT
			   +0x208 FlushTimeOutTimer : _KTIMER
			   +0x248 LoggerDpc        : _KDPC
			   +0x288 LoggerMutex      : _KMUTANT
			   +0x2c0 LoggerLock       : _EX_PUSH_LOCK
			   +0x2c8 BufferListSpinLock : Uint8B
			   +0x2c8 BufferListPushLock : _EX_PUSH_LOCK
			   +0x2d0 ClientSecurityContext : _SECURITY_CLIENT_CONTEXT
			   +0x318 TokenAccessInformation : Ptr64 _TOKEN_ACCESS_INFORMATION
			   +0x320 SecurityDescriptor : _EX_FAST_REF
			   +0x328 StartTime        : _LARGE_INTEGER
			   +0x330 LogFileHandle    : Ptr64 Void
			   +0x338 BufferSequenceNumber : Int8B
			   +0x340 Flags            : Uint4B
			   +0x340 Persistent       : Pos 0, 1 Bit
			   +0x340 AutoLogger       : Pos 1, 1 Bit
			   +0x340 FsReady          : Pos 2, 1 Bit
			   +0x340 RealTime         : Pos 3, 1 Bit
			   +0x340 Wow              : Pos 4, 1 Bit
			   +0x340 KernelTrace      : Pos 5, 1 Bit
			   +0x340 NoMoreEnable     : Pos 6, 1 Bit
			   +0x340 StackTracing     : Pos 7, 1 Bit
			   +0x340 ErrorLogged      : Pos 8, 1 Bit
			   +0x340 RealtimeLoggerContextFreed : Pos 9, 1 Bit
			   +0x340 PebsTracing      : Pos 10, 1 Bit
			   +0x340 PmcCounters      : Pos 11, 1 Bit
			   +0x340 PageAlignBuffers : Pos 12, 1 Bit
			   +0x340 StackLookasideListAllocated : Pos 13, 1 Bit
			   +0x340 SecurityTrace    : Pos 14, 1 Bit
			   +0x340 LastBranchTracing : Pos 15, 1 Bit
			   +0x340 SystemLoggerIndex : Pos 16, 8 Bits
			   +0x340 StackCaching     : Pos 24, 1 Bit
			   +0x340 ProviderTracking : Pos 25, 1 Bit
			   +0x340 ProcessorTrace   : Pos 26, 1 Bit
			   +0x340 QpcDeltaTracking : Pos 27, 1 Bit
			   +0x340 MarkerBufferSaved : Pos 28, 1 Bit
			   +0x340 SpareFlags2      : Pos 29, 3 Bits
			   +0x344 RequestFlag      : Uint4B
			   +0x344 DbgRequestNewFile : Pos 0, 1 Bit
			   +0x344 DbgRequestUpdateFile : Pos 1, 1 Bit
			   +0x344 DbgRequestFlush  : Pos 2, 1 Bit
			   +0x344 DbgRequestDisableRealtime : Pos 3, 1 Bit
			   +0x344 DbgRequestDisconnectConsumer : Pos 4, 1 Bit
			   +0x344 DbgRequestConnectConsumer : Pos 5, 1 Bit
			   +0x344 DbgRequestNotifyConsumer : Pos 6, 1 Bit
			   +0x344 DbgRequestUpdateHeader : Pos 7, 1 Bit
			   +0x344 DbgRequestDeferredFlush : Pos 8, 1 Bit
			   +0x344 DbgRequestDeferredFlushTimer : Pos 9, 1 Bit
			   +0x344 DbgRequestFlushTimer : Pos 10, 1 Bit
			   +0x344 DbgRequestUpdateDebugger : Pos 11, 1 Bit
			   +0x344 DbgSpareRequestFlags : Pos 12, 20 Bits
			   +0x350 StackTraceBlock  : _ETW_STACK_TRACE_BLOCK
			   +0x3d0 HookIdMap        : _RTL_BITMAP
			   +0x3e0 StackCache       : Ptr64 _ETW_STACK_CACHE
			   +0x3e8 PmcData          : Ptr64 _ETW_PMC_SUPPORT
			   +0x3f0 LbrData          : Ptr64 _ETW_LBR_SUPPORT
			   +0x3f8 IptData          : Ptr64 _ETW_IPT_SUPPORT
			   +0x400 BinaryTrackingList : _LIST_ENTRY
			   +0x410 ScratchArray     : Ptr64 Ptr64 _WMI_BUFFER_HEADER
			   +0x418 DisallowedGuids  : _DISALLOWED_GUIDS
			   +0x428 RelativeTimerDueTime : Int8B
			   +0x430 PeriodicCaptureStateGuids : _PERIODIC_CAPTURE_STATE_GUIDS
			   +0x440 PeriodicCaptureStateTimer : Ptr64 _EX_TIMER
			   +0x448 PeriodicCaptureStateTimerState : _ETW_PERIODIC_TIMER_STATE
			   +0x450 SoftRestartContext : Ptr64 _ETW_SOFT_RESTART_CONTEXT
			   +0x458 SiloState        : Ptr64 _ETW_SILODRIVERSTATE
			   +0x460 CompressionWorkItem : _WORK_QUEUE_ITEM
			   +0x480 CompressionWorkItemState : Int4B
			   +0x488 CompressionLock  : _EX_PUSH_LOCK
			   +0x490 CompressionTarget : Ptr64 _WMI_BUFFER_HEADER
			   +0x498 CompressionWorkspace : Ptr64 Void
			   +0x4a0 CompressionOn    : Int4B
			   +0x4a4 CompressionRatioGuess : Uint4B
			   +0x4a8 PartialBufferCompressionLevel : Uint4B
			   +0x4ac CompressionResumptionMode : ETW_COMPRESSION_RESUMPTION_MODE
			   +0x4b0 PlaceholderList  : _SINGLE_LIST_ENTRY
			   +0x4b8 CompressionDpc   : _KDPC
			   +0x4f8 LastBufferSwitchTime : _LARGE_INTEGER
			   +0x500 BufferWriteDuration : _LARGE_INTEGER
			   +0x508 BufferCompressDuration : _LARGE_INTEGER
			   +0x510 ReferenceQpcDelta : Int8B
			   +0x518 CallbackContext  : Ptr64 _ETW_EVENT_CALLBACK_CONTEXT
			   +0x520 LastDroppedTime  : Ptr64 _LARGE_INTEGER
			   +0x528 FlushingLastDroppedTime : Ptr64 _LARGE_INTEGER
			   +0x530 FlushingSequenceNumber : Int8B
	*/

	//
	// We care about overwriting the GetCpuClock (+0x28) pointer in 
	// this structure.
	//
	// 替换WMI_LOGGER_CONTEXT结构体的GetCpuClock (+0x28)成员保存的函数指针为detour函数的地址
	//
	PVOID* AddressOfEtwpGetCycleCount = (PVOID*)((uintptr_t)CkclWmiLoggerContext + OFFSET_WMI_LOGGER_CONTEXT_CPU_CYCLE_CLOCK);

	//
	// Replace this function pointer with our own. Each time syscall
	// is logged by ETW, it will invoke our new timing function.
	//
	*AddressOfEtwpGetCycleCount = IfhpInternalGetCpuClock;

	IfhpInitialized = TRUE;

	return STATUS_SUCCESS;
}

/*
*	Disables and then re-enables the circular kernel context logger,
*	clearing the system of the infinity hook pointer override.
*/
void IfhRelease()
{
	if (TRUE != IfhpInitialized)
	{
		return;
	}

	if (NT_SUCCESS(IfhpModifyTraceSettings(CKCL_TRACE_END)))
	{
		IfhpModifyTraceSettings(CKCL_TRACE_START);
	}

	IfhpInitialized = FALSE;
}

/*
*	Resolves necessary unexported symbols.
*/
static BOOLEAN IfhpResolveSymbols()
{
	//
	// We need to resolve nt!EtwpDebuggerData to get the current ETW
	// sessions WMI_LOGGER_CONTEXTS, find the CKCL, and overwrite its
	// GetCpuClock function pointer.
	//
	// 需要定位nt!EtwpDebuggerData的地址，以便获取当前ETW会话WMI_LOGGER，
	// 找到CKCL，并覆盖该结构体中GetCpuClock成员保存的函数指针。
	//
	PVOID NtBaseAddress = NULL;
	ULONG SizeOfNt = 0;
	NtBaseAddress = ImgGetBaseAddress(NULL, &SizeOfNt);
	if (!NtBaseAddress)
	{
		return FALSE;
	}

	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, ".data", &SizeOfSection);
	if (!SectionBase)
	{
		return FALSE;
	}

	//
	// Look for the EtwpDebuggerData global using the signature. This 
	// should be the same for Windows 7+.
	//
	// 使用特征码搜索方式来间接获得EtwpDebuggerData的地址
	//
	EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
	if (!EtwpDebuggerData)
	{
		//
		// Check inside of .rdata too... this is true for Windows 7.
		// Thanks to @ivanpos2015 for reporting.
		//
		SectionBase = ImgGetImageSection(NtBaseAddress, ".rdata", &SizeOfSection);
		if (!SectionBase)
		{
			return FALSE;
		}

		EtwpDebuggerData = MmSearchMemory(SectionBase, SizeOfSection, EtwpDebuggerDataPattern, RTL_NUMBER_OF(EtwpDebuggerDataPattern));
		if (!EtwpDebuggerData)
		{
			return FALSE;
		}
	}

	// 
	// This is offset by 2 bytes due to where the signature starts.
	//
	EtwpDebuggerData = (PVOID)((uintptr_t)EtwpDebuggerData - 2);

	//windbg查看结果：
	//3: kd > dq nt!EtwpDebuggerData
	//	fffff807`3a20e808  f80c3804`082c0220 60040c98`107000d8
	//	fffff807`3a20e818  ffffc707`401bbb40 ffffc707`401b8000	//偏移为+10h字节处是一个二级指针
	//	fffff807`3a20e828  00000000`00000000 00000001`00000000
	//	fffff807`3a20e838  00000000`0000e0bb 00000006`0000000f
	//	fffff807`3a20e848  000000ec`000001ce 00000000`00000100
	//	fffff807`3a20e858  00000000`00000000 0000024a`000001f1
	//	fffff807`3a20e868  00000021`0000001e 00000011`00000000
	//	fffff807`3a20e878  00000000`00000001 00000000`00000000
	//	3: kd > dq ffffc707`401bbb40
	//	ffffc707`401bbb40  00000000`00000001 00000000`00000001
	//	ffffc707`401bbb50  ffffc707`45754080 ffffc707`400c79c0	//数组偏移为2的地方保存了_WMI_LOGGER_CONTEXT结构体的地址
	//	ffffc707`401bbb60  ffffc707`401b9200 ffffc707`42bed3c0
	//	ffffc707`401bbb70  ffffc707`400d0600 ffffc707`400ce9c0
	//	ffffc707`401bbb80  ffffc707`401049c0 ffffc707`401069c0
	//	ffffc707`401bbb90  ffffc707`4010a040 ffffc707`4010c040
	//	ffffc707`401bbba0  ffffc707`4010c600 ffffc707`400bb9c0
	//	ffffc707`401bbbb0  ffffc707`400d49c0 ffffc707`422e0040
	//	3: kd > dt nt!_WMI_LOGGER_CONTEXT ffffc707`45754080
	//	+ 0x000 LoggerId         : 2
	//	+ 0x004 BufferSize : 0x1000
	//	+ 0x008 MaximumEventSize : 0xfb8
	//	+ 0x00c LoggerMode : 0x2800480
	//	+ 0x010 AcceptNewEvents : 0n0
	//	+ 0x014 EventMarker : [2] 0xc0130000
	//	+ 0x01c ErrorMarker : 0xc00d0000
	//	+ 0x020 SizeMask : 0xffff
	//	+ 0x028 GetCpuClock : 0xfffff806`1c291c00     int64  JcpDriver!IfhpInternalGetCpuClock + 0		<=替换的目标地址
	//	+ 0x030 LoggerThread     : (null)
	//	+ 0x038 LoggerStatus : 0n0
	//  ...


	//
	// 获得EtwpDebuggerData的储藏室里的值，这里查找8字节单位数组的下标为2的储藏室，即+10h
	//
	PVOID* EtwpDebuggerDataSilo = *(PVOID**)((uintptr_t)EtwpDebuggerData + OFFSET_ETW_DEBUGGER_DATA_SILO);

	//
	// Pull out the circular kernel context logger.
	//
	CkclWmiLoggerContext = EtwpDebuggerDataSilo[INDEX_CKCL_LOGGER];

	//
	// Grab the system call entry value.
	//
	SystemCallEntryPage = PAGE_ALIGN(ImgGetSyscallEntry());
	if (!SystemCallEntryPage)
	{
		return FALSE;
	}

	return TRUE;
}

/*
*	Modify the trace settings for the circular kernel context logger.
*/
static NTSTATUS IfhpModifyTraceSettings(
	_In_ CKCL_TRACE_OPERATION Operation)
{
	//申请一个物理页大小的内存，并且作为CKCL_TRACE_PROPERTIES结构体使用
	PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!Property)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(Property, 0, PAGE_SIZE);

	//初始化结构体的成员
	Property->Wnode.BufferSize = PAGE_SIZE;
	Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	RtlInitUnicodeString(&Property->ProviderName, L"Circular Kernel Context Logger");//注册使用的名字一定是这个
	Property->Wnode.Guid = CkclSessionGuid;//对结构体赋值
	Property->Wnode.ClientContext = 1;
	Property->BufferSize = sizeof(ULONG);
	Property->MinimumBuffers = Property->MaximumBuffers = 2;
	Property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;
	NTSTATUS Status = STATUS_ACCESS_DENIED;
	ULONG ReturnLength = 0;

	//
	// Might be wise to actually hook ZwTraceControl so folks don't 
	// disable your infinity hook ;).
	// 一般情况下，ntoskrnl.exe导出ZwTraceControl函数的，并且在lib文件中有导出符号，但是部分版本没有此函数，我们直接调用该函数
	switch (Operation)
	{
	case CKCL_TRACE_START://开启ckcl
	{
		//ZwTraceControl在用户层也有该函数的调用：http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/control/index.htm
		//	NTSTATUS NtTraceControl(
		//		ULONG FunctionCode,
		//		PVOID InBuffer,
		//		ULONG InBufferLen,
		//		PVOID OutBuffer,
		//		ULONG OutBufferLen,
		//		ULONG *ReturnSize
		//	);
		Status = ZwTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
		break;
	}
	case CKCL_TRACE_END:
	{
		Status = ZwTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
		break;
	}
	case CKCL_TRACE_SYSCALL://开启syscall
	{
		//
		// Add more flags here to trap on more events!
		//
		
		Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

		Status = ZwTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
		break;
	}
	}

	//释放缓冲区
	ExFreePool(Property);

	return Status;
}

/*
*	We replaced the GetCpuClock pointer to this one here which
*	implements stack walking logic. We use this to determine whether
*	a syscall occurred. It also provides you a way to alter the
*	address on the stack to redirect execution to your detoured
*	function.
*
*	call stack:
*		PerfInfoLogSysCallEntry
*		EtwTraceSiloKernelEvent
*		EtwpLogKernelEvent
*		EtwpReserveTraceBuffer
*		mov rax, [rdi+28h];call  _guard_dispatch_icall;
*	 -->IfhpInternalGetCpuClock
*	 -->call rax;调用服务函数
*/
static ULONG64 IfhpInternalGetCpuClock()
{

	//区分内核的systemcall还是用户层的zwxxx调用
	auto mode = ExGetPreviousMode();
	if (mode == KernelMode)
	{
		return __rdtsc();
	}

	//
	// Extract the system call index (if you so desire).
	//
	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(OFFSET_KPCR_CURRENT_THREAD);
	unsigned int SystemCallIndex = *(unsigned int*)((uintptr_t)CurrentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

	PVOID* StackMax = (PVOID*)__readgsqword(OFFSET_KPCR_RSP_BASE);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();

	//
	// First walk backwards on the stack to find the 2 magic values.
	//
	// StackFrame是大于StackMax的
	//
	for (PVOID* StackCurrent = StackMax;
		StackCurrent > StackFrame;
		--StackCurrent)
	{
		// 
		// This is intentionally being read as 4-byte magic on an 8
		// byte aligned boundary.
		//
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != INFINITYHOOK_MAGIC_1)
		{
			continue;
		}

		// 
		// If the first magic is set, check for the second magic.
		//
		--StackCurrent;

		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != INFINITYHOOK_MAGIC_2)
		{
			continue;
		}

		//
		// Now we reverse the direction of the stack walk.
		//
		for (;
			StackCurrent < StackMax;
			++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;

			if (!(PAGE_ALIGN(*AsUlonglong) >= SystemCallEntryPage &&
				PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)SystemCallEntryPage + (PAGE_SIZE * 2))))
			{
				continue;
			}

			//
			// If you want to "hook" this function, replace this stack memory 
			// with a pointer to your own function.
			//
			void** SystemCallFunction = &StackCurrent[9];

			if (IfhpCallback)
			{
				IfhpCallback(SystemCallIndex, SystemCallFunction);
			}

			break;
		}

		break;
	}

	return __rdtsc();
}