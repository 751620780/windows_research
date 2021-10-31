#pragma once
#ifndef WINDOWS_NT 
#define WINDOWS_NT
#ifndef X64_17763_253_H
#define X64_17763_253_H		//10.0.17763.253
#include "kernel_sr.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct _OBJECT_CREATE_INFORMATION_SR;
	struct _OBJECT_HEADER_SR;
	union _KEXECUTE_OPTIONS_SR;
	union _KSTACK_COUNT_SR;
	union _KIDTENTRY64_SR;
	union _KGDTENTRY64_SR;
	struct _KAFFINITY_EX_SR;
	struct _KPROCESS_SR;
	union _KWAIT_STATUS_REGISTER_SR;
	struct _RTL_UMS_CONTEXT_SR;
	struct _UMS_CONTROL_BLOCK_SR;
	struct _KDESCRIPTOR_SR;
	struct _KSPECIAL_REGISTERS_SR;
	struct _KPROCESSOR_STATE_SR;
	struct _PP_LOOKASIDE_LIST_SR;
	struct _KDPC_DATA_SR;
	struct _KTIMER_TABLE_ENTRY_SR;
	struct _KTIMER_TABLE_SR;
	struct _CACHED_KSTACK_LIST_SR;
	struct _flags_SR;
	struct _KNODE_SR;
	struct _KREQUEST_PACKET_SR;
	struct _REQUEST_MAILBOX_SR;
	struct _PROC_HISTORY_ENTRY_SR;
	struct _PROC_PERF_LOAD_SR;
	struct _PROC_PERF_CONSTRAINT_SR;
	struct _PROC_PERF_DOMAIN_SR;
	struct _PROC_IDLE_SNAP_SR;
	struct _PPM_FFH_THROTTLE_STATE_INFO_SR;
	struct _PROC_IDLE_STATE_BUCKET_SR;
	struct _PROC_IDLE_STATE_ACCOUNTING_SR;
	struct _PROC_IDLE_ACCOUNTING_SR;
	enum _PROC_HYPERVISOR_STATE_SR;
	struct _PROCESSOR_POWER_STATE_SR;
	struct _KPRCB_SR;
	struct _COUNTER_READING_SR;
	struct _THREAD_PERFORMANCE_DATA_SR;
	struct _KTHREAD_COUNTERS_SR;
	struct _TERMINATION_PORT_SR;
	union _PS_CLIENT_SECURITY_CONTEXT_SR;
	struct _MMADDRESS_NODE_SR;
	struct _PEB_LDR_DATA_SR;
	struct _RTL_DRIVE_LETTER_CURDIR_SR;
	struct _CURDIR_SR;
	struct _RTL_USER_PROCESS_PARAMETERS_SR;
	struct _RTL_CRITICAL_SECTION_DEBUG_SR;
	struct _RTL_CRITICAL_SECTION_SR;
	struct _MMWSLENTRY_SR;
	struct _MMWSLE_FREE_ENTRY_SR;
	struct _MMWSLE_SR;
	struct _MMWSLE_NONDIRECT_HASH_SR;
	struct _MMWSLE_HASH_SR;
	struct _MMWSL_SR;
	struct _MMSUPPORT_FLAGS_SR;
	struct _PS_PER_CPU_QUOTA_CACHE_AWARE_SR;
	union _PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA_SR;
	struct _PS_CPU_QUOTA_BLOCK_SR;
	struct _HANDLE_TRACE_DB_ENTRY_SR;
	struct _HANDLE_TRACE_DEBUG_INFO_SR;
	struct _HANDLE_TABLE_ENTRY_INFO_SR;
	struct _HANDLE_TABLE;
	struct _HANDLE_TABLE_ENTRY_SR;
	struct _EX_FAST_REF_SR;
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME_SR;
	struct _TEB_ACTIVE_FRAME_CONTEXT_SR;
	struct _TEB_ACTIVE_FRAME_SR;
	struct _GDI_TEB_BATCH_SR;
	struct _ACTIVATION_CONTEXT_STACK_SR;
	struct _TEB_SR;
	struct _TEB32_SR;
	struct _CLIENT_ID32_SR;
	struct _GDI_TEB_BATCH32_SR;
	struct _KTHREAD_SR;
	struct _ETHREAD;
	struct _MM_AVL_TABLE_SR;
	struct _EJOB_SR;
	struct _HARDWARE_PTE_SR;
	struct _PEB_SR;
	struct _SE_AUDIT_PROCESS_CREATION_INFO_SR;
	struct _MMSUPPORT_SR;
	struct _ALPC_PROCESS_CONTEXT_SR;
	struct _PO_DIAG_STACK_RECORD_SR;
	struct _EPROCESS_SR;
	struct _OBJECT_TYPE_INITIALIZER_SR;
	struct _OBJECT_TYPE_SR;
	struct _LDR_DATA_TABLE_ENTRY_SR;
	struct _DRIVER_OBJECT_SR;

	typedef struct _OBJECT_CREATE_INFORMATION                         // 9 elements, 0x40 bytes (sizeof) 
	{
		/*0x000*/     ULONG32      Attributes;
		/*0x004*/     UINT8        _PADDING0_[0x4];
		/*0x008*/     VOID*        RootDirectory;
		/*0x010*/     CHAR         ProbeMode;
		/*0x011*/     UINT8        _PADDING1_[0x3];
		/*0x014*/     ULONG32      PagedPoolCharge;
		/*0x018*/     ULONG32      NonPagedPoolCharge;
		/*0x01C*/     ULONG32      SecurityDescriptorCharge;
		/*0x020*/     VOID*        SecurityDescriptor;
		/*0x028*/     struct _SECURITY_QUALITY_OF_SERVICE* SecurityQos;
		/*0x030*/     struct _SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; // 4 elements, 0xC bytes (sizeof)  
		/*0x03C*/     UINT8        _PADDING2_[0x4];
	}OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;


	typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
	{
		union                                    // 3 elements, 0x8 bytes (sizeof) 
		{
			struct                               // 5 elements, 0x8 bytes (sizeof) 
			{
				/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
				/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
				/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
				/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
				/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
			};
			/*0x000*/         UINT64       Value;
			/*0x000*/         VOID*        Ptr;
		};
	}EX_PUSH_LOCK, *PEX_PUSH_LOCK;


	typedef struct _OBJECT_HEADER                                // 23 elements, 0x38 bytes (sizeof) 
	{
		/*0x000*/     INT64        PointerCount;
		union                                                    // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x008*/         INT64        HandleCount;
			/*0x008*/         VOID*        NextToFree;
		};
		/*0x010*/     struct _EX_PUSH_LOCK Lock;                               // 7 elements, 0x8 bytes (sizeof)   
		/*0x018*/     UINT8        TypeIndex;
		union                                                    // 2 elements, 0x1 bytes (sizeof)   
		{
			/*0x019*/         UINT8        TraceFlags;
			struct                                               // 2 elements, 0x1 bytes (sizeof)   
			{
				/*0x019*/             UINT8        DbgRefTrace : 1;                    // 0 BitPosition                    
				/*0x019*/             UINT8        DbgTracePermanent : 1;              // 1 BitPosition                    
			};
		};
		/*0x01A*/     UINT8        InfoMask;
		union                                                    // 2 elements, 0x1 bytes (sizeof)   
		{
			/*0x01B*/         UINT8        Flags;
			struct                                               // 8 elements, 0x1 bytes (sizeof)   
			{
				/*0x01B*/             UINT8        NewObject : 1;                      // 0 BitPosition                    
				/*0x01B*/             UINT8        KernelObject : 1;                   // 1 BitPosition                    
				/*0x01B*/             UINT8        KernelOnlyAccess : 1;               // 2 BitPosition                    
				/*0x01B*/             UINT8        ExclusiveObject : 1;                // 3 BitPosition                    
				/*0x01B*/             UINT8        PermanentObject : 1;                // 4 BitPosition                    
				/*0x01B*/             UINT8        DefaultSecurityQuota : 1;           // 5 BitPosition                    
				/*0x01B*/             UINT8        SingleHandleEntry : 1;              // 6 BitPosition                    
				/*0x01B*/             UINT8        DeletedInline : 1;                  // 7 BitPosition                    
			};
		};
		/*0x01C*/     ULONG32      Reserved;
		union                                                    // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x020*/         struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;
			/*0x020*/         VOID*        QuotaBlockCharged;
		};
		/*0x028*/     VOID*        SecurityDescriptor;
		/*0x030*/     struct _QUAD Body;                                       // 2 elements, 0x8 bytes (sizeof)   
	}OBJECT_HEADER, *POBJECT_HEADER;








































#ifdef __cplusplus
}
#endif

#endif
#endif
/*
debug port清零需要处理的地方共25处：
**FFFFF8073A61A3CB			DbgkpSetProcessDebugObject				4C 89 BE 20 04 00 00                                         mov     [rsi+420h], r15
**FFFFF8073A57CE2A			PspProcessDelete						4C 89 BF 20 04 00 00                                         mov     [rdi+420h], r15
**FFFFF8073A61A3B9			DbgkpSetProcessDebugObject				4C 39 A6 20 04 00 00                                         cmp     [rsi+420h], r12
**FFFFF8073A61A117			DbgkpQueueMessage						49 8B B5 20 04 00 00                                         mov     rsi, [r13+420h]
**FFFFF8073A3D5A72			PspExitThread							49 39 B6 20 04 00 00                                         cmp     [r14+420h], rsi
**FFFFF8073A4169AF			DbgkCopyProcessDebugPort				48 8B 9A 20 04 00 00                                         mov     rbx, [rdx+420h]
**FFFFF8073A61902D			DbgkOpenProcessDebugPort				48 8B 9E 20 04 00 00                                         mov     rbx, [rsi+420h]
**FFFFF8073A4D0459			DbgkClearProcessDebugObject				48 8B 9E 20 04 00 00                                         mov     rbx, [rsi+420h]
**FFFFF8073A4C5A7E			DbgkForwardException					48 8B 9E 20 04 00 00                                         mov     rbx, [rsi+420h]
**FFFFF8073A5A1810			DbgkCopyProcessDebugPort				48 8B 9F 20 04 00 00                                         mov     rbx, [rdi+420h]
**FFFFF8073A61946B			DbgkpCloseObject						48 39 AF 20 04 00 00                                         cmp     [rdi+420h], rbp
**FFFFF8073A416992			DbgkCopyProcessDebugPort				48 83 A1 20 04 00 00 00                                      and     qword ptr [rcx+420h], 0
**FFFFF8073A619474			DbgkpCloseObject						48 83 A7 20 04 00 00 00                                      and     qword ptr [rdi+420h], 0
**FFFFF8073A61C180			DbgkExitThread							48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
**FFFFF8073A61C0D8			DbgkExitProcess							48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
**FFFFF8073A3F6509			NtQueryInformationProcess				48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
**FFFFF8073A3C1687			DbgkUnMapViewOfSection					48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
**FFFFF80739E7C6A1			KiDispatchException						48 83 BA 20 04 00 00 00                                      cmp     qword ptr [rdx+420h], 0
**FFFFF8073A3FB611			DbgkMapViewOfSection					48 83 BF 20 04 00 00 00                                      cmp     qword ptr [rdi+420h], 0
**FFFFF8073A3FA740			PspTerminateAllThreads					48 83 BF 20 04 00 00 00                                      cmp     qword ptr [rdi+420h], 0
**FFFFF8073A5A1900			DbgkCopyProcessDebugPort				48 89 9E 20 04 00 00                                         mov     [rsi+420h], rbx
**FFFFF8073A61A3F4			DbgkpSetProcessDebugObject				4C 89 A6 20 04 00 00                                         mov     [rsi+420h], r12
**FFFFF8073A5C11B2			DbgkClearProcessDebugObject				48 83 A6 20 04 00 00 00
**FFFFF8073A61A490			DbgkpSetProcessDebugObject				4C 89 A6 20 04 00 00
**FFFFF8073A3D2D7A			DbgkCreateThread						48 83 BF 20 04 00 00 00

以下调试端口在debugprot移位时不需要移位
反调试：FFFFF8073A61972A		DbgkpMarkProcessPeb						48 83 BB 20 04 00 00 00                                      cmp     qword ptr [rbx+420h], 0
反调试：FFFFF8073A5DDD1D		ObCloseHandleTableEntry					48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
反调试：FFFFF8073A619005		DbgkOpenProcessDebugPort				48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
反调试：FFFFF8073A58FFC5		ObpCloseHandle							4C 39 AE 20 04 00 00                                         cmp     [rsi+420h], r13
反调试：FFFFF8073A4B0EAB		NtClose									49 83 BD 20 04 00 00 00                                      cmp     qword ptr [r13+420h], 0
疑开机：FFFFF8073A5443F5		DbgkCreateMinimalProcess				48 83 B9 20 04 00 00 00                                      cmp     qword ptr [rcx+420h], 0
疑开机：FFFFF8073A61C025		DbgkCreateMinimalThread					48 83 BF 20 04 00 00 00                                      cmp     qword ptr [rdi+420h], 0
*/