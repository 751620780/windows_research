#pragma once

#ifndef WINDOWS_NT 
#define WINDOWS_NT
#ifndef X64_7601_H
#define X64_7601_H

//attention:those struct is only used for windows 7 version 6.1.7601.17514

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



typedef struct _OBJECT_CREATE_INFORMATION_SR                         // 9 elements, 0x40 bytes (sizeof) 
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
	/*0x028*/     SECURITY_QUALITY_OF_SERVICE* SecurityQos;
	/*0x030*/     SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; // 4 elements, 0xC bytes (sizeof)  
	/*0x03C*/     UINT8        _PADDING2_[0x4];
}OBJECT_CREATE_INFORMATION_SR, *POBJECT_CREATE_INFORMATION_SR;

typedef struct _OBJECT_HEADER_SR                               // 12 elements, 0x38 bytes (sizeof) 最后8个字节已是内核对象 
{
	/*0x000*/     INT64        PointerCount;		//内核对象的引用计数
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x008*/         INT64        HandleCount;	//内核对象句柄数
		/*0x008*/         VOID*        NextToFree;
	};
	/*0x010*/     EX_PUSH_LOCK Lock;                               // 7 elements, 0x8 bytes (sizeof)   
	/*0x018*/     UINT8        TypeIndex;		//内核对象类型的编号
	/*0x019*/     UINT8        TraceFlags;
	/*0x01A*/     UINT8        InfoMask;
	/*0x01B*/     UINT8        Flags;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x020*/         OBJECT_CREATE_INFORMATION_SR* ObjectCreateInfo;
		/*0x020*/         VOID*        QuotaBlockCharged;
	};
	/*0x028*/     VOID*        SecurityDescriptor;
	/*0x030*/   QUAD Body;                                       // 2 elements, 0x8 bytes (sizeof)   
}OBJECT_HEADER, *POBJECT_HEADER;

typedef union _KEXECUTE_OPTIONS_SR                           // 9 elements, 0x1 bytes (sizeof) 
{
	struct                                                // 8 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                  
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                  
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                  
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                  
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                  
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                  
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                  
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                  
	};
	/*0x000*/     UINT8        ExecuteOptions;
}KEXECUTE_OPTIONS_SR, *PKEXECUTE_OPTIONS_SR;

typedef union _KSTACK_COUNT_SR           // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     LONG32       Value;
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};
}KSTACK_COUNT_SR, *PKSTACK_COUNT_SR;

typedef union _KIDTENTRY64_SR																	// 11 elements, 0x10 bytes (sizeof) 中断描述符表中中断描述符项的数据结构
{
	struct																						// 6 elements, 0x10 bytes (sizeof)  
	{
		/*0x000*/         UINT16       OffsetLow;												//中断服务函数地址的低16位(第1-16位)
		/*0x002*/         UINT16       Selector;
		struct																					// 5 elements, 0x2 bytes (sizeof)   
		{
			/*0x004*/             UINT16       IstIndex : 3;									// 0 BitPosition                    
			/*0x004*/             UINT16       Reserved0 : 5;									// 3 BitPosition                    
			/*0x004*/             UINT16       Type : 5;										// 8 BitPosition                    
			/*0x004*/             UINT16       Dpl : 2;											// 13 BitPosition                   
			/*0x004*/             UINT16       Present : 1;										// 15 BitPosition                   
		};
		/*0x006*/         UINT16       OffsetMiddle;											//中断服务函数地址的第17-32位
		/*0x008*/         ULONG32      OffsetHigh;												//终端服务函数地址的高4直接（第33-64位）
		/*0x00C*/         ULONG32      Reserved1;												//此4字节没用，恒为0
	};
	/*0x000*/     UINT64       Alignment;														//中断描述符项的前8个字节，此数据没什么解释用途
}KIDTENTRY64_SR, *PKIDTENTRY64_SR;

typedef union _KGDTENTRY64_SR																	// 7 elements, 0x10 bytes (sizeof) 全局描述符表项的数据结构
{
	struct																						// 5 elements, 0x10 bytes (sizeof) 
	{
		/*0x000*/         UINT16       LimitLow;
		/*0x002*/         UINT16       BaseLow;													//基址的低16位 第1 - 16位 bit 0 - 15
		union																					// 2 elements, 0x4 bytes (sizeof)  
		{
			struct																				// 4 elements, 0x4 bytes (sizeof)  
			{
				/*0x004*/                 UINT8        BaseMiddle;								//基址的中间8bit  第17 - 24位 bit 16 - 23
				/*0x005*/                 UINT8        Flags1;
				/*0x006*/                 UINT8        Flags2;
				/*0x007*/                 UINT8        BaseHigh;								//基址的高8bit  第25-32位 bit 24-31
			}Bytes;
			struct																				// 10 elements, 0x4 bytes (sizeof) 
			{
				/*0x004*/                 ULONG32      BaseMiddle : 8;							// 0 BitPosition   基址的中间8bit  第17-24位 bit 16-23              
				/*0x004*/                 ULONG32      Type : 5;								// 8 BitPosition   type域                
				/*0x004*/                 ULONG32      Dpl : 2;									// 13 BitPosition  DPL                
				/*0x004*/                 ULONG32      Present : 1;								// 15 BitPosition  P位                
				/*0x004*/                 ULONG32      LimitHigh : 4;							// 16 BitPosition  seg.limit              
				/*0x004*/                 ULONG32      System : 1;								// 20 BitPosition  AVL                
				/*0x004*/                 ULONG32      LongMode : 1;							// 21 BitPosition  L位                
				/*0x004*/                 ULONG32      DefaultBig : 1;							// 22 BitPosition  D/B             
				/*0x004*/                 ULONG32      Granularity : 1;							// 23 BitPosition  G位                 
				/*0x004*/                 ULONG32      BaseHigh : 8;							// 24 BitPosition  基址的高8bit  第25-32位 bit 24-31                
			}Bits;
		};
		/*0x008*/         ULONG32      BaseUpper;
		/*0x00C*/         ULONG32      MustBeZero;
	};
	/*0x000*/     UINT64       Alignment;
}KGDTENTRY64_SR, *PKGDTENTRY64_SR;

typedef struct _KAFFINITY_EX_SR // 4 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     UINT16       Count;
	/*0x002*/     UINT16       Size;
	/*0x004*/     ULONG32      Reserved;
	/*0x008*/     UINT64       Bitmap[4];
}KAFFINITY_EX_SR, *PKAFFINITY_EX_SR;

typedef struct _KPROCESS_SR                       // 37 elements, 0x160 bytes (sizeof) 
{
	/*0x000*/     DISPATCHER_HEADER Header;          // 29 elements, 0x18 bytes (sizeof)  
	/*0x018*/     LIST_ENTRY ProfileListHead;        // 2 elements, 0x10 bytes (sizeof)   
	/*0x028*/     UINT64       DirectoryTableBase;
	/*0x030*/     LIST_ENTRY ThreadListHead;         // 2 elements, 0x10 bytes (sizeof)   
	/*0x040*/     UINT64       ProcessLock;
	/*0x048*/     KAFFINITY_EX_SR Affinity;             // 4 elements, 0x28 bytes (sizeof)   
	/*0x070*/     LIST_ENTRY ReadyListHead;          // 2 elements, 0x10 bytes (sizeof)   
	/*0x080*/     SINGLE_LIST_ENTRY SwapListEntry;   // 1 elements, 0x8 bytes (sizeof)    
	/*0x088*/     KAFFINITY_EX_SR ActiveProcessors;     // 4 elements, 0x28 bytes (sizeof)   
	union                                      // 2 elements, 0x4 bytes (sizeof)    
	{
		struct                                 // 5 elements, 0x4 bytes (sizeof)    
		{
			/*0x0B0*/             LONG32       AutoAlignment : 1;    // 0 BitPosition                     
			/*0x0B0*/             LONG32       DisableBoost : 1;     // 1 BitPosition                     
			/*0x0B0*/             LONG32       DisableQuantum : 1;   // 2 BitPosition                     
			/*0x0B0*/             ULONG32      ActiveGroupsMask : 4; // 3 BitPosition                     
			/*0x0B0*/             LONG32       ReservedFlags : 25;   // 7 BitPosition                     
		};
		/*0x0B0*/         LONG32       ProcessFlags;
	};
	/*0x0B4*/     CHAR         BasePriority;
	/*0x0B5*/     CHAR         QuantumReset;
	/*0x0B6*/     UINT8        Visited;
	/*0x0B7*/     UINT8        Unused3;
	/*0x0B8*/     ULONG32      ThreadSeed[4];
	/*0x0C8*/     UINT16       IdealNode[4];
	/*0x0D0*/     UINT16       IdealGlobalNode;
	/*0x0D2*/     KEXECUTE_OPTIONS_SR Flags;             // 9 elements, 0x1 bytes (sizeof)    
	/*0x0D3*/     UINT8        Unused1;
	/*0x0D4*/     ULONG32      Unused2;
	/*0x0D8*/     ULONG32      Unused4;
	/*0x0DC*/     KSTACK_COUNT_SR StackCount;            // 3 elements, 0x4 bytes (sizeof)    
	/*0x0E0*/     LIST_ENTRY ProcessListEntry;       // 2 elements, 0x10 bytes (sizeof)   
	/*0x0F0*/     UINT64       CycleTime;
	/*0x0F8*/     ULONG32      KernelTime;
	/*0x0FC*/     ULONG32      UserTime;
	/*0x100*/     VOID*        InstrumentationCallback;
	/*0x108*/     KGDTENTRY64_SR LdtSystemDescriptor;    // 7 elements, 0x10 bytes (sizeof)   
	/*0x118*/     VOID*        LdtBaseAddress;
	/*0x120*/     KGUARDED_MUTEX LdtProcessLock;     // 7 elements, 0x38 bytes (sizeof)   
	/*0x158*/     UINT16       LdtFreeSelectorHint;
	/*0x15A*/     UINT16       LdtTableLength;
	/*0x15C*/     UINT8        _PADDING0_[0x4];
}KPROCESS_SR, *PKPROCESS_SR;

typedef union _KWAIT_STATUS_REGISTER_SR // 8 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        Flags;
	struct                           // 7 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        State : 2;      // 0 BitPosition                  
		/*0x000*/         UINT8        Affinity : 1;   // 2 BitPosition                  
		/*0x000*/         UINT8        Priority : 1;   // 3 BitPosition                  
		/*0x000*/         UINT8        Apc : 1;        // 4 BitPosition                  
		/*0x000*/         UINT8        UserApc : 1;    // 5 BitPosition                  
		/*0x000*/         UINT8        Alert : 1;      // 6 BitPosition                  
		/*0x000*/         UINT8        Unused : 1;     // 7 BitPosition                  
	};
}KWAIT_STATUS_REGISTER_SR, *PKWAIT_STATUS_REGISTER_SR;

typedef struct _RTL_UMS_CONTEXT_SR                       // 28 elements, 0x540 bytes (sizeof) 
{
	/*0x000*/     SINGLE_LIST_ENTRY Link;                   // 1 elements, 0x8 bytes (sizeof)    
	/*0x008*/     UINT8        _PADDING0_[0x8];
	/*0x010*/     CONTEXT Context;                          // 64 elements, 0x4D0 bytes (sizeof) 
	/*0x4E0*/     VOID*        Teb;
	/*0x4E8*/     VOID*        UserContext;
	union                                             // 2 elements, 0x8 bytes (sizeof)    
	{
		struct                                        // 11 elements, 0x4 bytes (sizeof)   
		{
			/*0x4F0*/             ULONG32      ScheduledThread : 1;         // 0 BitPosition                     
			/*0x4F0*/             ULONG32      HasQuantumReq : 1;           // 1 BitPosition                     
			/*0x4F0*/             ULONG32      HasAffinityReq : 1;          // 2 BitPosition                     
			/*0x4F0*/             ULONG32      HasPriorityReq : 1;          // 3 BitPosition                     
			/*0x4F0*/             ULONG32      Suspended : 1;               // 4 BitPosition                     
			/*0x4F0*/             ULONG32      VolatileContext : 1;         // 5 BitPosition                     
			/*0x4F0*/             ULONG32      Terminated : 1;              // 6 BitPosition                     
			/*0x4F0*/             ULONG32      DebugActive : 1;             // 7 BitPosition                     
			/*0x4F0*/             ULONG32      RunningOnSelfThread : 1;     // 8 BitPosition                     
			/*0x4F0*/             ULONG32      DenyRunningOnSelfThread : 1; // 9 BitPosition                     
			/*0x4F0*/             ULONG32      ReservedFlags : 22;          // 10 BitPosition                    
		};
		/*0x4F0*/         LONG32       Flags;
	};
	union                                             // 2 elements, 0x8 bytes (sizeof)    
	{
		struct                                        // 3 elements, 0x8 bytes (sizeof)    
		{
			/*0x4F8*/             UINT64       KernelUpdateLock : 1;        // 0 BitPosition                     
			/*0x4F8*/             UINT64       Reserved : 1;                // 1 BitPosition                     
			/*0x4F8*/             UINT64       PrimaryClientID : 62;        // 2 BitPosition                     
		};
		/*0x4F8*/         UINT64       ContextLock;
	};
	/*0x500*/     UINT64       QuantumValue;
	/*0x508*/     GROUP_AFFINITY AffinityMask;              // 3 elements, 0x10 bytes (sizeof)   
	/*0x518*/     LONG32       Priority;
	/*0x51C*/     UINT8        _PADDING1_[0x4];
	/*0x520*/     struct _RTL_UMS_CONTEXT_SR* PrimaryUmsContext;
	/*0x528*/     ULONG32      SwitchCount;
	/*0x52C*/     ULONG32      KernelYieldCount;
	/*0x530*/     ULONG32      MixedYieldCount;
	/*0x534*/     ULONG32      YieldCount;
	/*0x538*/     UINT8        _PADDING2_[0x8];
}RTL_UMS_CONTEXT_SR, *PRTL_UMS_CONTEXT_SR;

typedef struct _UMS_CONTROL_BLOCK_SR                                // 23 elements, 0x98 bytes (sizeof) 
{
	/*0x000*/     RTL_UMS_CONTEXT_SR* UmsContext;
	/*0x008*/     SINGLE_LIST_ENTRY* CompletionListEntry;
	/*0x010*/     KEVENT* CompletionListEvent;
	/*0x018*/     ULONG32      ServiceSequenceNumber;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	union                                                        // 2 elements, 0x6C bytes (sizeof)  
	{
		struct                                                   // 6 elements, 0x6C bytes (sizeof)  
		{
			/*0x020*/             KQUEUE UmsQueue;                             // 5 elements, 0x40 bytes (sizeof)  
			/*0x060*/             LIST_ENTRY QueueEntry;                       // 2 elements, 0x10 bytes (sizeof)  
			/*0x070*/             RTL_UMS_CONTEXT_SR* YieldingUmsContext;
			/*0x078*/             VOID*        YieldingParam;
			/*0x080*/             VOID*        UmsTeb;
			union                                                // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x088*/                 ULONG32      PrimaryFlags;
				/*0x088*/                 ULONG32      UmsContextHeaderReady : 1;          // 0 BitPosition                    
			};
		};
		struct                                                   // 6 elements, 0x6C bytes (sizeof)  
		{
			/*0x020*/             KQUEUE* UmsAssociatedQueue;
			/*0x028*/             LIST_ENTRY* UmsQueueListEntry;
			/*0x030*/             KUMS_CONTEXT_HEADER* UmsContextHeader;
			/*0x038*/             KGATE UmsWaitGate;                           // 1 elements, 0x18 bytes (sizeof)  
			/*0x050*/             VOID*        StagingArea;
			union                                                // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x058*/                 LONG32       Flags;
				struct                                           // 5 elements, 0x4 bytes (sizeof)   
				{
					/*0x058*/                     ULONG32      UmsForceQueueTermination : 1;   // 0 BitPosition                    
					/*0x058*/                     ULONG32      UmsAssociatedQueueUsed : 1;     // 1 BitPosition                    
					/*0x058*/                     ULONG32      UmsThreadParked : 1;            // 2 BitPosition                    
					/*0x058*/                     ULONG32      UmsPrimaryDeliveredContext : 1; // 3 BitPosition                    
					/*0x058*/                     ULONG32      UmsPerformingSingleStep : 1;    // 4 BitPosition                    
				};
			};
		};
	};
	/*0x090*/     UINT16       TebSelector;
	/*0x092*/     UINT8        _PADDING1_[0x6];
}UMS_CONTROL_BLOCK_SR, *PUMS_CONTROL_BLOCK_SR;

typedef struct _KDESCRIPTOR_SR // 3 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     UINT16       Pad[3];
	/*0x006*/     UINT16       Limit;
	/*0x008*/     VOID*        Base;
}KDESCRIPTOR_SR, *PKDESCRIPTOR_SR;

typedef struct _KSPECIAL_REGISTERS_SR     // 27 elements, 0xD8 bytes (sizeof) 
{
	/*0x000*/     UINT64       Cr0;
	/*0x008*/     UINT64       Cr2;
	/*0x010*/     UINT64       Cr3;
	/*0x018*/     UINT64       Cr4;
	/*0x020*/     UINT64       KernelDr0;
	/*0x028*/     UINT64       KernelDr1;
	/*0x030*/     UINT64       KernelDr2;
	/*0x038*/     UINT64       KernelDr3;
	/*0x040*/     UINT64       KernelDr6;
	/*0x048*/     UINT64       KernelDr7;
	/*0x050*/     KDESCRIPTOR_SR Gdtr;          // 3 elements, 0x10 bytes (sizeof)  
	/*0x060*/     KDESCRIPTOR_SR Idtr;          // 3 elements, 0x10 bytes (sizeof)  
	/*0x070*/     UINT16       Tr;
	/*0x072*/     UINT16       Ldtr;
	/*0x074*/     ULONG32      MxCsr;
	/*0x078*/     UINT64       DebugControl;
	/*0x080*/     UINT64       LastBranchToRip;
	/*0x088*/     UINT64       LastBranchFromRip;
	/*0x090*/     UINT64       LastExceptionToRip;
	/*0x098*/     UINT64       LastExceptionFromRip;
	/*0x0A0*/     UINT64       Cr8;
	/*0x0A8*/     UINT64       MsrGsBase;
	/*0x0B0*/     UINT64       MsrGsSwap;
	/*0x0B8*/     UINT64       MsrStar;
	/*0x0C0*/     UINT64       MsrLStar;
	/*0x0C8*/     UINT64       MsrCStar;
	/*0x0D0*/     UINT64       MsrSyscallMask;
}KSPECIAL_REGISTERS_SR, *PKSPECIAL_REGISTERS_SR;

typedef struct _KPROCESSOR_STATE_SR                 // 2 elements, 0x5B0 bytes (sizeof)  
{
	/*0x000*/     KSPECIAL_REGISTERS_SR SpecialRegisters; // 27 elements, 0xD8 bytes (sizeof)  
	/*0x0D8*/     UINT8        _PADDING0_[0x8];
	/*0x0E0*/     CONTEXT ContextFrame;                // 64 elements, 0x4D0 bytes (sizeof) 
}KPROCESSOR_STATE_SR, *PKPROCESSOR_STATE_SR;

typedef struct _PP_LOOKASIDE_LIST_SR // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     GENERAL_LOOKASIDE* P;
	/*0x008*/     GENERAL_LOOKASIDE* L;
}PP_LOOKASIDE_LIST_SR, *PPP_LOOKASIDE_LIST_SR;

typedef struct _KDPC_DATA_SR           // 4 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     LIST_ENTRY DpcListHead; // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     UINT64       DpcLock;
	/*0x018*/     LONG32       DpcQueueDepth;
	/*0x01C*/     ULONG32      DpcCount;
}KDPC_DATA_SR, *PKDPC_DATA_SR;

typedef struct _KTIMER_TABLE_ENTRY_SR // 3 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     UINT64       Lock;
	/*0x008*/     LIST_ENTRY Entry;      // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     ULARGE_INTEGER Time;    // 4 elements, 0x8 bytes (sizeof)  
}KTIMER_TABLE_ENTRY_SR, *PKTIMER_TABLE_ENTRY_SR;

typedef struct _KTIMER_TABLE_SR                      // 2 elements, 0x2200 bytes (sizeof) 
{
	/*0x000*/     KTIMER* TimerExpiry[64];
	/*0x200*/     KTIMER_TABLE_ENTRY_SR TimerEntries[256];
}KTIMER_TABLE_SR, *PKTIMER_TABLE_SR;

typedef struct _CACHED_KSTACK_LIST_SR // 5 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     SLIST_HEADER SListHead; // 5 elements, 0x10 bytes (sizeof) 
	/*0x010*/     LONG32       MinimumFree;
	/*0x014*/     ULONG32      Misses;
	/*0x018*/     ULONG32      MissesLast;
	/*0x01C*/     ULONG32      Pad0;
}CACHED_KSTACK_LIST_SR, *PCACHED_KSTACK_LIST_SR;

typedef struct _flags_SR                      // 5 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        Removable : 1;            // 0 BitPosition                  
	/*0x000*/     UINT8        GroupAssigned : 1;        // 1 BitPosition                  
	/*0x000*/     UINT8        GroupCommitted : 1;       // 2 BitPosition                  
	/*0x000*/     UINT8        GroupAssignmentFixed : 1; // 3 BitPosition                  
	/*0x000*/     UINT8        Fill : 4;                 // 4 BitPosition                  
}flags_SR, *Pflags_SR;

typedef struct _KNODE_SR                              // 18 elements, 0xC0 bytes (sizeof) 
{
	/*0x000*/     SLIST_HEADER PagedPoolSListHead;        // 5 elements, 0x10 bytes (sizeof)  
	/*0x010*/     SLIST_HEADER NonPagedPoolSListHead[3];
	/*0x040*/     GROUP_AFFINITY Affinity;               // 3 elements, 0x10 bytes (sizeof)  
	/*0x050*/     ULONG32      ProximityId;
	/*0x054*/     UINT16       NodeNumber;
	/*0x056*/     UINT16       PrimaryNodeNumber;
	/*0x058*/     UINT8        MaximumProcessors;
	/*0x059*/     UINT8        Color;
	/*0x05A*/     flags_SR Flags;                           // 5 elements, 0x1 bytes (sizeof)   
	/*0x05B*/     UINT8        NodePad0;
	/*0x05C*/     ULONG32      Seed;
	/*0x060*/     ULONG32      MmShiftedColor;
	/*0x064*/     UINT8        _PADDING0_[0x4];
	/*0x068*/     UINT64       FreeCount[2];
	/*0x078*/     ULONG32      Right;
	/*0x07C*/     ULONG32      Left;
	/*0x080*/     CACHED_KSTACK_LIST_SR CachedKernelStacks; // 5 elements, 0x20 bytes (sizeof)  
	/*0x0A0*/     LONG32       ParkLock;
	/*0x0A4*/     ULONG32      NodePad1;
	/*0x0A8*/     UINT8        _PADDING1_[0x18];
}KNODE_SR, *PKNODE_SR;

typedef struct _KREQUEST_PACKET_SR                   // 2 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     VOID*        CurrentPacket[3];
	/*0x018*/     VOID*		   WorkerRoutine;
}KREQUEST_PACKET_SR, *PKREQUEST_PACKET_SR;

typedef struct _REQUEST_MAILBOX_SR            // 3 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _REQUEST_MAILBOX_SR* Next;
	/*0x008*/     INT64        RequestSummary;
	/*0x010*/     KREQUEST_PACKET_SR RequestPacket; // 2 elements, 0x20 bytes (sizeof) 
	/*0x030*/     UINT8        _PADDING0_[0x10];
}REQUEST_MAILBOX_SR, *PREQUEST_MAILBOX_SR;

typedef struct _PROC_HISTORY_ENTRY_SR // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT16       Utility;
	/*0x002*/     UINT8        Frequency;
	/*0x003*/     UINT8        Reserved;
}PROC_HISTORY_ENTRY_SR, *PPROC_HISTORY_ENTRY_SR;

typedef struct _PROC_PERF_LOAD_SR        // 2 elements, 0x2 bytes (sizeof) 
{
	/*0x000*/     UINT8        BusyPercentage;
	/*0x001*/     UINT8        FrequencyPercentage;
}PROC_PERF_LOAD_SR, *PPROC_PERF_LOAD_SR;

typedef struct _PROC_PERF_CONSTRAINT_SR      // 9 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     struct _KPRCB_SR* Prcb;
	/*0x008*/     UINT64       PerfContext;
	/*0x010*/     ULONG32      PercentageCap;
	/*0x014*/     ULONG32      ThermalCap;
	/*0x018*/     ULONG32      TargetFrequency;
	/*0x01C*/     ULONG32      AcumulatedFullFrequency;
	/*0x020*/     ULONG32      AcumulatedZeroFrequency;
	/*0x024*/     ULONG32      FrequencyHistoryTotal;
	/*0x028*/     ULONG32      AverageFrequency;
	/*0x02C*/     UINT8        _PADDING0_[0x4];
}PROC_PERF_CONSTRAINT_SR, *PPROC_PERF_CONSTRAINT_SR;

typedef struct _PROC_PERF_DOMAIN_SR                                         // 26 elements, 0xB8 bytes (sizeof) 
{
	/*0x000*/     LIST_ENTRY Link;                                             // 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     struct _KPRCB_SR* Master;
	/*0x018*/     KAFFINITY_EX_SR Members;                                        // 4 elements, 0x28 bytes (sizeof)  
	/*0x040*/     VOID* FeedbackHandler;
	/*0x048*/     VOID* GetFFHThrottleState;
	/*0x050*/     VOID* BoostPolicyHandler;
	/*0x058*/     VOID* PerfSelectionHandler;
	/*0x060*/     VOID* PerfHandler;
	/*0x068*/     PROC_PERF_CONSTRAINT_SR* Processors;
	/*0x070*/     UINT64       PerfChangeTime;
	/*0x078*/     ULONG32      ProcessorCount;
	/*0x07C*/     ULONG32      PreviousFrequencyMhz;
	/*0x080*/     ULONG32      CurrentFrequencyMhz;
	/*0x084*/     ULONG32      PreviousFrequency;
	/*0x088*/     ULONG32      CurrentFrequency;
	/*0x08C*/     ULONG32      CurrentPerfContext;
	/*0x090*/     ULONG32      DesiredFrequency;
	/*0x094*/     ULONG32      MaxFrequency;
	/*0x098*/     ULONG32      MinPerfPercent;
	/*0x09C*/     ULONG32      MinThrottlePercent;
	/*0x0A0*/     ULONG32      MaxPercent;
	/*0x0A4*/     ULONG32      MinPercent;
	/*0x0A8*/     ULONG32      ConstrainedMaxPercent;
	/*0x0AC*/     ULONG32      ConstrainedMinPercent;
	/*0x0B0*/     UINT8        Coordination;
	/*0x0B1*/     UINT8        _PADDING0_[0x3];
	/*0x0B4*/     LONG32       PerfChangeIntervalCount;
}PROC_PERF_DOMAIN_SR, *PPROC_PERF_DOMAIN_SR;

typedef struct _PROC_IDLE_SNAP_SR // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     UINT64       Time;
	/*0x008*/     UINT64       Idle;
}PROC_IDLE_SNAP_SR, *PPROC_IDLE_SNAP_SR;

typedef struct _PPM_FFH_THROTTLE_STATE_INFO_SR // 5 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     UINT8        EnableLogging;
	/*0x001*/     UINT8        _PADDING0_[0x3];
	/*0x004*/     ULONG32      MismatchCount;
	/*0x008*/     UINT8        Initialized;
	/*0x009*/     UINT8        _PADDING1_[0x7];
	/*0x010*/     UINT64       LastValue;
	/*0x018*/     LARGE_INTEGER LastLogTickCount;  // 4 elements, 0x8 bytes (sizeof)  
}PPM_FFH_THROTTLE_STATE_INFO_SR, *PPPM_FFH_THROTTLE_STATE_INFO_SR;

typedef struct _PROC_IDLE_STATE_BUCKET_SR // 4 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     UINT64       MinTime;
	/*0x010*/     UINT64       MaxTime;
	/*0x018*/     ULONG32      Count;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
}PROC_IDLE_STATE_BUCKET_SR, *PPROC_IDLE_STATE_BUCKET_SR;

typedef struct _PROC_IDLE_STATE_ACCOUNTING_SR              // 7 elements, 0x228 bytes (sizeof) 
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     ULONG32      IdleTransitions;
	/*0x00C*/     ULONG32      FailedTransitions;
	/*0x010*/     ULONG32      InvalidBucketIndex;
	/*0x014*/     UINT8        _PADDING0_[0x4];
	/*0x018*/     UINT64       MinTime;
	/*0x020*/     UINT64       MaxTime;
	/*0x028*/     PROC_IDLE_STATE_BUCKET_SR IdleTimeBuckets[16];
}PROC_IDLE_STATE_ACCOUNTING_SR, *PPROC_IDLE_STATE_ACCOUNTING_SR;

typedef struct _PROC_IDLE_ACCOUNTING_SR             // 6 elements, 0x2C0 bytes (sizeof) 
{
	/*0x000*/     ULONG32      StateCount;
	/*0x004*/     ULONG32      TotalTransitions;
	/*0x008*/     ULONG32      ResetCount;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     UINT64       StartTime;
	/*0x018*/     UINT64       BucketLimits[16];
	/*0x098*/     PROC_IDLE_STATE_ACCOUNTING_SR State[1];
}PROC_IDLE_ACCOUNTING_SR, *PPROC_IDLE_ACCOUNTING_SR;

typedef enum _PROC_HYPERVISOR_STATE_SR  // 3 elements, 0x4 bytes
{
	ProcHypervisorNone_Sr = 0 /*0x0*/,
	ProcHypervisorPresent_Sr = 1 /*0x1*/,
	ProcHypervisorPower_Sr = 2 /*0x2*/
}PROC_HYPERVISOR_STATE_SR, *PPROC_HYPERVISOR_STATE_SR;

typedef struct _PROCESSOR_POWER_STATE_SR                         // 27 elements, 0x100 bytes (sizeof) 
{
	/*0x000*/     struct _PPM_IDLE_STATES* IdleStates;
	/*0x008*/     UINT64       IdleTimeLast;
	/*0x010*/     UINT64       IdleTimeTotal;
	/*0x018*/     UINT64       IdleTimeEntry;
	/*0x020*/     PROC_IDLE_ACCOUNTING_SR* IdleAccounting;
	/*0x028*/     PROC_HYPERVISOR_STATE_SR Hypervisor;
	/*0x02C*/     ULONG32      PerfHistoryTotal;
	/*0x030*/     UINT8        ThermalConstraint;
	/*0x031*/     UINT8        PerfHistoryCount;
	/*0x032*/     UINT8        PerfHistorySlot;
	/*0x033*/     UINT8        Reserved;
	/*0x034*/     ULONG32      LastSysTime;
	/*0x038*/     UINT64       WmiDispatchPtr;
	/*0x040*/     LONG32       WmiInterfaceEnabled;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     PPM_FFH_THROTTLE_STATE_INFO_SR FFHThrottleStateInfo; // 5 elements, 0x20 bytes (sizeof)   
	/*0x068*/     KDPC PerfActionDpc;                               // 9 elements, 0x40 bytes (sizeof)   
	/*0x0A8*/     LONG32       PerfActionMask;
	/*0x0AC*/     UINT8        _PADDING1_[0x4];
	/*0x0B0*/     PROC_IDLE_SNAP_SR IdleCheck;                         // 2 elements, 0x10 bytes (sizeof)   
	/*0x0C0*/     PROC_IDLE_SNAP_SR PerfCheck;                         // 2 elements, 0x10 bytes (sizeof)   
	/*0x0D0*/     PROC_PERF_DOMAIN_SR* Domain;
	/*0x0D8*/     PROC_PERF_CONSTRAINT_SR* PerfConstraint;
	/*0x0E0*/     PROC_PERF_LOAD_SR* Load;
	/*0x0E8*/     PROC_HISTORY_ENTRY_SR* PerfHistory;
	/*0x0F0*/     ULONG32      Utility;
	/*0x0F4*/     ULONG32      OverUtilizedHistory;
	/*0x0F8*/     ULONG32      AffinityCount;
	/*0x0FC*/     ULONG32      AffinityHistory;
}PROCESSOR_POWER_STATE_SR, *PPROCESSOR_POWER_STATE_SR;

typedef struct _KPRCB_SR                                                   // 242 elements, 0x4D00 bytes (sizeof) 
{
	/*0x000*/      ULONG32      MxCsr;
	/*0x004*/      UINT8        LegacyNumber;
	/*0x005*/      UINT8        ReservedMustBeZero;
	/*0x006*/      UINT8        InterruptRequest;
	/*0x007*/      UINT8        IdleHalt;
	/*0x008*/      struct _KTHREAD_SR* CurrentThread;
	/*0x010*/      struct _KTHREAD_SR* NextThread;
	/*0x018*/      struct _KTHREAD_SR* IdleThread;
	/*0x020*/      UINT8        NestingLevel;
	/*0x021*/      UINT8        PrcbPad00[3];
	/*0x024*/      ULONG32      Number;
	/*0x028*/      UINT64       RspBase;
	/*0x030*/      UINT64       PrcbLock;
	/*0x038*/      UINT64       PrcbPad01;
	/*0x040*/      struct _KPROCESSOR_STATE_SR ProcessorState;                            // 2 elements, 0x5B0 bytes (sizeof)    
	/*0x5F0*/      CHAR         CpuType;
	/*0x5F1*/      CHAR         CpuID;
	union                                                               // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x5F2*/          UINT16       CpuStep;
		struct                                                          // 2 elements, 0x2 bytes (sizeof)      
		{
			/*0x5F2*/              UINT8        CpuStepping;
			/*0x5F3*/              UINT8        CpuModel;
		};
	};
	/*0x5F4*/      ULONG32      MHz;
	/*0x5F8*/      UINT64       HalReserved[8];
	/*0x638*/      UINT16       MinorVersion;
	/*0x63A*/      UINT16       MajorVersion;
	/*0x63C*/      UINT8        BuildType;
	/*0x63D*/      UINT8        CpuVendor;
	/*0x63E*/      UINT8        CoresPerPhysicalProcessor;
	/*0x63F*/      UINT8        LogicalProcessorsPerCore;
	/*0x640*/      ULONG32      ApicMask;
	/*0x644*/      ULONG32      CFlushSize;
	/*0x648*/      VOID*        AcpiReserved;
	/*0x650*/      ULONG32      InitialApicId;
	/*0x654*/      ULONG32      Stride;
	/*0x658*/      UINT16       Group;
	/*0x65A*/      UINT8        _PADDING0_[0x6];
	/*0x660*/      UINT64       GroupSetMember;
	/*0x668*/      UINT8        GroupIndex;
	/*0x669*/      UINT8        _PADDING1_[0x7];
	/*0x670*/      KSPIN_LOCK_QUEUE LockQueue[17];
	/*0x780*/      PP_LOOKASIDE_LIST_SR PPLookasideList[16];
	/*0x880*/      GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
	/*0x1480*/     GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
	/*0x2080*/     LONG32       PacketBarrier;
	/*0x2084*/     UINT8        _PADDING2_[0x4];
	/*0x2088*/     SINGLE_LIST_ENTRY DeferredReadyListHead;                    // 1 elements, 0x8 bytes (sizeof)      
	/*0x2090*/     LONG32       MmPageFaultCount;
	/*0x2094*/     LONG32       MmCopyOnWriteCount;
	/*0x2098*/     LONG32       MmTransitionCount;
	/*0x209C*/     LONG32       MmDemandZeroCount;
	/*0x20A0*/     LONG32       MmPageReadCount;
	/*0x20A4*/     LONG32       MmPageReadIoCount;
	/*0x20A8*/     LONG32       MmDirtyPagesWriteCount;
	/*0x20AC*/     LONG32       MmDirtyWriteIoCount;
	/*0x20B0*/     LONG32       MmMappedPagesWriteCount;
	/*0x20B4*/     LONG32       MmMappedWriteIoCount;
	/*0x20B8*/     ULONG32      KeSystemCalls;
	/*0x20BC*/     ULONG32      KeContextSwitches;
	/*0x20C0*/     ULONG32      CcFastReadNoWait;
	/*0x20C4*/     ULONG32      CcFastReadWait;
	/*0x20C8*/     ULONG32      CcFastReadNotPossible;
	/*0x20CC*/     ULONG32      CcCopyReadNoWait;
	/*0x20D0*/     ULONG32      CcCopyReadWait;
	/*0x20D4*/     ULONG32      CcCopyReadNoWaitMiss;
	/*0x20D8*/     LONG32       LookasideIrpFloat;
	/*0x20DC*/     LONG32       IoReadOperationCount;
	/*0x20E0*/     LONG32       IoWriteOperationCount;
	/*0x20E4*/     LONG32       IoOtherOperationCount;
	/*0x20E8*/     LARGE_INTEGER IoReadTransferCount;                           // 4 elements, 0x8 bytes (sizeof)      
	/*0x20F0*/     LARGE_INTEGER IoWriteTransferCount;                          // 4 elements, 0x8 bytes (sizeof)      
	/*0x20F8*/     LARGE_INTEGER IoOtherTransferCount;                          // 4 elements, 0x8 bytes (sizeof)      
	/*0x2100*/     LONG32       TargetCount;
	/*0x2104*/     ULONG32      IpiFrozen;
	/*0x2108*/     UINT8        _PADDING3_[0x78];
	/*0x2180*/     KDPC_DATA_SR DpcData[2];
	/*0x21C0*/     VOID*        DpcStack;
	/*0x21C8*/     LONG32       MaximumDpcQueueDepth;
	/*0x21CC*/     ULONG32      DpcRequestRate;
	/*0x21D0*/     ULONG32      MinimumDpcRate;
	/*0x21D4*/     ULONG32      DpcLastCount;
	/*0x21D8*/     UINT8        ThreadDpcEnable;
	/*0x21D9*/     UINT8        QuantumEnd;
	/*0x21DA*/     UINT8        DpcRoutineActive;
	/*0x21DB*/     UINT8        IdleSchedule;
	union                                                               // 3 elements, 0x4 bytes (sizeof)      
	{
		/*0x21DC*/         LONG32       DpcRequestSummary;
		/*0x21DC*/         INT16        DpcRequestSlot[2];
		struct                                                          // 2 elements, 0x4 bytes (sizeof)      
		{
			/*0x21DC*/             INT16        NormalDpcState;
			union                                                       // 2 elements, 0x2 bytes (sizeof)      
			{
				/*0x21DE*/                 UINT16       DpcThreadActive : 1;                       // 0 BitPosition                       
				/*0x21DE*/                 INT16        ThreadDpcState;
			};
		};
	};
	/*0x21E0*/     ULONG32      TimerHand;
	/*0x21E4*/     LONG32       MasterOffset;
	/*0x21E8*/     ULONG32      LastTick;
	/*0x21EC*/     ULONG32      UnusedPad;
	/*0x21F0*/     UINT64       PrcbPad50[2];
	/*0x2200*/     KTIMER_TABLE_SR TimerTable;                                    // 2 elements, 0x2200 bytes (sizeof)   
	/*0x4400*/     KGATE DpcGate;                                              // 1 elements, 0x18 bytes (sizeof)     
	/*0x4418*/     VOID*        PrcbPad52;
	/*0x4420*/     KDPC CallDpc;                                               // 9 elements, 0x40 bytes (sizeof)     
	/*0x4460*/     LONG32       ClockKeepAlive;
	/*0x4464*/     UINT8        ClockCheckSlot;
	/*0x4465*/     UINT8        ClockPollCycle;
	/*0x4466*/     UINT16       NmiActive;
	/*0x4468*/     LONG32       DpcWatchdogPeriod;
	/*0x446C*/     LONG32       DpcWatchdogCount;
	/*0x4470*/     UINT64       TickOffset;
	/*0x4478*/     LONG32       KeSpinLockOrdering;
	/*0x447C*/     ULONG32      PrcbPad70;
	/*0x4480*/     LIST_ENTRY WaitListHead;                                    // 2 elements, 0x10 bytes (sizeof)     
	/*0x4490*/     UINT64       WaitLock;
	/*0x4498*/     ULONG32      ReadySummary;
	/*0x449C*/     ULONG32      QueueIndex;
	/*0x44A0*/     KDPC TimerExpirationDpc;                                    // 9 elements, 0x40 bytes (sizeof)     
	/*0x44E0*/     UINT64       PrcbPad72[4];
	/*0x4500*/     LIST_ENTRY DispatcherReadyListHead[32];
	/*0x4700*/     ULONG32      InterruptCount;
	/*0x4704*/     ULONG32      KernelTime;
	/*0x4708*/     ULONG32      UserTime;
	/*0x470C*/     ULONG32      DpcTime;
	/*0x4710*/     ULONG32      InterruptTime;
	/*0x4714*/     ULONG32      AdjustDpcThreshold;
	/*0x4718*/     UINT8        DebuggerSavedIRQL;
	/*0x4719*/     UINT8        PrcbPad80[7];
	/*0x4720*/     ULONG32      DpcTimeCount;
	/*0x4724*/     ULONG32      DpcTimeLimit;
	/*0x4728*/     ULONG32      PeriodicCount;
	/*0x472C*/     ULONG32      PeriodicBias;
	/*0x4730*/     ULONG32      AvailableTime;
	/*0x4734*/     ULONG32      KeExceptionDispatchCount;
	/*0x4738*/     KNODE_SR* ParentNode;
	/*0x4740*/     UINT64       StartCycles;
	/*0x4748*/     UINT64       PrcbPad82[3];
	/*0x4760*/     LONG32       MmSpinLockOrdering;
	/*0x4764*/     ULONG32      PageColor;
	/*0x4768*/     ULONG32      NodeColor;
	/*0x476C*/     ULONG32      NodeShiftedColor;
	/*0x4770*/     ULONG32      SecondaryColorMask;
	/*0x4774*/     ULONG32      PrcbPad83;
	/*0x4778*/     UINT64       CycleTime;
	/*0x4780*/     ULONG32      CcFastMdlReadNoWait;
	/*0x4784*/     ULONG32      CcFastMdlReadWait;
	/*0x4788*/     ULONG32      CcFastMdlReadNotPossible;
	/*0x478C*/     ULONG32      CcMapDataNoWait;
	/*0x4790*/     ULONG32      CcMapDataWait;
	/*0x4794*/     ULONG32      CcPinMappedDataCount;
	/*0x4798*/     ULONG32      CcPinReadNoWait;
	/*0x479C*/     ULONG32      CcPinReadWait;
	/*0x47A0*/     ULONG32      CcMdlReadNoWait;
	/*0x47A4*/     ULONG32      CcMdlReadWait;
	/*0x47A8*/     ULONG32      CcLazyWriteHotSpots;
	/*0x47AC*/     ULONG32      CcLazyWriteIos;
	/*0x47B0*/     ULONG32      CcLazyWritePages;
	/*0x47B4*/     ULONG32      CcDataFlushes;
	/*0x47B8*/     ULONG32      CcDataPages;
	/*0x47BC*/     ULONG32      CcLostDelayedWrites;
	/*0x47C0*/     ULONG32      CcFastReadResourceMiss;
	/*0x47C4*/     ULONG32      CcCopyReadWaitMiss;
	/*0x47C8*/     ULONG32      CcFastMdlReadResourceMiss;
	/*0x47CC*/     ULONG32      CcMapDataNoWaitMiss;
	/*0x47D0*/     ULONG32      CcMapDataWaitMiss;
	/*0x47D4*/     ULONG32      CcPinReadNoWaitMiss;
	/*0x47D8*/     ULONG32      CcPinReadWaitMiss;
	/*0x47DC*/     ULONG32      CcMdlReadNoWaitMiss;
	/*0x47E0*/     ULONG32      CcMdlReadWaitMiss;
	/*0x47E4*/     ULONG32      CcReadAheadIos;
	/*0x47E8*/     LONG32       MmCacheTransitionCount;
	/*0x47EC*/     LONG32       MmCacheReadCount;
	/*0x47F0*/     LONG32       MmCacheIoCount;
	/*0x47F4*/     ULONG32      PrcbPad91[1];
	/*0x47F8*/     UINT64       RuntimeAccumulation;
	/*0x4800*/     PROCESSOR_POWER_STATE_SR PowerState;                           // 27 elements, 0x100 bytes (sizeof)   
	/*0x4900*/     UINT8        PrcbPad92[16];
	/*0x4910*/     ULONG32      KeAlignmentFixupCount;
	/*0x4914*/     UINT8        _PADDING4_[0x4];
	/*0x4918*/     KDPC DpcWatchdogDpc;                                        // 9 elements, 0x40 bytes (sizeof)     
	/*0x4958*/     KTIMER DpcWatchdogTimer;                                    // 6 elements, 0x40 bytes (sizeof)     
	/*0x4998*/     CACHE_DESCRIPTOR Cache[5];
	/*0x49D4*/     ULONG32      CacheCount;
	/*0x49D8*/     ULONG32      CachedCommit;
	/*0x49DC*/     ULONG32      CachedResidentAvailable;
	/*0x49E0*/     VOID*        HyperPte;
	/*0x49E8*/     VOID*        WheaInfo;
	/*0x49F0*/     VOID*        EtwSupport;
	/*0x49F8*/     UINT8        _PADDING5_[0x8];
	/*0x4A00*/     SLIST_HEADER InterruptObjectPool;                            // 5 elements, 0x10 bytes (sizeof)     
	/*0x4A10*/     SLIST_HEADER HypercallPageList;                              // 5 elements, 0x10 bytes (sizeof)     
	/*0x4A20*/     VOID*        HypercallPageVirtual;
	/*0x4A28*/     VOID*        VirtualApicAssist;
	/*0x4A30*/     UINT64*      StatisticsPage;
	/*0x4A38*/     VOID*        RateControl;
	/*0x4A40*/     UINT64       CacheProcessorMask[5];
	/*0x4A68*/     KAFFINITY_EX_SR PackageProcessorSet;                           // 4 elements, 0x28 bytes (sizeof)     
	/*0x4A90*/     UINT64       CoreProcessorSet;
	/*0x4A98*/     VOID*        PebsIndexAddress;
	/*0x4AA0*/     UINT64       PrcbPad93[12];
	/*0x4B00*/     ULONG32      SpinLockAcquireCount;
	/*0x4B04*/     ULONG32      SpinLockContentionCount;
	/*0x4B08*/     ULONG32      SpinLockSpinCount;
	/*0x4B0C*/     ULONG32      IpiSendRequestBroadcastCount;
	/*0x4B10*/     ULONG32      IpiSendRequestRoutineCount;
	/*0x4B14*/     ULONG32      IpiSendSoftwareInterruptCount;
	/*0x4B18*/     ULONG32      ExInitializeResourceCount;
	/*0x4B1C*/     ULONG32      ExReInitializeResourceCount;
	/*0x4B20*/     ULONG32      ExDeleteResourceCount;
	/*0x4B24*/     ULONG32      ExecutiveResourceAcquiresCount;
	/*0x4B28*/     ULONG32      ExecutiveResourceContentionsCount;
	/*0x4B2C*/     ULONG32      ExecutiveResourceReleaseExclusiveCount;
	/*0x4B30*/     ULONG32      ExecutiveResourceReleaseSharedCount;
	/*0x4B34*/     ULONG32      ExecutiveResourceConvertsCount;
	/*0x4B38*/     ULONG32      ExAcqResExclusiveAttempts;
	/*0x4B3C*/     ULONG32      ExAcqResExclusiveAcquiresExclusive;
	/*0x4B40*/     ULONG32      ExAcqResExclusiveAcquiresExclusiveRecursive;
	/*0x4B44*/     ULONG32      ExAcqResExclusiveWaits;
	/*0x4B48*/     ULONG32      ExAcqResExclusiveNotAcquires;
	/*0x4B4C*/     ULONG32      ExAcqResSharedAttempts;
	/*0x4B50*/     ULONG32      ExAcqResSharedAcquiresExclusive;
	/*0x4B54*/     ULONG32      ExAcqResSharedAcquiresShared;
	/*0x4B58*/     ULONG32      ExAcqResSharedAcquiresSharedRecursive;
	/*0x4B5C*/     ULONG32      ExAcqResSharedWaits;
	/*0x4B60*/     ULONG32      ExAcqResSharedNotAcquires;
	/*0x4B64*/     ULONG32      ExAcqResSharedStarveExclusiveAttempts;
	/*0x4B68*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresExclusive;
	/*0x4B6C*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresShared;
	/*0x4B70*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresSharedRecursive;
	/*0x4B74*/     ULONG32      ExAcqResSharedStarveExclusiveWaits;
	/*0x4B78*/     ULONG32      ExAcqResSharedStarveExclusiveNotAcquires;
	/*0x4B7C*/     ULONG32      ExAcqResSharedWaitForExclusiveAttempts;
	/*0x4B80*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresExclusive;
	/*0x4B84*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresShared;
	/*0x4B88*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive;
	/*0x4B8C*/     ULONG32      ExAcqResSharedWaitForExclusiveWaits;
	/*0x4B90*/     ULONG32      ExAcqResSharedWaitForExclusiveNotAcquires;
	/*0x4B94*/     ULONG32      ExSetResOwnerPointerExclusive;
	/*0x4B98*/     ULONG32      ExSetResOwnerPointerSharedNew;
	/*0x4B9C*/     ULONG32      ExSetResOwnerPointerSharedOld;
	/*0x4BA0*/     ULONG32      ExTryToAcqExclusiveAttempts;
	/*0x4BA4*/     ULONG32      ExTryToAcqExclusiveAcquires;
	/*0x4BA8*/     ULONG32      ExBoostExclusiveOwner;
	/*0x4BAC*/     ULONG32      ExBoostSharedOwners;
	/*0x4BB0*/     ULONG32      ExEtwSynchTrackingNotificationsCount;
	/*0x4BB4*/     ULONG32      ExEtwSynchTrackingNotificationsAccountedCount;
	/*0x4BB8*/     UINT8        VendorString[13];
	/*0x4BC5*/     UINT8        PrcbPad10[3];
	/*0x4BC8*/     ULONG32      FeatureBits;
	/*0x4BCC*/     UINT8        _PADDING6_[0x4];
	/*0x4BD0*/     LARGE_INTEGER UpdateSignature;                               // 4 elements, 0x8 bytes (sizeof)      
	/*0x4BD8*/     CONTEXT* Context;
	/*0x4BE0*/     ULONG32      ContextFlags;
	/*0x4BE4*/     UINT8        _PADDING7_[0x4];
	/*0x4BE8*/     XSAVE_AREA* ExtendedState;
	/*0x4BF0*/     UINT8        _PADDING8_[0x10];
	/*0x4C00*/     REQUEST_MAILBOX_SR* Mailbox;
	/*0x4C08*/     UINT8        _PADDING9_[0x78];
	/*0x4C80*/     REQUEST_MAILBOX_SR RequestMailbox[1];
	/*0x4CC0*/     UINT8        _PADDING10_[0x40];
}KPRCB_SR, *PKPRCB_SR;

typedef struct _COUNTER_READING_SR       // 4 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     HARDWARE_COUNTER_TYPE Type;
	/*0x004*/     ULONG32      Index;
	/*0x008*/     UINT64       Start;
	/*0x010*/     UINT64       Total;
}COUNTER_READING_SR, *PCOUNTER_READING_SR;

typedef struct _THREAD_PERFORMANCE_DATA_SR       // 10 elements, 0x1C0 bytes (sizeof) 
{
	/*0x000*/     UINT16       Size;
	/*0x002*/     UINT16       Version;
	/*0x004*/     PROCESSOR_NUMBER ProcessorNumber; // 3 elements, 0x4 bytes (sizeof)    
	/*0x008*/     ULONG32      ContextSwitches;
	/*0x00C*/     ULONG32      HwCountersCount;
	/*0x010*/     UINT64       UpdateCount;
	/*0x018*/     UINT64       WaitReasonBitMap;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     COUNTER_READING_SR CycleTime;        // 4 elements, 0x18 bytes (sizeof)   
	/*0x040*/     COUNTER_READING_SR HwCounters[16];
}THREAD_PERFORMANCE_DATA_SR, *PTHREAD_PERFORMANCE_DATA_SR;

typedef struct _KTHREAD_COUNTERS_SR               // 7 elements, 0x1A8 bytes (sizeof) 
{
	/*0x000*/     UINT64       WaitReasonBitMap;
	/*0x008*/     THREAD_PERFORMANCE_DATA_SR* UserData;
	/*0x010*/     ULONG32      Flags;
	/*0x014*/     ULONG32      ContextSwitches;
	/*0x018*/     UINT64       CycleTimeBias;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     COUNTER_READING_SR HwCounter[16];
}KTHREAD_COUNTERS_SR, *PKTHREAD_COUNTERS_SR;

typedef struct _TERMINATION_PORT_SR    // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     struct _TERMINATION_PORT_SR* Next;
	/*0x008*/     VOID*        Port;
}TERMINATION_PORT_SR, *PTERMINATION_PORT_SR;

typedef union _PS_CLIENT_SECURITY_CONTEXT_SR    // 4 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       ImpersonationData;
	/*0x000*/     VOID*        ImpersonationToken;
	struct                                   // 2 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         UINT64       ImpersonationLevel : 2; // 0 BitPosition                  
		/*0x000*/         UINT64       EffectiveOnly : 1;      // 2 BitPosition                  
	};
}PS_CLIENT_SECURITY_CONTEXT_SR, *PPS_CLIENT_SECURITY_CONTEXT_SR;

typedef struct _MMADDRESS_NODE_SR          // 5 elements, 0x28 bytes (sizeof) 
{
	union                               // 2 elements, 0x8 bytes (sizeof)  
	{
		/*0x000*/         INT64        Balance : 2;       // 0 BitPosition                   
		/*0x000*/         struct _MMADDRESS_NODE_SR* Parent;
	}u1;
	/*0x008*/     struct _MMADDRESS_NODE_SR* LeftChild;
	/*0x010*/     struct _MMADDRESS_NODE_SR* RightChild;
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
}MMADDRESS_NODE_SR, *PMMADDRESS_NODE_SR;

typedef struct _PEB_LDR_DATA_SR                            // 9 elements, 0x58 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID*        SsHandle;
	/*0x010*/     LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
	/*0x020*/     LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
	/*0x030*/     LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
	/*0x040*/     VOID*        EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID*        ShutdownThreadId;
}PEB_LDR_DATA_SR, *PPEB_LDR_DATA_SR;

typedef struct _RTL_DRIVE_LETTER_CURDIR_SR // 4 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     UINT16       Flags;
	/*0x002*/     UINT16       Length;
	/*0x004*/     ULONG32      TimeStamp;
	/*0x008*/     STRING	   DosPath;             // 3 elements, 0x10 bytes (sizeof) 
}RTL_DRIVE_LETTER_CURDIR_SR, *PRTL_DRIVE_LETTER_CURDIR_SR;

typedef struct _CURDIR_SR              // 2 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     UNICODE_STRING DosPath; // 3 elements, 0x10 bytes (sizeof) 
	/*0x010*/     VOID*        Handle;
}CURDIR_SR, *PCURDIR_SR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_SR                // 30 elements, 0x400 bytes (sizeof) 
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
	/*0x038*/     CURDIR_SR CurrentDirectory;                       // 2 elements, 0x18 bytes (sizeof)   
	/*0x050*/     UNICODE_STRING DllPath;                        // 3 elements, 0x10 bytes (sizeof)   
	/*0x060*/     UNICODE_STRING ImagePathName;                  // 3 elements, 0x10 bytes (sizeof)   
	/*0x070*/     UNICODE_STRING CommandLine;                    // 3 elements, 0x10 bytes (sizeof)   
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
	/*0x0B0*/     UNICODE_STRING WindowTitle;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0C0*/     UNICODE_STRING DesktopInfo;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0D0*/     UNICODE_STRING ShellInfo;                      // 3 elements, 0x10 bytes (sizeof)   
	/*0x0E0*/     UNICODE_STRING RuntimeData;                    // 3 elements, 0x10 bytes (sizeof)   
	/*0x0F0*/     RTL_DRIVE_LETTER_CURDIR_SR CurrentDirectores[32];
	/*0x3F0*/     UINT64       EnvironmentSize;
	/*0x3F8*/     UINT64       EnvironmentVersion;
}RTL_USER_PROCESS_PARAMETERS_SR, *PRTL_USER_PROCESS_PARAMETERS_SR;

typedef struct _RTL_CRITICAL_SECTION_DEBUG_SR         // 9 elements, 0x30 bytes (sizeof) 
{
	/*0x000*/     UINT16       Type;
	/*0x002*/     UINT16       CreatorBackTraceIndex;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     struct _RTL_CRITICAL_SECTION_SR* CriticalSection;
	/*0x010*/     LIST_ENTRY ProcessLocksList;           // 2 elements, 0x10 bytes (sizeof) 
	/*0x020*/     ULONG32      EntryCount;
	/*0x024*/     ULONG32      ContentionCount;
	/*0x028*/     ULONG32      Flags;
	/*0x02C*/     UINT16       CreatorBackTraceIndexHigh;
	/*0x02E*/     UINT16       SpareUSHORT;
}RTL_CRITICAL_SECTION_DEBUG_SR, *PRTL_CRITICAL_SECTION_DEBUG_SR;

typedef struct _RTL_CRITICAL_SECTION_SR               // 6 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     RTL_CRITICAL_SECTION_DEBUG_SR* DebugInfo;
	/*0x008*/     LONG32       LockCount;
	/*0x00C*/     LONG32       RecursionCount;
	/*0x010*/     VOID*        OwningThread;
	/*0x018*/     VOID*        LockSemaphore;
	/*0x020*/     UINT64       SpinCount;
}RTL_CRITICAL_SECTION_SR, *PRTL_CRITICAL_SECTION_SR;

typedef struct _MMWSLENTRY_SR               // 7 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       Valid : 1;              // 0 BitPosition                  
	/*0x000*/     UINT64       Spare : 1;              // 1 BitPosition                  
	/*0x000*/     UINT64       Hashed : 1;             // 2 BitPosition                  
	/*0x000*/     UINT64       Direct : 1;             // 3 BitPosition                  
	/*0x000*/     UINT64       Protection : 5;         // 4 BitPosition                  
	/*0x000*/     UINT64       Age : 3;                // 9 BitPosition                  
	/*0x000*/     UINT64       VirtualPageNumber : 52; // 12 BitPosition                 
}MMWSLENTRY_SR, *PMMWSLENTRY_SR;

typedef struct _MMWSLE_FREE_ENTRY_SR   // 3 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       MustBeZero : 1;    // 0 BitPosition                  
	/*0x000*/     UINT64       PreviousFree : 31; // 1 BitPosition                  
	/*0x000*/     UINT64       NextFree : 32;     // 32 BitPosition                 
}MMWSLE_FREE_ENTRY_SR, *PMMWSLE_FREE_ENTRY_SR;

typedef struct _MMWSLE_SR                // 1 elements, 0x8 bytes (sizeof) 
{
	union                             // 4 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         VOID*        VirtualAddress;
		/*0x000*/         UINT64       Long;
		/*0x000*/         MMWSLENTRY_SR e1;        // 7 elements, 0x8 bytes (sizeof) 
		/*0x000*/         MMWSLE_FREE_ENTRY_SR e2; // 3 elements, 0x8 bytes (sizeof) 
	}u1;
}MMWSLE_SR, *PMMWSLE_SR;

typedef struct _MMWSLE_NONDIRECT_HASH_SR // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     VOID*        Key;
	/*0x008*/     ULONG32      Index;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
}MMWSLE_NONDIRECT_HASH_SR, *PMMWSLE_NONDIRECT_HASH_SR;

typedef struct _MMWSLE_HASH_SR // 1 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Index;
}MMWSLE_HASH_SR, *PMMWSLE_HASH_SR;

typedef struct _MMWSL_SR                                   // 25 elements, 0x488 bytes (sizeof) 
{
	/*0x000*/     ULONG32      FirstFree;
	/*0x004*/     ULONG32      FirstDynamic;
	/*0x008*/     ULONG32      LastEntry;
	/*0x00C*/     ULONG32      NextSlot;
	/*0x010*/     MMWSLE_SR* Wsle;
	/*0x018*/     VOID*        LowestPagableAddress;
	/*0x020*/     ULONG32      LastInitializedWsle;
	/*0x024*/     ULONG32      NextAgingSlot;
	/*0x028*/     ULONG32      NumberOfCommittedPageTables;
	/*0x02C*/     ULONG32      VadBitMapHint;
	/*0x030*/     ULONG32      NonDirectCount;
	/*0x034*/     ULONG32      LastVadBit;
	/*0x038*/     ULONG32      MaximumLastVadBit;
	/*0x03C*/     ULONG32      LastAllocationSizeHint;
	/*0x040*/     ULONG32      LastAllocationSize;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     MMWSLE_NONDIRECT_HASH_SR* NonDirectHash;
	/*0x050*/     MMWSLE_HASH_SR* HashTableStart;
	/*0x058*/     MMWSLE_HASH_SR* HighestPermittedHashAddress;
	/*0x060*/     ULONG32      MaximumUserPageTablePages;
	/*0x064*/     ULONG32      MaximumUserPageDirectoryPages;
	/*0x068*/     ULONG32*     CommittedPageTables;
	/*0x070*/     ULONG32      NumberOfCommittedPageDirectories;
	/*0x074*/     UINT8        _PADDING1_[0x4];
	/*0x078*/     UINT64       CommittedPageDirectories[128];
	/*0x478*/     ULONG32      NumberOfCommittedPageDirectoryParents;
	/*0x47C*/     UINT8        _PADDING2_[0x4];
	/*0x480*/     UINT64       CommittedPageDirectoryParents[1];
}MMWSL_SR, *PMMWSL_SR;

typedef struct _MMSUPPORT_FLAGS_SR                 // 15 elements, 0x4 bytes (sizeof) 
{
	struct                                      // 6 elements, 0x1 bytes (sizeof)  
	{
		/*0x000*/         UINT8        WorkingSetType : 3;        // 0 BitPosition                   
		/*0x000*/         UINT8        ModwriterAttached : 1;     // 3 BitPosition                   
		/*0x000*/         UINT8        TrimHard : 1;              // 4 BitPosition                   
		/*0x000*/         UINT8        MaximumWorkingSetHard : 1; // 5 BitPosition                   
		/*0x000*/         UINT8        ForceTrim : 1;             // 6 BitPosition                   
		/*0x000*/         UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition                   
	};
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{
		/*0x001*/         UINT8        SessionMaster : 1;         // 0 BitPosition                   
		/*0x001*/         UINT8        TrimmerState : 2;          // 1 BitPosition                   
		/*0x001*/         UINT8        Reserved : 1;              // 3 BitPosition                   
		/*0x001*/         UINT8        PageStealers : 4;          // 4 BitPosition                   
	};
	/*0x002*/     UINT8        MemoryPriority : 8;            // 0 BitPosition                   
	struct                                      // 4 elements, 0x1 bytes (sizeof)  
	{
		/*0x003*/         UINT8        WsleDeleted : 1;           // 0 BitPosition                   
		/*0x003*/         UINT8        VmExiting : 1;             // 1 BitPosition                   
		/*0x003*/         UINT8        ExpansionFailed : 1;       // 2 BitPosition                   
		/*0x003*/         UINT8        Available : 5;             // 3 BitPosition                   
	};
}MMSUPPORT_FLAGS_SR, *PMMSUPPORT_FLAGS_SR;



typedef struct _PS_PER_CPU_QUOTA_CACHE_AWARE_SR // 5 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     LIST_ENTRY SortedListEntry;      // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     LIST_ENTRY IdleOnlyListHead;     // 2 elements, 0x10 bytes (sizeof) 
	/*0x020*/     UINT64       CycleBaseAllowance;
	/*0x028*/     INT64        CyclesRemaining;
	/*0x030*/     ULONG32      CurrentGeneration;
	/*0x034*/     UINT8        _PADDING0_[0xC];
}PS_PER_CPU_QUOTA_CACHE_AWARE_SR, *PPS_PER_CPU_QUOTA_CACHE_AWARE_SR;

typedef union _PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA_SR // 3 elements, 0x8 bytes (sizeof) 
{
	struct                                        // 2 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      CapturedCpuShareWeight;
		/*0x004*/         ULONG32      CapturedTotalWeight;
	};
	/*0x000*/     INT64        CombinedData;
}PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA_SR, *PPSP_CPU_SHARE_CAPTURED_WEIGHT_DATA_SR;

typedef struct _PS_CPU_QUOTA_BLOCK_SR                                        // 14 elements, 0x4080 bytes (sizeof) 
{
	union                                                                 // 2 elements, 0x40 bytes (sizeof)    
	{
		struct                                                            // 5 elements, 0x40 bytes (sizeof)    
		{
			/*0x000*/             LIST_ENTRY ListEntry;                                 // 2 elements, 0x10 bytes (sizeof)    
			/*0x010*/             ULONG32      SessionId;
			/*0x014*/             ULONG32      CpuShareWeight;
			/*0x018*/             PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA_SR CapturedWeightData; // 3 elements, 0x8 bytes (sizeof)     
			union                                                         // 2 elements, 0x4 bytes (sizeof)     
			{
				struct                                                    // 2 elements, 0x4 bytes (sizeof)     
				{
					/*0x020*/                     ULONG32      DuplicateInputMarker : 1;                // 0 BitPosition                      
					/*0x020*/                     ULONG32      Reserved : 31;                           // 1 BitPosition                      
				};
				/*0x020*/                 LONG32       MiscFlags;
			};
		};
		struct                                                            // 2 elements, 0x40 bytes (sizeof)    
		{
			/*0x000*/             UINT64       BlockCurrentGenerationLock;
			/*0x008*/             UINT64       CyclesAccumulated;
			/*0x010*/             UINT8        _PADDING0_[0x30];
		};
	};
	/*0x040*/     UINT64       CycleCredit;
	/*0x048*/     ULONG32      BlockCurrentGeneration;
	/*0x04C*/     ULONG32      CpuCyclePercent;
	/*0x050*/     UINT8        CyclesFinishedForCurrentGeneration;
	/*0x051*/     UINT8        _PADDING1_[0x2F];
	/*0x080*/     PS_PER_CPU_QUOTA_CACHE_AWARE_SR Cpu[256];
}PS_CPU_QUOTA_BLOCK_SR, *PPS_CPU_QUOTA_BLOCK_SR;

typedef struct _HANDLE_TRACE_DB_ENTRY_SR // 4 elements, 0xA0 bytes (sizeof) 
{
	/*0x000*/     CLIENT_ID ClientId;       // 2 elements, 0x10 bytes (sizeof) 
	/*0x010*/     VOID*        Handle;
	/*0x018*/     ULONG32      Type;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	/*0x020*/     VOID*        StackTrace[16];
}HANDLE_TRACE_DB_ENTRY_SR, *PHANDLE_TRACE_DB_ENTRY_SR;

typedef struct _HANDLE_TRACE_DEBUG_INFO_SR       // 6 elements, 0xF0 bytes (sizeof) 
{
	/*0x000*/     LONG32       RefCount;
	/*0x004*/     ULONG32      TableSize;
	/*0x008*/     ULONG32      BitMaskFlags;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     FAST_MUTEX CloseCompactionLock;   // 5 elements, 0x38 bytes (sizeof) 
	/*0x048*/     ULONG32      CurrentStackIndex;
	/*0x04C*/     UINT8        _PADDING1_[0x4];
	/*0x050*/     HANDLE_TRACE_DB_ENTRY_SR TraceDb[1];
}HANDLE_TRACE_DEBUG_INFO_SR, *PHANDLE_TRACE_DEBUG_INFO_SR;

typedef struct _HANDLE_TABLE_ENTRY_INFO_SR // 1 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      AuditMask;
}HANDLE_TABLE_ENTRY_INFO_SR, *PHANDLE_TABLE_ENTRY_INFO_SR;

typedef struct _HANDLE_TABLE                         // 15 elements, 0x68 bytes (sizeof) 
{
	/*0x000*/     UINT64       TableCode;
	/*0x008*/     struct _EPROCESS_SR* QuotaProcess;
	/*0x010*/     VOID*        UniqueProcessId;
	/*0x018*/     EX_PUSH_LOCK HandleLock;                 // 7 elements, 0x8 bytes (sizeof)   
	/*0x020*/     LIST_ENTRY HandleTableList;              // 2 elements, 0x10 bytes (sizeof)  
	/*0x030*/     EX_PUSH_LOCK HandleContentionEvent;      // 7 elements, 0x8 bytes (sizeof)   
	/*0x038*/     struct _HANDLE_TRACE_DEBUG_INFO_SR* DebugInfo;
	/*0x040*/     LONG32       ExtraInfoPages;
	union                                            // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x044*/         ULONG32      Flags;
		/*0x044*/         UINT8        StrictFIFO : 1;                 // 0 BitPosition                    
	};
	/*0x048*/     ULONG32      FirstFreeHandle;
	/*0x04C*/     UINT8        _PADDING0_[0x4];
	/*0x050*/     struct _HANDLE_TABLE_ENTRY_SR* LastFreeHandleEntry;
	/*0x058*/     ULONG32      HandleCount;
	/*0x05C*/     ULONG32      NextHandleNeedingPool;
	/*0x060*/     ULONG32      HandleCountHighWatermark;
	/*0x064*/     UINT8        _PADDING1_[0x4];
}HANDLE_TABLE_SR, *PHANDLE_TABLE_SR;

typedef struct _HANDLE_TABLE_ENTRY_SR                  // 8 elements, 0x10 bytes (sizeof) 
{
	union                                           // 4 elements, 0x8 bytes (sizeof)  
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         ULONG32      ObAttributes;
		/*0x000*/         HANDLE_TABLE_ENTRY_INFO_SR* InfoTable;
		/*0x000*/         UINT64       Value;
	};
	union                                           // 3 elements, 0x8 bytes (sizeof)  
	{
		/*0x008*/         ULONG32      GrantedAccess;
		struct                                      // 2 elements, 0x8 bytes (sizeof)  
		{
			/*0x008*/             UINT16       GrantedAccessIndex;
			/*0x00A*/             UINT16       CreatorBackTraceIndex;
			/*0x00C*/             UINT8        _PADDING0_[0x4];
		};
		/*0x008*/         ULONG32      NextFreeTableEntry;
	};
}HANDLE_TABLE_ENTRY_SR, *PHANDLE_TABLE_ENTRY_SR;

typedef struct _EX_FAST_REF_SR      // 3 elements, 0x8 bytes (sizeof) 
{
	union                        // 3 elements, 0x8 bytes (sizeof) 
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition                  
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF_SR, *PEX_FAST_REF_SR;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME_SR        // 3 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME_SR* Previous;
	/*0x008*/     VOID* ActivationContext;//struct ACTIVATION_CONTEXT has no element
	/*0x010*/     ULONG32      Flags;
	/*0x014*/     UINT8        _PADDING0_[0x4];
}RTL_ACTIVATION_CONTEXT_STACK_FRAME_SR, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME_SR;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_SR // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Flags;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     CHAR*        FrameName;
}TEB_ACTIVE_FRAME_CONTEXT_SR, *PTEB_ACTIVE_FRAME_CONTEXT_SR;

typedef struct _TEB_ACTIVE_FRAME_SR               // 3 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Flags;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     struct _TEB_ACTIVE_FRAME_SR* Previous;
	/*0x010*/     struct _TEB_ACTIVE_FRAME_CONTEXT_SR* Context;
}TEB_ACTIVE_FRAME_SR, *PTEB_ACTIVE_FRAME_SR;

typedef struct _GDI_TEB_BATCH_SR     // 3 elements, 0x4E8 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Offset;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     UINT64       HDC;
	/*0x010*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH_SR, *PGDI_TEB_BATCH_SR;

typedef struct _ACTIVATION_CONTEXT_STACK_SR                     // 5 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     RTL_ACTIVATION_CONTEXT_STACK_FRAME_SR* ActiveFrame;
	/*0x008*/     LIST_ENTRY FrameListCache;                       // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     ULONG32      Flags;
	/*0x01C*/     ULONG32      NextCookieSequenceNumber;
	/*0x020*/     ULONG32      StackId;
	/*0x024*/     UINT8        _PADDING0_[0x4];
}ACTIVATION_CONTEXT_STACK_SR, *PACTIVATION_CONTEXT_STACK_SR;

typedef struct _TEB_SR                                                  // 101 elements, 0x1818 bytes (sizeof) 
{
	/*0x000*/      NT_TIB NtTib;                                            // 8 elements, 0x38 bytes (sizeof)     
	/*0x038*/      VOID*        EnvironmentPointer;
	/*0x040*/      CLIENT_ID ClientId;                                      // 2 elements, 0x10 bytes (sizeof)     
	/*0x050*/      VOID*        ActiveRpcHandle;
	/*0x058*/      VOID*        ThreadLocalStoragePointer;
	/*0x060*/      struct _PEB_SR* ProcessEnvironmentBlock;
	/*0x068*/      ULONG32      LastErrorValue;
	/*0x06C*/      ULONG32      CountOfOwnedCriticalSections;
	/*0x070*/      VOID*        CsrClientThread;
	/*0x078*/      VOID*        Win32ThreadInfo;
	/*0x080*/      ULONG32      User32Reserved[26];
	/*0x0E8*/      ULONG32      UserReserved[5];
	/*0x0FC*/      UINT8        _PADDING0_[0x4];
	/*0x100*/      VOID*        WOW32Reserved;
	/*0x108*/      ULONG32      CurrentLocale;
	/*0x10C*/      ULONG32      FpSoftwareStatusRegister;
	/*0x110*/      VOID*        SystemReserved1[54];
	/*0x2C0*/      LONG32       ExceptionCode;
	/*0x2C4*/      UINT8        _PADDING1_[0x4];
	/*0x2C8*/      struct _ACTIVATION_CONTEXT_STACK_SR* ActivationContextStackPointer;
	/*0x2D0*/      UINT8        SpareBytes[24];
	/*0x2E8*/      ULONG32      TxFsContext;
	/*0x2EC*/      UINT8        _PADDING2_[0x4];
	/*0x2F0*/      struct _GDI_TEB_BATCH_SR GdiTebBatch;                               // 3 elements, 0x4E8 bytes (sizeof)    
	/*0x7D8*/      CLIENT_ID RealClientId;                                  // 2 elements, 0x10 bytes (sizeof)     
	/*0x7E8*/      VOID*        GdiCachedProcessHandle;
	/*0x7F0*/      ULONG32      GdiClientPID;
	/*0x7F4*/      ULONG32      GdiClientTID;
	/*0x7F8*/      VOID*        GdiThreadLocalInfo;
	/*0x800*/      UINT64       Win32ClientInfo[62];
	/*0x9F0*/      VOID*        glDispatchTable[233];
	/*0x1138*/     UINT64       glReserved1[29];
	/*0x1220*/     VOID*        glReserved2;
	/*0x1228*/     VOID*        glSectionInfo;
	/*0x1230*/     VOID*        glSection;
	/*0x1238*/     VOID*        glTable;
	/*0x1240*/     VOID*        glCurrentRC;
	/*0x1248*/     VOID*        glContext;
	/*0x1250*/     ULONG32      LastStatusValue;
	/*0x1254*/     UINT8        _PADDING3_[0x4];
	/*0x1258*/     UNICODE_STRING StaticUnicodeString;                      // 3 elements, 0x10 bytes (sizeof)     
	/*0x1268*/     WCHAR        StaticUnicodeBuffer[261];
	/*0x1472*/     UINT8        _PADDING4_[0x6];
	/*0x1478*/     VOID*        DeallocationStack;
	/*0x1480*/     VOID*        TlsSlots[64];
	/*0x1680*/     LIST_ENTRY TlsLinks;                                     // 2 elements, 0x10 bytes (sizeof)     
	/*0x1690*/     VOID*        Vdm;
	/*0x1698*/     VOID*        ReservedForNtRpc;
	/*0x16A0*/     VOID*        DbgSsReserved[2];
	/*0x16B0*/     ULONG32      HardErrorMode;
	/*0x16B4*/     UINT8        _PADDING5_[0x4];
	/*0x16B8*/     VOID*        Instrumentation[11];
	/*0x1710*/     GUID ActivityId;                                         // 4 elements, 0x10 bytes (sizeof)     
	/*0x1720*/     VOID*        SubProcessTag;
	/*0x1728*/     VOID*        EtwLocalData;
	/*0x1730*/     VOID*        EtwTraceData;
	/*0x1738*/     VOID*        WinSockData;
	/*0x1740*/     ULONG32      GdiBatchCount;
	union                                                            // 3 elements, 0x4 bytes (sizeof)      
	{
		/*0x1744*/         PROCESSOR_NUMBER CurrentIdealProcessor;              // 3 elements, 0x4 bytes (sizeof)      
		/*0x1744*/         ULONG32      IdealProcessorValue;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)      
		{
			/*0x1744*/             UINT8        ReservedPad0;
			/*0x1745*/             UINT8        ReservedPad1;
			/*0x1746*/             UINT8        ReservedPad2;
			/*0x1747*/             UINT8        IdealProcessor;
		};
	};
	/*0x1748*/     ULONG32      GuaranteedStackBytes;
	/*0x174C*/     UINT8        _PADDING6_[0x4];
	/*0x1750*/     VOID*        ReservedForPerf;
	/*0x1758*/     VOID*        ReservedForOle;
	/*0x1760*/     ULONG32      WaitingOnLoaderLock;
	/*0x1764*/     UINT8        _PADDING7_[0x4];
	/*0x1768*/     VOID*        SavedPriorityState;
	/*0x1770*/     UINT64       SoftPatchPtr1;
	/*0x1778*/     VOID*        ThreadPoolData;
	/*0x1780*/     VOID**       TlsExpansionSlots;
	/*0x1788*/     VOID*        DeallocationBStore;
	/*0x1790*/     VOID*        BStoreLimit;
	/*0x1798*/     ULONG32      MuiGeneration;
	/*0x179C*/     ULONG32      IsImpersonating;
	/*0x17A0*/     VOID*        NlsCache;
	/*0x17A8*/     VOID*        pShimData;
	/*0x17B0*/     ULONG32      HeapVirtualAffinity;
	/*0x17B4*/     UINT8        _PADDING8_[0x4];
	/*0x17B8*/     VOID*        CurrentTransactionHandle;
	/*0x17C0*/     struct _TEB_ACTIVE_FRAME_SR* ActiveFrame;
	/*0x17C8*/     VOID*        FlsData;
	/*0x17D0*/     VOID*        PreferredLanguages;
	/*0x17D8*/     VOID*        UserPrefLanguages;
	/*0x17E0*/     VOID*        MergedPrefLanguages;
	/*0x17E8*/     ULONG32      MuiImpersonation;
	union                                                            // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EC*/         UINT16       CrossTebFlags;
		/*0x17EC*/         UINT16       SpareCrossTebBits : 16;                         // 0 BitPosition                       
	};
	union                                                            // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EE*/         UINT16       SameTebFlags;
		struct                                                       // 12 elements, 0x2 bytes (sizeof)     
		{
			/*0x17EE*/             UINT16       SafeThunkCall : 1;                          // 0 BitPosition                       
			/*0x17EE*/             UINT16       InDebugPrint : 1;                           // 1 BitPosition                       
			/*0x17EE*/             UINT16       HasFiberData : 1;                           // 2 BitPosition                       
			/*0x17EE*/             UINT16       SkipThreadAttach : 1;                       // 3 BitPosition                       
			/*0x17EE*/             UINT16       WerInShipAssertCode : 1;                    // 4 BitPosition                       
			/*0x17EE*/             UINT16       RanProcessInit : 1;                         // 5 BitPosition                       
			/*0x17EE*/             UINT16       ClonedThread : 1;                           // 6 BitPosition                       
			/*0x17EE*/             UINT16       SuppressDebugMsg : 1;                       // 7 BitPosition                       
			/*0x17EE*/             UINT16       DisableUserStackWalk : 1;                   // 8 BitPosition                       
			/*0x17EE*/             UINT16       RtlExceptionAttached : 1;                   // 9 BitPosition                       
			/*0x17EE*/             UINT16       InitialThread : 1;                          // 10 BitPosition                      
			/*0x17EE*/             UINT16       SpareSameTebBits : 5;                       // 11 BitPosition                      
		};
	};
	/*0x17F0*/     VOID*        TxnScopeEnterCallback;
	/*0x17F8*/     VOID*        TxnScopeExitCallback;
	/*0x1800*/     VOID*        TxnScopeContext;
	/*0x1808*/     ULONG32      LockCount;
	/*0x180C*/     ULONG32      SpareUlong0;
	/*0x1810*/     VOID*        ResourceRetValue;
}TEB_SR, *PTEB_SR;

typedef struct _CLIENT_ID32_SR     // 2 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     ULONG32      UniqueProcess;
	/*0x004*/     ULONG32      UniqueThread;
}CLIENT_ID32_SR, *PCLIENT_ID32_SR;

typedef struct _GDI_TEB_BATCH32_SR // 3 elements, 0x4E0 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Offset;
	/*0x004*/     ULONG32      HDC;
	/*0x008*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH32_SR, *PGDI_TEB_BATCH32_SR;

typedef struct _TEB32_SR                                   // 99 elements, 0xFE4 bytes (sizeof) 
{
	/*0x000*/     NT_TIB32 NtTib;                             // 8 elements, 0x1C bytes (sizeof)   
	/*0x01C*/     ULONG32      EnvironmentPointer;
	/*0x020*/     CLIENT_ID32_SR ClientId;                       // 2 elements, 0x8 bytes (sizeof)    
	/*0x028*/     ULONG32      ActiveRpcHandle;
	/*0x02C*/     ULONG32      ThreadLocalStoragePointer;
	/*0x030*/     ULONG32      ProcessEnvironmentBlock;
	/*0x034*/     ULONG32      LastErrorValue;
	/*0x038*/     ULONG32      CountOfOwnedCriticalSections;
	/*0x03C*/     ULONG32      CsrClientThread;
	/*0x040*/     ULONG32      Win32ThreadInfo;
	/*0x044*/     ULONG32      User32Reserved[26];
	/*0x0AC*/     ULONG32      UserReserved[5];
	/*0x0C0*/     ULONG32      WOW32Reserved;
	/*0x0C4*/     ULONG32      CurrentLocale;
	/*0x0C8*/     ULONG32      FpSoftwareStatusRegister;
	/*0x0CC*/     ULONG32      SystemReserved1[54];
	/*0x1A4*/     LONG32       ExceptionCode;
	/*0x1A8*/     ULONG32      ActivationContextStackPointer;
	/*0x1AC*/     UINT8        SpareBytes[36];
	/*0x1D0*/     ULONG32      TxFsContext;
	/*0x1D4*/     GDI_TEB_BATCH32_SR GdiTebBatch;                // 3 elements, 0x4E0 bytes (sizeof)  
	/*0x6B4*/     CLIENT_ID32_SR RealClientId;                   // 2 elements, 0x8 bytes (sizeof)    
	/*0x6BC*/     ULONG32      GdiCachedProcessHandle;
	/*0x6C0*/     ULONG32      GdiClientPID;
	/*0x6C4*/     ULONG32      GdiClientTID;
	/*0x6C8*/     ULONG32      GdiThreadLocalInfo;
	/*0x6CC*/     ULONG32      Win32ClientInfo[62];
	/*0x7C4*/     ULONG32      glDispatchTable[233];
	/*0xB68*/     ULONG32      glReserved1[29];
	/*0xBDC*/     ULONG32      glReserved2;
	/*0xBE0*/     ULONG32      glSectionInfo;
	/*0xBE4*/     ULONG32      glSection;
	/*0xBE8*/     ULONG32      glTable;
	/*0xBEC*/     ULONG32      glCurrentRC;
	/*0xBF0*/     ULONG32      glContext;
	/*0xBF4*/     ULONG32      LastStatusValue;
	/*0xBF8*/     STRING32 StaticUnicodeString;               // 3 elements, 0x8 bytes (sizeof)    
	/*0xC00*/     WCHAR        StaticUnicodeBuffer[261];
	/*0xE0A*/     UINT8        _PADDING0_[0x2];
	/*0xE0C*/     ULONG32      DeallocationStack;
	/*0xE10*/     ULONG32      TlsSlots[64];
	/*0xF10*/     LIST_ENTRY32 TlsLinks;                      // 2 elements, 0x8 bytes (sizeof)    
	/*0xF18*/     ULONG32      Vdm;
	/*0xF1C*/     ULONG32      ReservedForNtRpc;
	/*0xF20*/     ULONG32      DbgSsReserved[2];
	/*0xF28*/     ULONG32      HardErrorMode;
	/*0xF2C*/     ULONG32      Instrumentation[9];
	/*0xF50*/     GUID ActivityId;                            // 4 elements, 0x10 bytes (sizeof)   
	/*0xF60*/     ULONG32      SubProcessTag;
	/*0xF64*/     ULONG32      EtwLocalData;
	/*0xF68*/     ULONG32      EtwTraceData;
	/*0xF6C*/     ULONG32      WinSockData;
	/*0xF70*/     ULONG32      GdiBatchCount;
	union                                               // 3 elements, 0x4 bytes (sizeof)    
	{
		/*0xF74*/         PROCESSOR_NUMBER CurrentIdealProcessor; // 3 elements, 0x4 bytes (sizeof)    
		/*0xF74*/         ULONG32      IdealProcessorValue;
		struct                                          // 4 elements, 0x4 bytes (sizeof)    
		{
			/*0xF74*/             UINT8        ReservedPad0;
			/*0xF75*/             UINT8        ReservedPad1;
			/*0xF76*/             UINT8        ReservedPad2;
			/*0xF77*/             UINT8        IdealProcessor;
		};
	};
	/*0xF78*/     ULONG32      GuaranteedStackBytes;
	/*0xF7C*/     ULONG32      ReservedForPerf;
	/*0xF80*/     ULONG32      ReservedForOle;
	/*0xF84*/     ULONG32      WaitingOnLoaderLock;
	/*0xF88*/     ULONG32      SavedPriorityState;
	/*0xF8C*/     ULONG32      SoftPatchPtr1;
	/*0xF90*/     ULONG32      ThreadPoolData;
	/*0xF94*/     ULONG32      TlsExpansionSlots;
	/*0xF98*/     ULONG32      MuiGeneration;
	/*0xF9C*/     ULONG32      IsImpersonating;
	/*0xFA0*/     ULONG32      NlsCache;
	/*0xFA4*/     ULONG32      pShimData;
	/*0xFA8*/     ULONG32      HeapVirtualAffinity;
	/*0xFAC*/     ULONG32      CurrentTransactionHandle;
	/*0xFB0*/     ULONG32      ActiveFrame;
	/*0xFB4*/     ULONG32      FlsData;
	/*0xFB8*/     ULONG32      PreferredLanguages;
	/*0xFBC*/     ULONG32      UserPrefLanguages;
	/*0xFC0*/     ULONG32      MergedPrefLanguages;
	/*0xFC4*/     ULONG32      MuiImpersonation;
	union                                               // 2 elements, 0x2 bytes (sizeof)    
	{
		/*0xFC8*/         UINT16       CrossTebFlags;
		/*0xFC8*/         UINT16       SpareCrossTebBits : 16;            // 0 BitPosition                     
	};
	union                                               // 2 elements, 0x2 bytes (sizeof)    
	{
		/*0xFCA*/         UINT16       SameTebFlags;
		struct                                          // 12 elements, 0x2 bytes (sizeof)   
		{
			/*0xFCA*/             UINT16       SafeThunkCall : 1;             // 0 BitPosition                     
			/*0xFCA*/             UINT16       InDebugPrint : 1;              // 1 BitPosition                     
			/*0xFCA*/             UINT16       HasFiberData : 1;              // 2 BitPosition                     
			/*0xFCA*/             UINT16       SkipThreadAttach : 1;          // 3 BitPosition                     
			/*0xFCA*/             UINT16       WerInShipAssertCode : 1;       // 4 BitPosition                     
			/*0xFCA*/             UINT16       RanProcessInit : 1;            // 5 BitPosition                     
			/*0xFCA*/             UINT16       ClonedThread : 1;              // 6 BitPosition                     
			/*0xFCA*/             UINT16       SuppressDebugMsg : 1;          // 7 BitPosition                     
			/*0xFCA*/             UINT16       DisableUserStackWalk : 1;      // 8 BitPosition                     
			/*0xFCA*/             UINT16       RtlExceptionAttached : 1;      // 9 BitPosition                     
			/*0xFCA*/             UINT16       InitialThread : 1;             // 10 BitPosition                    
			/*0xFCA*/             UINT16       SpareSameTebBits : 5;          // 11 BitPosition                    
		};
	};
	/*0xFCC*/     ULONG32      TxnScopeEnterCallback;
	/*0xFD0*/     ULONG32      TxnScopeExitCallback;
	/*0xFD4*/     ULONG32      TxnScopeContext;
	/*0xFD8*/     ULONG32      LockCount;
	/*0xFDC*/     ULONG32      SpareUlong0;
	/*0xFE0*/     ULONG32      ResourceRetValue;
}TEB32_SR, *PTEB32_SR;

typedef struct _KTHREAD_SR                                 // 129 elements, 0x360 bytes (sizeof) 
{
	/*0x000*/     DISPATCHER_HEADER Header;                   // 29 elements, 0x18 bytes (sizeof)   
	/*0x018*/     UINT64       CycleTime;
	/*0x020*/     UINT64       QuantumTarget;
	/*0x028*/     VOID*        InitialStack;
	/*0x030*/     VOID*        StackLimit;
	/*0x038*/     VOID*        KernelStack;
	/*0x040*/     UINT64       ThreadLock;
	/*0x048*/     KWAIT_STATUS_REGISTER_SR WaitRegister;          // 8 elements, 0x1 bytes (sizeof)     
	/*0x049*/     UINT8        Running;
	/*0x04A*/     UINT8        Alerted[2];
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                          // 15 elements, 0x4 bytes (sizeof)    
		{
			/*0x04C*/             ULONG32      KernelStackResident : 1;       // 0 BitPosition                      
			/*0x04C*/             ULONG32      ReadyTransition : 1;           // 1 BitPosition                      
			/*0x04C*/             ULONG32      ProcessReadyQueue : 1;         // 2 BitPosition                      
			/*0x04C*/             ULONG32      WaitNext : 1;                  // 3 BitPosition                      
			/*0x04C*/             ULONG32      SystemAffinityActive : 1;      // 4 BitPosition                      
			/*0x04C*/             ULONG32      Alertable : 1;                 // 5 BitPosition                      
			/*0x04C*/             ULONG32      GdiFlushActive : 1;            // 6 BitPosition                      
			/*0x04C*/             ULONG32      UserStackWalkActive : 1;       // 7 BitPosition                      
			/*0x04C*/             ULONG32      ApcInterruptRequest : 1;       // 8 BitPosition                      
			/*0x04C*/             ULONG32      ForceDeferSchedule : 1;        // 9 BitPosition                      
			/*0x04C*/             ULONG32      QuantumEndMigrate : 1;         // 10 BitPosition                     
			/*0x04C*/             ULONG32      UmsDirectedSwitchEnable : 1;   // 11 BitPosition                     
			/*0x04C*/             ULONG32      TimerActive : 1;               // 12 BitPosition                     
			/*0x04C*/             ULONG32      SystemThread : 1;              // 13 BitPosition                     
			/*0x04C*/             ULONG32      Reserved : 18;                 // 14 BitPosition                     
		};
		/*0x04C*/         LONG32       MiscFlags;
	};
	union                                               // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x050*/         KAPC_STATE ApcState;                    // 5 elements, 0x30 bytes (sizeof)    
		struct                                          // 3 elements, 0x30 bytes (sizeof)    
		{
			/*0x050*/             UINT8        ApcStateFill[43];//该元素偏移位50h，但是在70h处(+20h)保存了eprocess地址
			/*0x07B*/             CHAR         Priority;
			/*0x07C*/             ULONG32      NextProcessor;
		};
	};
	/*0x080*/     ULONG32      DeferredProcessor;
	/*0x084*/     UINT8        _PADDING0_[0x4];
	/*0x088*/     UINT64       ApcQueueLock;
	/*0x090*/     INT64        WaitStatus;
	/*0x098*/     KWAIT_BLOCK* WaitBlockList;
	union                                               // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x0A0*/         LIST_ENTRY WaitListEntry;               // 2 elements, 0x10 bytes (sizeof)    
		/*0x0A0*/         SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x8 bytes (sizeof)     
	};
	/*0x0B0*/     KQUEUE* Queue;
	/*0x0B8*/     TEB_SR*        Teb;
	/*0x0C0*/     KTIMER Timer;                               // 6 elements, 0x40 bytes (sizeof)    
	union                                               // 2 elements, 0x4 bytes (sizeof)     
	{
		struct                                          // 12 elements, 0x4 bytes (sizeof)    
		{
			/*0x100*/             ULONG32      AutoAlignment : 1;             // 0 BitPosition                      
			/*0x100*/             ULONG32      DisableBoost : 1;              // 1 BitPosition                      
			/*0x100*/             ULONG32      EtwStackTraceApc1Inserted : 1; // 2 BitPosition                      
			/*0x100*/             ULONG32      EtwStackTraceApc2Inserted : 1; // 3 BitPosition                      
			/*0x100*/             ULONG32      CalloutActive : 1;             // 4 BitPosition                      
			/*0x100*/             ULONG32      ApcQueueable : 1;              // 5 BitPosition                      
			/*0x100*/             ULONG32      EnableStackSwap : 1;           // 6 BitPosition                      
			/*0x100*/             ULONG32      GuiThread : 1;                 // 7 BitPosition                      
			/*0x100*/             ULONG32      UmsPerformingSyscall : 1;      // 8 BitPosition                      
			/*0x100*/             ULONG32      VdmSafe : 1;                   // 9 BitPosition                      
			/*0x100*/             ULONG32      UmsDispatched : 1;             // 10 BitPosition                     
			/*0x100*/             ULONG32      ReservedFlags : 21;            // 11 BitPosition                     
		};
		/*0x100*/         LONG32       ThreadFlags;
	};
	/*0x104*/     ULONG32      Spare0;
	union                                               // 6 elements, 0xC0 bytes (sizeof)    
	{
		/*0x108*/         KWAIT_BLOCK WaitBlock[4];
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill4[44];
			/*0x134*/             ULONG32      ContextSwitches;
			/*0x138*/             UINT8        _PADDING1_[0x90];
		};
		struct                                          // 5 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill5[92];
			/*0x164*/             UINT8        State;
			/*0x165*/             CHAR         NpxState;
			/*0x166*/             UINT8        WaitIrql;
			/*0x167*/             CHAR         WaitMode;
			/*0x168*/             UINT8        _PADDING2_[0x60];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill6[140];
			/*0x194*/             ULONG32      WaitTime;
			/*0x198*/             UINT8        _PADDING3_[0x30];
		};
		struct                                          // 3 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill7[168];
			/*0x1B0*/             VOID*        TebMappedLowVa;
			/*0x1B8*/             UMS_CONTROL_BLOCK_SR* Ucb;
			/*0x1C0*/             UINT8        _PADDING4_[0x8];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)    
		{
			/*0x108*/             UINT8        WaitBlockFill8[188];
			union                                       // 2 elements, 0x4 bytes (sizeof)     
			{
				struct                                  // 2 elements, 0x4 bytes (sizeof)     
				{
					/*0x1C4*/                     INT16        KernelApcDisable;
					/*0x1C6*/                     INT16        SpecialApcDisable;
				};
				/*0x1C4*/                 ULONG32      CombinedApcDisable;
			};
		};
	};
	/*0x1C8*/     LIST_ENTRY QueueListEntry;                  // 2 elements, 0x10 bytes (sizeof)    
	/*0x1D8*/     KTRAP_FRAME* TrapFrame;
	/*0x1E0*/     VOID*        FirstArgument;
	union                                               // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x1E8*/         VOID*        CallbackStack;
		/*0x1E8*/         UINT64       CallbackDepth;
	};
	/*0x1F0*/     UINT8        ApcStateIndex;
	/*0x1F1*/     CHAR         BasePriority;
	union                                               // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x1F2*/         CHAR         PriorityDecrement;
		struct                                          // 2 elements, 0x1 bytes (sizeof)     
		{
			/*0x1F2*/             UINT8        ForegroundBoost : 4;           // 0 BitPosition                      
			/*0x1F2*/             UINT8        UnusualBoost : 4;              // 4 BitPosition                      
		};
	};
	/*0x1F3*/     UINT8        Preempted;
	/*0x1F4*/     UINT8        AdjustReason;
	/*0x1F5*/     CHAR         AdjustIncrement;
	/*0x1F6*/     CHAR         PreviousMode;
	/*0x1F7*/     CHAR         Saturation;
	/*0x1F8*/     ULONG32      SystemCallNumber;
	/*0x1FC*/     ULONG32      FreezeCount;
	/*0x200*/     GROUP_AFFINITY UserAffinity;                // 3 elements, 0x10 bytes (sizeof)    
	/*0x210*/     KPROCESS_SR* Process;
	/*0x218*/     GROUP_AFFINITY Affinity;                    // 3 elements, 0x10 bytes (sizeof)    
	/*0x228*/     ULONG32      IdealProcessor;
	/*0x22C*/     ULONG32      UserIdealProcessor;
	/*0x230*/     KAPC_STATE* ApcStatePointer[2];
	union                                               // 2 elements, 0x30 bytes (sizeof)    
	{
		/*0x240*/         KAPC_STATE SavedApcState;               // 5 elements, 0x30 bytes (sizeof)    
		struct                                          // 5 elements, 0x30 bytes (sizeof)    
		{
			/*0x240*/             UINT8        SavedApcStateFill[43];
			/*0x26B*/             UINT8        WaitReason;
			/*0x26C*/             CHAR         SuspendCount;
			/*0x26D*/             CHAR         Spare1;
			/*0x26E*/             UINT8        CodePatchInProgress;
			/*0x26F*/             UINT8        _PADDING5_[0x1];
		};
	};
	/*0x270*/     VOID*        Win32Thread;
	/*0x278*/     VOID*        StackBase;
	union                                               // 7 elements, 0x58 bytes (sizeof)    
	{
		/*0x280*/         KAPC SuspendApc;                        // 16 elements, 0x58 bytes (sizeof)   
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill0[1];
			/*0x281*/             UINT8        ResourceIndex;
			/*0x282*/             UINT8        _PADDING6_[0x56];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill1[3];
			/*0x283*/             UINT8        QuantumReset;
			/*0x284*/             UINT8        _PADDING7_[0x54];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill2[4];
			/*0x284*/             ULONG32      KernelTime;
			/*0x288*/             UINT8        _PADDING8_[0x50];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill3[64];
			/*0x2C0*/             KPRCB_SR* WaitPrcb;
			/*0x2C8*/             UINT8        _PADDING9_[0x10];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill4[72];
			/*0x2C8*/             VOID*        LegoData;
			/*0x2D0*/             UINT8        _PADDING10_[0x8];
		};
		struct                                          // 3 elements, 0x58 bytes (sizeof)    
		{
			/*0x280*/             UINT8        SuspendApcFill5[83];
			/*0x2D3*/             UINT8        LargeStack;
			/*0x2D4*/             ULONG32      UserTime;
		};
	};
	union                                               // 2 elements, 0x20 bytes (sizeof)    
	{
		/*0x2D8*/         KSEMAPHORE SuspendSemaphore;            // 2 elements, 0x20 bytes (sizeof)    
		struct                                          // 2 elements, 0x20 bytes (sizeof)    
		{
			/*0x2D8*/             UINT8        SuspendSemaphorefill[28];
			/*0x2F4*/             ULONG32      SListFaultCount;
		};
	};
	/*0x2F8*/     LIST_ENTRY ThreadListEntry;                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x308*/     LIST_ENTRY MutantListHead;                  // 2 elements, 0x10 bytes (sizeof)    
	/*0x318*/     VOID*        SListFaultAddress;
	/*0x320*/     INT64        ReadOperationCount;
	/*0x328*/     INT64        WriteOperationCount;
	/*0x330*/     INT64        OtherOperationCount;
	/*0x338*/     INT64        ReadTransferCount;
	/*0x340*/     INT64        WriteTransferCount;
	/*0x348*/     INT64        OtherTransferCount;
	/*0x350*/     KTHREAD_COUNTERS_SR* ThreadCounters;
	/*0x358*/     XSTATE_SAVE* XStateSave;
}KTHREAD_SR, *PKTHREAD_SR;

typedef struct _ETHREAD                                              // 88 elements, 0x498 bytes (sizeof)  
{
	/*0x000*/     KTHREAD_SR Tcb;                                             // 129 elements, 0x360 bytes (sizeof) 
	/*0x360*/     LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)     
	union                                                            // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x368*/         LARGE_INTEGER ExitTime;                               // 4 elements, 0x8 bytes (sizeof)     
		/*0x368*/         LIST_ENTRY KeyedWaitChain;                           // 2 elements, 0x10 bytes (sizeof)    
	};
	/*0x378*/     LONG32       ExitStatus;
	/*0x37C*/     UINT8        _PADDING0_[0x4];
	union                                                            // 2 elements, 0x10 bytes (sizeof)    
	{
		/*0x380*/         LIST_ENTRY PostBlockList;                            // 2 elements, 0x10 bytes (sizeof)    
		struct                                                       // 2 elements, 0x10 bytes (sizeof)    
		{
			/*0x380*/             VOID*        ForwardLinkShadow;
			/*0x388*/             VOID*        StartAddress;
		};
	};
	union                                                            // 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x390*/         TERMINATION_PORT_SR* TerminationPort;
		/*0x390*/         struct _ETHREAD_SR* ReaperLink;
		/*0x390*/         VOID*        KeyedWaitValue;
	};
	/*0x398*/     UINT64       ActiveTimerListLock;
	/*0x3A0*/     LIST_ENTRY ActiveTimerListHead;                          // 2 elements, 0x10 bytes (sizeof)    
	/*0x3B0*/     CLIENT_ID Cid;                                           // 2 elements, 0x10 bytes (sizeof)    
	union                                                            // 2 elements, 0x20 bytes (sizeof)    
	{
		/*0x3C0*/         KSEMAPHORE KeyedWaitSemaphore;                       // 2 elements, 0x20 bytes (sizeof)    
		/*0x3C0*/         KSEMAPHORE AlpcWaitSemaphore;                        // 2 elements, 0x20 bytes (sizeof)    
	};
	/*0x3E0*/     union _PS_CLIENT_SECURITY_CONTEXT_SR ClientSecurity;                // 4 elements, 0x8 bytes (sizeof)     
	/*0x3E8*/     LIST_ENTRY IrpList;                                      // 2 elements, 0x10 bytes (sizeof)    
	/*0x3F8*/     UINT64       TopLevelIrp;
	/*0x400*/     DEVICE_OBJECT* DeviceToVerify;
	/*0x408*/     VOID* CpuQuotaApc;										//struct PSP_CPU_QUOTA_APC has no element
	/*0x410*/     VOID*        Win32StartAddress;
	/*0x418*/     VOID*        LegacyPowerObject;
	/*0x420*/     LIST_ENTRY ThreadListEntry;                              // 2 elements, 0x10 bytes (sizeof)    
	/*0x430*/     EX_RUNDOWN_REF RundownProtect;                           // 2 elements, 0x8 bytes (sizeof)     
	/*0x438*/     EX_PUSH_LOCK ThreadLock;                                 // 7 elements, 0x8 bytes (sizeof)     
	/*0x440*/     ULONG32      ReadClusterSize;
	/*0x444*/     LONG32       MmLockOrdering;
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x448*/         ULONG32      CrossThreadFlags;
		struct                                                       // 14 elements, 0x4 bytes (sizeof)    
		{
			/*0x448*/             ULONG32      Terminated : 1;                             // 0 BitPosition                      
			/*0x448*/             ULONG32      ThreadInserted : 1;                         // 1 BitPosition                      
			/*0x448*/             ULONG32      HideFromDebugger : 1;                       // 2 BitPosition                      
			/*0x448*/             ULONG32      ActiveImpersonationInfo : 1;                // 3 BitPosition                      
			/*0x448*/             ULONG32      Reserved : 1;                               // 4 BitPosition                      
			/*0x448*/             ULONG32      HardErrorsAreDisabled : 1;                  // 5 BitPosition                      
			/*0x448*/             ULONG32      BreakOnTermination : 1;                     // 6 BitPosition                      
			/*0x448*/             ULONG32      SkipCreationMsg : 1;                        // 7 BitPosition                      
			/*0x448*/             ULONG32      SkipTerminationMsg : 1;                     // 8 BitPosition                      
			/*0x448*/             ULONG32      CopyTokenOnOpen : 1;                        // 9 BitPosition                      
			/*0x448*/             ULONG32      ThreadIoPriority : 3;                       // 10 BitPosition                     
			/*0x448*/             ULONG32      ThreadPagePriority : 3;                     // 13 BitPosition                     
			/*0x448*/             ULONG32      RundownFail : 1;                            // 16 BitPosition                     
			/*0x448*/             ULONG32      NeedsWorkingSetAging : 1;                   // 17 BitPosition                     
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x44C*/         ULONG32      SameThreadPassiveFlags;
		struct                                                       // 7 elements, 0x4 bytes (sizeof)     
		{
			/*0x44C*/             ULONG32      ActiveExWorker : 1;                         // 0 BitPosition                      
			/*0x44C*/             ULONG32      ExWorkerCanWaitUser : 1;                    // 1 BitPosition                      
			/*0x44C*/             ULONG32      MemoryMaker : 1;                            // 2 BitPosition                      
			/*0x44C*/             ULONG32      ClonedThread : 1;                           // 3 BitPosition                      
			/*0x44C*/             ULONG32      KeyedEventInUse : 1;                        // 4 BitPosition                      
			/*0x44C*/             ULONG32      RateApcState : 2;                           // 5 BitPosition                      
			/*0x44C*/             ULONG32      SelfTerminate : 1;                          // 7 BitPosition                      
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x450*/         ULONG32      SameThreadApcFlags;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)     
		{
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x450*/                 UINT8        Spare : 1;                              // 0 BitPosition                      
				/*0x450*/                 UINT8        StartAddressInvalid : 1;                // 1 BitPosition                      
				/*0x450*/                 UINT8        EtwPageFaultCalloutActive : 1;          // 2 BitPosition                      
				/*0x450*/                 UINT8        OwnsProcessWorkingSetExclusive : 1;     // 3 BitPosition                      
				/*0x450*/                 UINT8        OwnsProcessWorkingSetShared : 1;        // 4 BitPosition                      
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetExclusive : 1; // 5 BitPosition                      
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetShared : 1;    // 6 BitPosition                      
				/*0x450*/                 UINT8        OwnsSessionWorkingSetExclusive : 1;     // 7 BitPosition                      
			};
			struct                                                   // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x451*/                 UINT8        OwnsSessionWorkingSetShared : 1;        // 0 BitPosition                      
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;   // 1 BitPosition                      
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceShared : 1;      // 2 BitPosition                      
				/*0x451*/                 UINT8        SuppressSymbolLoad : 1;                 // 3 BitPosition                      
				/*0x451*/                 UINT8        Prefetching : 1;                        // 4 BitPosition                      
				/*0x451*/                 UINT8        OwnsDynamicMemoryShared : 1;            // 5 BitPosition                      
				/*0x451*/                 UINT8        OwnsChangeControlAreaExclusive : 1;     // 6 BitPosition                      
				/*0x451*/                 UINT8        OwnsChangeControlAreaShared : 1;        // 7 BitPosition                      
			};
			struct                                                   // 6 elements, 0x1 bytes (sizeof)     
			{
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetExclusive : 1;   // 0 BitPosition                      
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetShared : 1;      // 1 BitPosition                      
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetExclusive : 1;  // 2 BitPosition                      
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetShared : 1;     // 3 BitPosition                      
				/*0x452*/                 UINT8        TrimTrigger : 2;                        // 4 BitPosition                      
				/*0x452*/                 UINT8        Spare1 : 2;                             // 6 BitPosition                      
			};
			/*0x453*/             UINT8        PriorityRegionActive;
		};
	};
	/*0x454*/     UINT8        CacheManagerActive;
	/*0x455*/     UINT8        DisablePageFaultClustering;
	/*0x456*/     UINT8        ActiveFaultCount;
	/*0x457*/     UINT8        LockOrderState;
	/*0x458*/     UINT64       AlpcMessageId;
	union                                                            // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x460*/         VOID*        AlpcMessage;
		/*0x460*/         ULONG32      AlpcReceiveAttributeSet;
	};
	/*0x468*/     LIST_ENTRY AlpcWaitListEntry;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x478*/     ULONG32      CacheManagerCount;
	/*0x47C*/     ULONG32      IoBoostCount;
	/*0x480*/     UINT64       IrpListLock;
	/*0x488*/     VOID*        ReservedForSynchTracking;
	/*0x490*/     SINGLE_LIST_ENTRY CmCallbackListHead;                    // 1 elements, 0x8 bytes (sizeof)     
}ETHREAD_SR, *PETHREAD_SR;

typedef struct _MM_AVL_TABLE_SR                          // 6 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _MMADDRESS_NODE_SR BalancedRoot;              // 5 elements, 0x28 bytes (sizeof) 
	struct                                            // 3 elements, 0x8 bytes (sizeof)  
	{
		/*0x028*/         UINT64       DepthOfTree : 5;                 // 0 BitPosition                   
		/*0x028*/         UINT64       Unused : 3;                      // 5 BitPosition                   
		/*0x028*/         UINT64       NumberGenericTableElements : 56; // 8 BitPosition                   
	};
	/*0x030*/     VOID*        NodeHint;
	/*0x038*/     VOID*        NodeFreeHint;
}MM_AVL_TABLE_SR, *PMM_AVL_TABLE_SR;

typedef struct _EJOB_SR                                // 42 elements, 0x1C8 bytes (sizeof) 
{
	/*0x000*/     KEVENT Event;                           // 1 elements, 0x18 bytes (sizeof)   
	/*0x018*/     LIST_ENTRY JobLinks;                    // 2 elements, 0x10 bytes (sizeof)   
	/*0x028*/     LIST_ENTRY ProcessListHead;             // 2 elements, 0x10 bytes (sizeof)   
	/*0x038*/     ERESOURCE JobLock;                      // 15 elements, 0x68 bytes (sizeof)  
	/*0x0A0*/     LARGE_INTEGER TotalUserTime;             // 4 elements, 0x8 bytes (sizeof)    
	/*0x0A8*/     LARGE_INTEGER TotalKernelTime;           // 4 elements, 0x8 bytes (sizeof)    
	/*0x0B0*/     LARGE_INTEGER ThisPeriodTotalUserTime;   // 4 elements, 0x8 bytes (sizeof)    
	/*0x0B8*/     LARGE_INTEGER ThisPeriodTotalKernelTime; // 4 elements, 0x8 bytes (sizeof)    
	/*0x0C0*/     ULONG32      TotalPageFaultCount;
	/*0x0C4*/     ULONG32      TotalProcesses;
	/*0x0C8*/     ULONG32      ActiveProcesses;
	/*0x0CC*/     ULONG32      TotalTerminatedProcesses;
	/*0x0D0*/     LARGE_INTEGER PerProcessUserTimeLimit;   // 4 elements, 0x8 bytes (sizeof)    
	/*0x0D8*/     LARGE_INTEGER PerJobUserTimeLimit;       // 4 elements, 0x8 bytes (sizeof)    
	/*0x0E0*/     UINT64       MinimumWorkingSetSize;
	/*0x0E8*/     UINT64       MaximumWorkingSetSize;
	/*0x0F0*/     ULONG32      LimitFlags;
	/*0x0F4*/     ULONG32      ActiveProcessLimit;
	/*0x0F8*/     KAFFINITY_EX_SR Affinity;                  // 4 elements, 0x28 bytes (sizeof)   
	/*0x120*/     UINT8        PriorityClass;
	/*0x121*/     UINT8        _PADDING0_[0x7];
	/*0x128*/     VOID* AccessState;						//struct JOB_ACCESS_STATE has no element
	/*0x130*/     ULONG32      UIRestrictionsClass;
	/*0x134*/     ULONG32      EndOfJobTimeAction;
	/*0x138*/     VOID*        CompletionPort;
	/*0x140*/     VOID*        CompletionKey;
	/*0x148*/     ULONG32      SessionId;
	/*0x14C*/     ULONG32      SchedulingClass;
	/*0x150*/     UINT64       ReadOperationCount;
	/*0x158*/     UINT64       WriteOperationCount;
	/*0x160*/     UINT64       OtherOperationCount;
	/*0x168*/     UINT64       ReadTransferCount;
	/*0x170*/     UINT64       WriteTransferCount;
	/*0x178*/     UINT64       OtherTransferCount;
	/*0x180*/     UINT64       ProcessMemoryLimit;
	/*0x188*/     UINT64       JobMemoryLimit;
	/*0x190*/     UINT64       PeakProcessMemoryUsed;
	/*0x198*/     UINT64       PeakJobMemoryUsed;
	/*0x1A0*/     UINT64       CurrentJobMemoryUsed;
	/*0x1A8*/     EX_PUSH_LOCK MemoryLimitsLock;          // 7 elements, 0x8 bytes (sizeof)    
	/*0x1B0*/     LIST_ENTRY JobSetLinks;                 // 2 elements, 0x10 bytes (sizeof)   
	/*0x1C0*/     ULONG32      MemberLevel;
	/*0x1C4*/     ULONG32      JobFlags;
}EJOB_SR, *PEJOB_SR;

typedef struct _HARDWARE_PTE_SR           // 16 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT64       Valid : 1;            // 0 BitPosition                   
	/*0x000*/     UINT64       Write : 1;            // 1 BitPosition                   
	/*0x000*/     UINT64       Owner : 1;            // 2 BitPosition                   
	/*0x000*/     UINT64       WriteThrough : 1;     // 3 BitPosition                   
	/*0x000*/     UINT64       CacheDisable : 1;     // 4 BitPosition                   
	/*0x000*/     UINT64       Accessed : 1;         // 5 BitPosition                   
	/*0x000*/     UINT64       Dirty : 1;            // 6 BitPosition                   
	/*0x000*/     UINT64       LargePage : 1;        // 7 BitPosition                   
	/*0x000*/     UINT64       Global : 1;           // 8 BitPosition                   
	/*0x000*/     UINT64       CopyOnWrite : 1;      // 9 BitPosition                   
	/*0x000*/     UINT64       Prototype : 1;        // 10 BitPosition                  
	/*0x000*/     UINT64       reserved0 : 1;        // 11 BitPosition                  
	/*0x000*/     UINT64       PageFrameNumber : 36; // 12 BitPosition	9 9 9 9 12分页模式的页帧编号                
	/*0x000*/     UINT64       reserved1 : 4;        // 48 BitPosition                  
	/*0x000*/     UINT64       SoftwareWsIndex : 11; // 52 BitPosition                  
	/*0x000*/     UINT64       NoExecute : 1;        // 63 BitPosition                  
}HARDWARE_PTE_SR, *PHARDWARE_PTE_SR;

typedef struct _PEB_SR                                                                               // 91 elements, 0x380 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                                                         // 2 elements, 0x1 bytes (sizeof)    
	{
		/*0x003*/         UINT8        BitField;
		struct                                                                                    // 6 elements, 0x1 bytes (sizeof)    
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                 // 0 BitPosition                     
			/*0x003*/             UINT8        IsProtectedProcess : 1;                                                  // 1 BitPosition                     
			/*0x003*/             UINT8        IsLegacyProcess : 1;                                                     // 2 BitPosition                     
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                         // 3 BitPosition                     
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                        // 4 BitPosition                     
			/*0x003*/             UINT8        SpareBits : 3;                                                           // 5 BitPosition                     
		};
	};
	/*0x008*/     VOID*        Mutant;
	/*0x010*/     VOID*        ImageBaseAddress;
	/*0x018*/     PEB_LDR_DATA_SR* Ldr;
	/*0x020*/     RTL_USER_PROCESS_PARAMETERS_SR* ProcessParameters;
	/*0x028*/     VOID*        SubSystemData;
	/*0x030*/     VOID*        ProcessHeap;
	/*0x038*/     RTL_CRITICAL_SECTION_SR* FastPebLock;
	/*0x040*/     VOID*        AtlThunkSListPtr;
	/*0x048*/     VOID*        IFEOKey;
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct                                                                                    // 6 elements, 0x4 bytes (sizeof)    
		{
			/*0x050*/             ULONG32      ProcessInJob : 1;                                                        // 0 BitPosition                     
			/*0x050*/             ULONG32      ProcessInitializing : 1;                                                 // 1 BitPosition                     
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;                                                     // 2 BitPosition                     
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;                                                     // 3 BitPosition                     
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;                                                     // 4 BitPosition                     
			/*0x050*/             ULONG32      ReservedBits0 : 27;                                                      // 5 BitPosition                     
		};
	};
	union                                                                                         // 2 elements, 0x8 bytes (sizeof)    
	{
		/*0x058*/         VOID*        KernelCallbackTable;
		/*0x058*/         VOID*        UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved[1];
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     VOID*        ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        _PADDING0_[0x4];
	/*0x078*/     VOID*        TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     VOID*        ReadOnlySharedMemoryBase;
	/*0x090*/     VOID*        HotpatchInformation;
	/*0x098*/     VOID**       ReadOnlyStaticServerData;
	/*0x0A0*/     VOID*        AnsiCodePageData;
	/*0x0A8*/     VOID*        OemCodePageData;
	/*0x0B0*/     VOID*        UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     LARGE_INTEGER CriticalSectionTimeout;                                                  // 4 elements, 0x8 bytes (sizeof)    
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     VOID**       ProcessHeaps;
	/*0x0F8*/     VOID*        GdiSharedHandleTable;
	/*0x100*/     VOID*        ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        _PADDING1_[0x4];
	/*0x110*/     RTL_CRITICAL_SECTION_SR* LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        _PADDING2_[0x4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     VOID*		   PostProcessInitRoutine;
	/*0x238*/     VOID*        TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        _PADDING3_[0x4];
	/*0x2C8*/     ULARGE_INTEGER AppCompatFlags;                                                         // 4 elements, 0x8 bytes (sizeof)    
	/*0x2D0*/     ULARGE_INTEGER AppCompatFlagsUser;                                                     // 4 elements, 0x8 bytes (sizeof)    
	/*0x2D8*/     VOID*        pShimData;
	/*0x2E0*/     VOID*        AppCompatInfo;
	/*0x2E8*/     UNICODE_STRING CSDVersion;                                                            // 3 elements, 0x10 bytes (sizeof)   
	/*0x2F8*/     VOID* ActivationContextData;														//struct ACTIVATION_CONTEXT_DATA has no element
	/*0x300*/     VOID* ProcessAssemblyStorageMap;														//struct ASSEMBLY_STORAGE_MAP has no element
	/*0x308*/     VOID* SystemDefaultActivationContextData;											//struct ACTIVATION_CONTEXT_DATA has no element
	/*0x310*/     VOID* SystemAssemblyStorageMap;													//struct ASSEMBLY_STORAGE_MAP has no element
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     VOID* FlsCallback;																	//struct FLS_CALLBACK_INFO has no element
	/*0x328*/     LIST_ENTRY FlsListHead;                                                               // 2 elements, 0x10 bytes (sizeof)   
	/*0x338*/     VOID*        FlsBitmap;
	/*0x340*/     ULONG32      FlsBitmapBits[4];
	/*0x350*/     ULONG32      FlsHighIndex;
	/*0x354*/     UINT8        _PADDING4_[0x4];
	/*0x358*/     VOID*        WerRegistrationData;
	/*0x360*/     VOID*        WerShipAssertPtr;
	/*0x368*/     VOID*        pContextData;
	/*0x370*/     VOID*        pImageHeaderHash;
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)    
	{
		/*0x378*/         ULONG32      TracingFlags;
		struct                                                                                    // 3 elements, 0x4 bytes (sizeof)    
		{
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;                                                  // 0 BitPosition                     
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;                                               // 1 BitPosition                     
			/*0x378*/             ULONG32      SpareTracingBits : 30;                                                   // 2 BitPosition                     
		};
	};
}PEB_SR, *PPEB_SR;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO_SR      // 1 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     OBJECT_NAME_INFORMATION* ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO_SR, *PSE_AUDIT_PROCESS_CREATION_INFO_SR;

typedef struct _MMSUPPORT_SR                        // 21 elements, 0x88 bytes (sizeof) 
{
	/*0x000*/     EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x8 bytes (sizeof)   
	/*0x008*/     KGATE* ExitGate;
	/*0x010*/     VOID*        AccessLog;
	/*0x018*/     LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)  
	/*0x028*/     ULONG32      AgeDistribution[7];
	/*0x044*/     ULONG32      MinimumWorkingSetSize;
	/*0x048*/     ULONG32      WorkingSetSize;
	/*0x04C*/     ULONG32      WorkingSetPrivateSize;
	/*0x050*/     ULONG32      MaximumWorkingSetSize;
	/*0x054*/     ULONG32      ChargedWslePages;
	/*0x058*/     ULONG32      ActualWslePages;
	/*0x05C*/     ULONG32      WorkingSetSizeOverhead;
	/*0x060*/     ULONG32      PeakWorkingSetSize;
	/*0x064*/     ULONG32      HardFaultCount;
	/*0x068*/     MMWSL_SR* VmWorkingSetList;
	/*0x070*/     UINT16       NextPageColor;
	/*0x072*/     UINT16       LastTrimStamp;
	/*0x074*/     ULONG32      PageFaultCount;
	/*0x078*/     ULONG32      RepurposeCount;
	/*0x07C*/     ULONG32      Spare[2];
	/*0x084*/     MMSUPPORT_FLAGS_SR Flags;               // 15 elements, 0x4 bytes (sizeof)  
}MMSUPPORT_SR, *PMMSUPPORT_SR;

typedef struct _ALPC_PROCESS_CONTEXT_SR  // 3 elements, 0x20 bytes (sizeof) 
{
	/*0x000*/     EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)  
	/*0x008*/     LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     UINT64       PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT_SR, *PALPC_PROCESS_CONTEXT_SR;

typedef struct _PO_DIAG_STACK_RECORD_SR // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     ULONG32      StackDepth;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     VOID*        Stack[1];
}PO_DIAG_STACK_RECORD_SR, *PPO_DIAG_STACK_RECORD_SR;

typedef struct _EPROCESS_SR													// 135 elements, 0x4D0 bytes (sizeof) 
{
	/*0x000*/     KPROCESS_SR Pcb;                                          // 37 elements, 0x160 bytes (sizeof)  
	/*0x160*/     EX_PUSH_LOCK ProcessLock;                                 // 7 elements, 0x8 bytes (sizeof)     
	/*0x168*/     LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)     
	/*0x170*/     LARGE_INTEGER ExitTime;                                   // 4 elements, 0x8 bytes (sizeof)     
	/*0x178*/     EX_RUNDOWN_REF RundownProtect;                            // 2 elements, 0x8 bytes (sizeof)     
	/*0x180*/     VOID*        UniqueProcessId;
	/*0x188*/	  LIST_ENTRY ActiveProcessLinks;                            // 2 elements, 0x10 bytes (sizeof)    
	/*0x198*/     UINT64       ProcessQuotaUsage[2];
	/*0x1A8*/     UINT64       ProcessQuotaPeak[2];
	/*0x1B8*/     UINT64       CommitCharge;
	/*0x1C0*/     VOID* QuotaBlock;											//struct EPROCESS_QUOTA_BLOCK has no element
	/*0x1C8*/     PS_CPU_QUOTA_BLOCK_SR* CpuQuotaBlock;
	/*0x1D0*/     UINT64       PeakVirtualSize;
	/*0x1D8*/     UINT64       VirtualSize;
	/*0x1E0*/     LIST_ENTRY SessionProcessLinks;                           // 2 elements, 0x10 bytes (sizeof)    
	/*0x1F0*/     VOID*        DebugPort;									//如果其值不为0，表明该进程正在被调试。保存的是调试内核对象
	union																	// 3 elements, 0x8 bytes (sizeof)     
	{
		/*0x1F8*/         VOID*        ExceptionPortData;
		/*0x1F8*/         UINT64       ExceptionPortValue;
		/*0x1F8*/         UINT64       ExceptionPortState : 3;              // 0 BitPosition                      
	};
	/*0x200*/     HANDLE_TABLE_SR* ObjectTable;
	/*0x208*/     EX_FAST_REF_SR Token;                                     // 3 elements, 0x8 bytes (sizeof)     
	/*0x210*/     UINT64       WorkingSetPage;
	/*0x218*/     EX_PUSH_LOCK AddressCreationLock;                         // 7 elements, 0x8 bytes (sizeof)     
	/*0x220*/     ETHREAD_SR* RotateInProgress;
	/*0x228*/     ETHREAD_SR* ForkInProgress;
	/*0x230*/     UINT64       HardwareTrigger;
	/*0x238*/     MM_AVL_TABLE_SR* PhysicalVadRoot;
	/*0x240*/     VOID*        CloneRoot;
	/*0x248*/     UINT64       NumberOfPrivatePages;
	/*0x250*/     UINT64       NumberOfLockedPages;
	/*0x258*/     VOID*        Win32Process;
	/*0x260*/     EJOB_SR*	   Job;
	/*0x268*/     VOID*        SectionObject;
	/*0x270*/     VOID*        SectionBaseAddress;
	/*0x278*/     ULONG32      Cookie;
	/*0x27C*/     ULONG32      UmsScheduledThreads;
	/*0x280*/     VOID*		   WorkingSetWatch;					//struct PAGEFAULT_HISTORY has no element
	/*0x288*/     VOID*        Win32WindowStation;
	/*0x290*/     VOID*        InheritedFromUniqueProcessId;
	/*0x298*/     VOID*        LdtInformation;
	/*0x2A0*/     VOID*        Spare;
	/*0x2A8*/     UINT64       ConsoleHostProcess;
	/*0x2B0*/     VOID*        DeviceMap;
	/*0x2B8*/     VOID*        EtwDataSource;
	/*0x2C0*/     VOID*        FreeTebHint;
	/*0x2C8*/     VOID*        FreeUmsTebHint;
	union                                                              // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x2D0*/         HARDWARE_PTE_SR PageDirectoryPte;                         // 16 elements, 0x8 bytes (sizeof)    
		/*0x2D0*/         UINT64       Filler;
	};
	/*0x2D8*/     VOID*        Session;
	/*0x2E0*/     UINT8        ImageFileName[15];
	/*0x2EF*/     UINT8        PriorityClass;
	/*0x2F0*/     LIST_ENTRY JobLinks;                                       // 2 elements, 0x10 bytes (sizeof)    
	/*0x300*/     VOID*        LockedPagesList;
	/*0x308*/     LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x318*/     VOID*        SecurityPort;
	/*0x320*/     VOID*        Wow64Process;								//如果进程是32位进程，那么这里将保存32位进程的peb32
	/*0x328*/     ULONG32      ActiveThreads;
	/*0x32C*/     ULONG32      ImagePathHash;
	/*0x330*/     ULONG32      DefaultHardErrorProcessing;
	/*0x334*/     LONG32       LastThreadExitStatus;
	/*0x338*/     PEB_SR* Peb;
	/*0x340*/     EX_FAST_REF_SR PrefetchTrace;                                 // 3 elements, 0x8 bytes (sizeof)     
	/*0x348*/     LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x350*/     LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x358*/     LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
	/*0x360*/     LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)     
	/*0x368*/     LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x370*/     LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
	/*0x378*/     UINT64       CommitChargeLimit;
	/*0x380*/     UINT64       CommitChargePeak;
	/*0x388*/     VOID*        AweInfo;
	/*0x390*/     SE_AUDIT_PROCESS_CREATION_INFO_SR SeAuditProcessCreationInfo; // 1 elements, 0x8 bytes (sizeof)     
	/*0x398*/     MMSUPPORT_SR Vm;                                              // 21 elements, 0x88 bytes (sizeof)   
	/*0x420*/     LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x10 bytes (sizeof)    
	/*0x430*/     VOID*        HighestUserAddress;
	/*0x438*/     ULONG32      ModifiedPageCount;
	union                                                              // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x43C*/         ULONG32      Flags2;
		struct																					// 20 elements, 0x4 bytes (sizeof)    
		{
			/*0x43C*/             ULONG32      JobNotReallyActive : 1;							// 0 BitPosition                      
			/*0x43C*/             ULONG32      AccountingFolded : 1;							// 1 BitPosition                      
			/*0x43C*/             ULONG32      NewProcessReported : 1;							// 2 BitPosition                      
			/*0x43C*/             ULONG32      ExitProcessReported : 1;							// 3 BitPosition                      
			/*0x43C*/             ULONG32      ReportCommitChanges : 1;							// 4 BitPosition                      
			/*0x43C*/             ULONG32      LastReportMemory : 1;							// 5 BitPosition                      
			/*0x43C*/             ULONG32      ReportPhysicalPageChanges : 1;					// 6 BitPosition                      
			/*0x43C*/             ULONG32      HandleTableRundown : 1;							// 7 BitPosition                      
			/*0x43C*/             ULONG32      NeedsHandleRundown : 1;							// 8 BitPosition                      
			/*0x43C*/             ULONG32      RefTraceEnabled : 1;								// 9 BitPosition                      
			/*0x43C*/             ULONG32      NumaAware : 1;									// 10 BitPosition                     
			/*0x43C*/             ULONG32      ProtectedProcess : 1;							// 11 BitPosition                     
			/*0x43C*/             ULONG32      DefaultPagePriority : 3;							// 12 BitPosition                     
			/*0x43C*/             ULONG32      PrimaryTokenFrozen : 1;							// 15 BitPosition                     
			/*0x43C*/             ULONG32      ProcessVerifierTarget : 1;						// 16 BitPosition                     
			/*0x43C*/             ULONG32      StackRandomizationDisabled : 1;					// 17 BitPosition                     
			/*0x43C*/             ULONG32      AffinityPermanent : 1;							// 18 BitPosition                     
			/*0x43C*/             ULONG32      AffinityUpdateEnable : 1;						// 19 BitPosition                     
			/*0x43C*/             ULONG32      PropagateNode : 1;								// 20 BitPosition                     
			/*0x43C*/             ULONG32      ExplicitAffinity : 1;							// 21 BitPosition                     
		};
	};
	union																						// 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x440*/         ULONG32      Flags;
		struct																					// 29 elements, 0x4 bytes (sizeof)    
		{
			/*0x440*/             ULONG32      CreateReported : 1;								// 0 BitPosition                      
			/*0x440*/             ULONG32      NoDebugInherit : 1;								// 1 BitPosition                      
			/*0x440*/             ULONG32      ProcessExiting : 1;								// 2 BitPosition                      
			/*0x440*/             ULONG32      ProcessDelete : 1;								// 3 BitPosition                      
			/*0x440*/             ULONG32      Wow64SplitPages : 1;								// 4 BitPosition                      
			/*0x440*/             ULONG32      VmDeleted : 1;									// 5 BitPosition                      
			/*0x440*/             ULONG32      OutswapEnabled : 1;								// 6 BitPosition                      
			/*0x440*/             ULONG32      Outswapped : 1;									// 7 BitPosition                      
			/*0x440*/             ULONG32      ForkFailed : 1;									// 8 BitPosition                      
			/*0x440*/             ULONG32      Wow64VaSpace4Gb : 1;								// 9 BitPosition                      
			/*0x440*/             ULONG32      AddressSpaceInitialized : 2;						// 10 BitPosition                     
			/*0x440*/             ULONG32      SetTimerResolution : 1;							// 12 BitPosition                     
			/*0x440*/             ULONG32      BreakOnTermination : 1;							// 13 BitPosition                     
			/*0x440*/             ULONG32      DeprioritizeViews : 1;							// 14 BitPosition                     
			/*0x440*/             ULONG32      WriteWatch : 1;									// 15 BitPosition                     
			/*0x440*/             ULONG32      ProcessInSession : 1;							// 16 BitPosition                     
			/*0x440*/             ULONG32      OverrideAddressSpace : 1;						// 17 BitPosition                     
			/*0x440*/             ULONG32      HasAddressSpace : 1;								// 18 BitPosition                     
			/*0x440*/             ULONG32      LaunchPrefetched : 1;							// 19 BitPosition                     
			/*0x440*/             ULONG32      InjectInpageErrors : 1;							// 20 BitPosition                     
			/*0x440*/             ULONG32      VmTopDown : 1;									// 21 BitPosition                     
			/*0x440*/             ULONG32      ImageNotifyDone : 1;								// 22 BitPosition                     
			/*0x440*/             ULONG32      PdeUpdateNeeded : 1;								// 23 BitPosition                     
			/*0x440*/             ULONG32      VdmAllowed : 1;									// 24 BitPosition                     
			/*0x440*/             ULONG32      CrossSessionCreate : 1;							// 25 BitPosition                     
			/*0x440*/             ULONG32      ProcessInserted : 1;								// 26 BitPosition                     
			/*0x440*/             ULONG32      DefaultIoPriority : 3;							// 27 BitPosition                     
			/*0x440*/             ULONG32      ProcessSelfDelete : 1;							// 30 BitPosition                     
			/*0x440*/             ULONG32      SetTimerResolutionLink : 1;						// 31 BitPosition                     
		};
	};
	/*0x444*/     LONG32       ExitStatus;
	/*0x448*/     MM_AVL_TABLE_SR VadRoot;														// 6 elements, 0x40 bytes (sizeof)    
	/*0x488*/     ALPC_PROCESS_CONTEXT_SR AlpcContext;											// 3 elements, 0x20 bytes (sizeof)    
	/*0x4A8*/     LIST_ENTRY TimerResolutionLink;												// 2 elements, 0x10 bytes (sizeof)    
	/*0x4B8*/     ULONG32      RequestedTimerResolution;
	/*0x4BC*/     ULONG32      ActiveThreadsHighWatermark;
	/*0x4C0*/     ULONG32      SmallestTimerResolution;
	/*0x4C4*/     UINT8        _PADDING0_[0x4];
	/*0x4C8*/     PO_DIAG_STACK_RECORD_SR* TimerResolutionStackRecord;
}EPROCESS_SR, *PEPROCESS_SR;

typedef struct _OBJECT_TYPE_INITIALIZER_SR														// 25 elements, 0x70 bytes (sizeof) 
{
	/*0x000*/     UINT16       Length;															//该结构体占用内存的大小
	union																						// 2 elements, 0x1 bytes (sizeof)   
	{
		/*0x002*/         UINT8        ObjectTypeFlags;
		struct																					// 7 elements, 0x1 bytes (sizeof)   
		{
			/*0x002*/             UINT8        CaseInsensitive : 1;								// 0 BitPosition                    
			/*0x002*/             UINT8        UnnamedObjectsOnly : 1;							// 1 BitPosition                    
			/*0x002*/             UINT8        UseDefaultObject : 1;							// 2 BitPosition                    
			/*0x002*/             UINT8        SecurityRequired : 1;							// 3 BitPosition                    
			/*0x002*/             UINT8        MaintainHandleCount : 1;							// 4 BitPosition                    
			/*0x002*/             UINT8        MaintainTypeList : 1;							// 5 BitPosition                    
			/*0x002*/             UINT8        SupportsObjectCallbacks : 1;						// 6 BitPosition                    
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     GENERIC_MAPPING GenericMapping;												// 4 elements, 0x10 bytes (sizeof)  
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     POOL_TYPE    PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     VOID*		   DumpProcedure;													//object hook function 
	/*0x038*/     VOID*		   OpenProcedure;													//object hook function 
	/*0x040*/     VOID*		   CloseProcedure;													//object hook function 
	/*0x048*/     VOID*		   DeleteProcedure;													//object hook function 
	/*0x050*/     VOID*		   ParseProcedure;													//object hook function 
	/*0x058*/     VOID*		   SecurityProcedure;												//object hook function 
	/*0x060*/     VOID*		   QueryNameProcedure;												//object hook function 
	/*0x068*/     VOID*		   OkayToCloseProcedure;											//object hook function 
}OBJECT_TYPE_INITIALIZER_SR, *POBJECT_TYPE_INITIALIZER_SR;

typedef struct _OBJECT_TYPE_SR																	// 12 elements, 0xD0 bytes (sizeof) 
{
	/*0x000*/     LIST_ENTRY TypeList;															// 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     UNICODE_STRING Name;															// 3 elements, 0x10 bytes (sizeof)	内核对象的名字  
	/*0x020*/     VOID*        DefaultObject;
	/*0x028*/     UINT8        Index;															// 内核对象的当前编号，任何对象的对象头都具有该index，可通过该值判断对象的类型
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;											//此类内核对象的总数
	/*0x030*/     ULONG32      TotalNumberOfHandles;											//此类内核对象的句柄总数
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x03C*/     UINT8        _PADDING1_[0x4];
	/*0x040*/     OBJECT_TYPE_INITIALIZER_SR TypeInfo;											// 25 elements, 0x70 bytes (sizeof) 
	/*0x0B0*/     EX_PUSH_LOCK TypeLock;														// 7 elements, 0x8 bytes (sizeof)   
	/*0x0B8*/     ULONG32      Key;
	/*0x0BC*/     UINT8        _PADDING2_[0x4];
	/*0x0C0*/     LIST_ENTRY CallbackList;														// 2 elements, 0x10 bytes (sizeof)  
}OBJECT_TYPE_SR, *POBJECT_TYPE_SR;

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













#endif
#endif

/*

debug port移位,注意需要修改debugobject的name信息。
eprocess+1f0=debug_port
可以移位到+2a0处


FFFFF800042265DD		DbgkCopyProcessDebugPort                    48 8B 9F		F0 01 00 00											mov     rbx, [rdi+1F0h]
反调试调用：
导出函数，内部没有任何引用，只做反调试用途
FFFFF8000424E410		PsIsProcessBeingDebugged                    48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
导出函数，内部也进行了使用在rtlheapxxx函数调用
FFFFF80004302883		DbgkOpenProcessDebugPort                    48 8B 9B		F0 01 00 00											mov     rbx, [rbx+1F0h]
明确需要修改的有31处：
FFFFF80004192DED		DbgkCopyProcessDebugPort                    48 83 A1		F0 01 00 00		00									and     qword ptr [rcx+1F0h], 0
FFFFF80004225ABC		PspProcessDelete                            48 83 A3		F0 01 00 00		00									and     qword ptr [rbx+1F0h], 0
FFFFF80004283493		DbgkClearProcessDebugObject                 48 83 A5		F0 01 00 00		00									and     qword ptr [rbp+1F0h], 0
FFFFF80004308ED8		DbgkpCloseObject                            48 83 A7		F0 01 00 00		00									and     qword ptr [rdi+1F0h], 0
FFFFF800041FFD81		DbgkMapViewOfSection                        48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
FFFFF80004302828		DbgkOpenProcessDebugPort                    48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
FFFFF800041B83FE		DbgkUnMapViewOfSection                      48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
FFFFF80003F1EEC5		KiDispatchException                         48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
FFFFF8000414D32E		ObpCloseHandleTableEntry                    48 83 B9		F0 01 00 00		00									cmp     qword ptr [rcx+1F0h], 0
FFFFF80004282A3A		DbgkExitThread                              48 83 BA		F0 01 00 00		00									cmp     qword ptr [rdx+1F0h], 0
FFFFF8000419BED8		PspTerminateAllThreads                      48 83 BF		F0 01 00 00		00									cmp     qword ptr [rdi+1F0h], 0
FFFFF800042829B7		DbgkExitProcess                             49 83 B8		F0 01 00 00		00                                  cmp     qword ptr [r8+1F0h], 0
FFFFF8000419A05A		ObpCloseHandle                              48 83 BD		F0 01 00 00		00									cmp     qword ptr [rbp+1F0h], 0
FFFFF80004009A05		FsRtlMdlReadCompleteDevEx                   48 89 95		F0 01 00 00											mov     [rbp+1F0h], rdx
FFFFF800042266E7		DbgkCopyProcessDebugPort                    48 89 9E		F0 01 00 00											mov     [rsi+1F0h], rbx
FFFFF8000423ED74		NtQueryInformationProcess                   48 8B 81		F0 01 00 00											mov     rax, [rcx+1F0h]
FFFFF80003F68300		PsGetProcessDebugPort                       48 8B 81		F0 01 00 00											mov     rax, [rcx+1F0h]
FFFFF8000419BB40		PspProcessDelete                            48 8B 8B		F0 01 00 00											mov     rcx, [rbx+1F0h]
FFFFF800041A86DE		DbgkForwardException                        48 8B 99		F0 01 00 00											mov     rbx, [rcx+1F0h]
FFFFF8000428347D		DbgkClearProcessDebugObject                 48 8B BD		F0 01 00 00											mov     rdi, [rbp+1F0h]
FFFFF80004282313		DbgkpQueueMessage                           49 8B BF		F0 01 00 00											mov     rdi, [r15+1F0h]
FFFFF80004192E0D		DbgkCopyProcessDebugPort                    4C 39 82		F0 01 00 00											cmp     [rdx+1F0h], r8
FFFFF8000432D7B2		DbgkpSetProcessDebugObject                  4C 39 A5		F0 01 00 00											cmp     [rbp+1F0h], r12
FFFFF8000432D7EF		DbgkpSetProcessDebugObject                  4C 89 A5		F0 01 00 00											mov     [rbp+1F0h], r12
FFFFF8000432D8E8		DbgkpSetProcessDebugObject                  4C 89 A5		F0 01 00 00											mov     [rbp+1F0h], r12
FFFFF8000432D7C7		DbgkpSetProcessDebugObject                  4C 89 AD		F0 01 00 00											mov     [rbp+1F0h], r13
FFFFF80004277BDB		DbgkpMarkProcessPeb                         48 39 8B		F0 01 00 00											cmp     [rbx+1F0h], rcx
FFFFF800041D351D		DbgkCreateThread                            48 39 9F		F0 01 00 00											cmp     [rdi+1F0h], rbx
FFFFF80004308E86		DbgkpCloseObject                            48 39 AF		F0 01 00 00											cmp     [rdi+1F0h], rbp
FFFFF80004308ECF		DbgkpCloseObject                            48 39 AF		F0 01 00 00											cmp     [rdi+1F0h], rbp
FFFFF800041B8C86		PspExitThread                               49 39 B4 24		F0 01 00 00                                         cmp     [r12+1F0h], rsi

一方面需要IDA帮助搜索，另一方面需要逐个下断点来确认,再者根据编程经验排除一部分搜索到的结果
*/