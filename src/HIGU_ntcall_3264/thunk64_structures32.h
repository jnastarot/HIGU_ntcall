

#pragma pack(push, 4)

typedef struct X32__UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	WOW64_POINTER(PWCH) Buffer;
} X32_UNICODE_STRING;

typedef struct X32__CLIENT_ID {
	X32_HANDLE UniqueProcess;
	X32_HANDLE UniqueThread;
} X32_CLIENT_ID;

typedef struct X32__IO_STATUS_BLOCK {
	union
	{
		NTSTATUS Status;
		X32_PVOID Pointer;
	};
	X32_ULONG_PTR Information;
} X32_IO_STATUS_BLOCK;

typedef struct X32__SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	X32_ULONG_PTR MinimumUserModeAddress;
	X32_ULONG_PTR MaximumUserModeAddress;
	X32_ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
};

typedef struct X32__SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	X32_PVOID StartAddress;
	X32_CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	KTHREAD_STATE ThreadState;
	KWAIT_REASON WaitReason;
} X32_SYSTEM_THREAD_INFORMATION;

typedef struct X32__SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	X32_UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	X32_HANDLE UniqueProcessId;
	X32_HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	X32_ULONG_PTR UniqueProcessKey;
	X32_SIZE_T PeakVirtualSize;
	X32_SIZE_T VirtualSize;
	ULONG PageFaultCount;
	X32_SIZE_T PeakWorkingSetSize;
	X32_SIZE_T WorkingSetSize;
	X32_SIZE_T QuotaPeakPagedPoolUsage;
	X32_SIZE_T QuotaPagedPoolUsage;
	X32_SIZE_T QuotaPeakNonPagedPoolUsage;
	X32_SIZE_T QuotaNonPagedPoolUsage;
	X32_SIZE_T PagefileUsage;
	X32_SIZE_T PeakPagefileUsage;
	X32_SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	X32_SYSTEM_THREAD_INFORMATION Threads[1];
};

typedef struct X32__SYSTEM_POOL_ENTRY {
	BOOLEAN Allocated;
	BOOLEAN Spare0;
	USHORT AllocatorBackTraceIndex;
	ULONG Size;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
		X32_PVOID ProcessChargedQuota;
	};
} X32_SYSTEM_POOL_ENTRY;

typedef struct X32__SYSTEM_POOL_INFORMATION {
	X32_SIZE_T TotalSize;
	X32_PVOID FirstEntry;
	USHORT EntryOverhead;
	BOOLEAN PoolTagPresent;
	BOOLEAN Spare0;
	ULONG NumberOfEntries;
	X32_SYSTEM_POOL_ENTRY Entries[1];
};

typedef struct X32__SYSTEM_PAGEFILE_INFORMATION {
	ULONG NextEntryOffset;
	ULONG TotalSize;
	ULONG TotalInUse;
	ULONG PeakUsage;
	X32_UNICODE_STRING PageFileName;
};

typedef struct X32__SYSTEM_FILECACHE_INFORMATION {
	X32_SIZE_T CurrentSize;
	X32_SIZE_T PeakSize;
	ULONG PageFaultCount;
	X32_SIZE_T MinimumWorkingSet;
	X32_SIZE_T MaximumWorkingSet;
	X32_SIZE_T CurrentSizeIncludingTransitionInPages;
	X32_SIZE_T PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
};

typedef struct X32__SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	X32_SIZE_T PagedPoolSize;
};

typedef struct X32__SYSTEM_LEGACY_DRIVER_INFORMATION {
	ULONG VetoType;
	X32_UNICODE_STRING VetoList;
};

typedef struct X32__SYSTEM_VERIFIER_INFORMATION {
	ULONG NextEntryOffset;
	ULONG Level;
	ULONG RuleClasses[2];
	ULONG TriageContext;
	ULONG AreAllDriversBeingVerified;
	X32_UNICODE_STRING DriverName;
	ULONG RaiseIrqls;
	ULONG AcquireSpinLocks;
	ULONG SynchronizeExecutions;
	ULONG AllocationsAttempted;
	ULONG AllocationsSucceeded;
	ULONG AllocationsSucceededSpecialPool;
	ULONG AllocationsWithNoTag;
	ULONG TrimRequests;
	ULONG Trims;
	ULONG AllocationsFailed;
	ULONG AllocationsFailedDeliberately;
	ULONG Loads;
	ULONG Unloads;
	ULONG UnTrackedPool;
	ULONG CurrentPagedPoolAllocations;
	ULONG CurrentNonPagedPoolAllocations;
	ULONG PeakPagedPoolAllocations;
	ULONG PeakNonPagedPoolAllocations;
	X32_SIZE_T PagedPoolUsageInBytes;
	X32_SIZE_T NonPagedPoolUsageInBytes;
	X32_SIZE_T PeakPagedPoolUsageInBytes;
	X32_SIZE_T PeakNonPagedPoolUsageInBytes;
};

typedef struct X32__SYSTEM_SESSION_PROCESS_INFORMATION {
	ULONG SessionId;
	ULONG SizeOfBuf;
	X32_PVOID Buffer;
};

typedef struct X32__SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	X32_PVOID Object;
	X32_ULONG_PTR UniqueProcessId;
	X32_ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} X32_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct X32__SYSTEM_HANDLE_INFORMATION_EX {
	X32_ULONG_PTR NumberOfHandles;
	X32_ULONG_PTR Reserved;
	X32_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

typedef struct X32__SYSTEM_POOLTAG {
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	X32_SIZE_T PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	X32_SIZE_T NonPagedUsed;
} X32_SYSTEM_POOLTAG;

typedef struct X32__SYSTEM_SESSION_POOLTAG_INFORMATION {
	X32_SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG Count;
	X32_SYSTEM_POOLTAG TagInfo[1];
};

typedef struct X32__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION {
	X32_SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG ViewFailures;
	X32_SIZE_T NumberOfBytesAvailable;
	X32_SIZE_T NumberOfBytesAvailableContiguous;
};

typedef struct X32__SYSTEM_FIRMWARE_TABLE_HANDLER {
	ULONG ProviderSignature;
	BOOLEAN Register;
	WOW64_POINTER(PFNFTH) FirmwareTableHandler;
	X32_PVOID DriverObject;
};

typedef struct X32__RTL_PROCESS_MODULE_INFORMATION {
	X32_HANDLE Section;
	X32_PVOID MappedBase;
	X32_PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} X32_RTL_PROCESS_MODULE_INFORMATION;

typedef struct X32__RTL_PROCESS_MODULE_INFORMATION_EX {
	USHORT NextOffset;
	X32_RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	X32_PVOID DefaultBase;
};

typedef struct X32__SUPERFETCH_INFORMATION {
	ULONG Version;
	ULONG Magic;
	SUPERFETCH_INFORMATION_CLASS InfoClass;
	X32_PVOID Data;
	ULONG Length;
};

typedef struct X32__SYSTEM_MEMORY_LIST_INFORMATION {
	X32_ULONG_PTR ZeroPageCount;
	X32_ULONG_PTR FreePageCount;
	X32_ULONG_PTR ModifiedPageCount;
	X32_ULONG_PTR ModifiedNoWritePageCount;
	X32_ULONG_PTR BadPageCount;
	X32_ULONG_PTR PageCountByPriority[8];
	X32_ULONG_PTR RepurposedPagesByPriority[8];
	X32_ULONG_PTR ModifiedPageCountPageFile;
};

typedef struct X32__SYSTEM_REF_TRACE_INFORMATION {
	BOOLEAN TraceEnable;
	BOOLEAN TracePermanent;
	X32_UNICODE_STRING TraceProcessName;
	X32_UNICODE_STRING TracePoolTags;
};

typedef struct X32__SYSTEM_PROCESS_ID_INFORMATION {
	X32_HANDLE ProcessId;
	X32_UNICODE_STRING ImageName;
};

typedef struct X32__SYSTEM_VERIFIER_INFORMATION_EX {
	ULONG VerifyMode;
	ULONG OptionChanges;
	X32_UNICODE_STRING PreviousBucketName;
	ULONG IrpCancelTimeoutMsec;
	ULONG VerifierExtensionEnabled;
	ULONG Reserved[3];
};

typedef struct X32__SYSTEM_SYSTEM_PARTITION_INFORMATION {
	X32_UNICODE_STRING SystemPartition;
};

typedef struct X32__SYSTEM_SYSTEM_DISK_INFORMATION {
	X32_UNICODE_STRING SystemDisk;
};

typedef struct X32__SYSTEM_BASIC_PERFORMANCE_INFORMATION {
	X32_SIZE_T AvailablePages;
	X32_SIZE_T CommittedPages;
	X32_SIZE_T CommitLimit;
	X32_SIZE_T PeakCommitment;
};

typedef struct X32__SYSTEM_POLICY_INFORMATION {
	X32_PVOID InputData;
	X32_PVOID OutputData;
	ULONG InputDataSize;
	ULONG OutputDataSize;
	ULONG Version;
};

typedef struct X32__SYSTEM_MANUFACTURING_INFORMATION {
	ULONG Options;
	X32_UNICODE_STRING ProfileName;
};

typedef struct X32__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS {
	X32_HANDLE UserKeyHandle;
};

typedef struct X32__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION {
	X32_PVOID HypervisorSharedUserVa;
};

typedef struct X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
	X32_ULONG_PTR ProcessorMask;
	LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
	union {
		struct {
			BYTE  Flags;
		} ProcessorCore;
		struct {
			DWORD NodeNumber;
		} NumaNode;
		CACHE_DESCRIPTOR Cache;
		ULONGLONG  Reserved[2];
	};
};

typedef struct X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX {
	LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
	DWORD Size;
	/*
	union {
		PROCESSOR_RELATIONSHIP Processor;
		NUMA_NODE_RELATIONSHIP NumaNode;
		CACHE_RELATIONSHIP Cache;
		GROUP_RELATIONSHIP Group;
	} DUMMYUNIONNAME;
	*/
};

typedef struct X32__SYSTEM_FEATURE_CONFIGURATION_INFORMATION {
	ULONGLONG ChangeStamp;
	WOW64_POINTER(_RTL_FEATURE_CONFIGURATION*) Configuration;
};

typedef struct X32__SYSTEM_THREAD_CID_PRIORITY_INFORMATION {
	X32_CLIENT_ID ClientId;
	KPRIORITY Priority;
};

typedef struct X32__SYSTEM_VERIFIER_FAULTS_INFORMATION {
	ULONG Probability;
	ULONG MaxProbability;
	X32_UNICODE_STRING PoolTags;
	X32_UNICODE_STRING Applications;
};

typedef struct X32__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS {
	X32_HANDLE KeyHandle;
	WOW64_POINTER(X32_UNICODE_STRING*) ValueNamePointer;
	WOW64_POINTER(PULONG) RequiredLengthPointer;
	WOW64_POINTER(PUCHAR) Buffer;
	ULONG BufferLength;
	ULONG Type;
	WOW64_POINTER(PUCHAR) AppendBuffer;
	ULONG AppendBufferLength;
	BOOLEAN CreateIfDoesntExist;
	BOOLEAN TruncateExistingValue;
};

typedef struct X32__SYSTEM_ELAM_CERTIFICATE_INFORMATION {
	X32_HANDLE ElamDriverFile;
};

typedef struct X32__SYSTEM_ACTIVITY_MODERATION_EXE_STATE {
	X32_UNICODE_STRING ExePathNt;
	SYSTEM_ACTIVITY_MODERATION_STATE ModerationState;
};

typedef struct X32__MEMORY_BASIC_INFORMATION {
	X32_PVOID BaseAddress;
	X32_PVOID AllocationBase;
	DWORD AllocationProtect;
	X32_SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
};

typedef struct X32__MEMORY_WORKING_SET_BLOCK {
	X32_ULONG_PTR Protection : 5;
	X32_ULONG_PTR ShareCount : 3;
	X32_ULONG_PTR Shared : 1;
	X32_ULONG_PTR Node : 3;
	ULONG VirtualPage : 20;
} X32_MEMORY_WORKING_SET_BLOCK;

typedef struct X32__MEMORY_WORKING_SET_INFORMATION {
	X32_ULONG_PTR NumberOfEntries;
	X32_MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
};

typedef struct X32__MEMORY_REGION_INFORMATION {
	X32_PVOID AllocationBase;
	ULONG AllocationProtect;
	union
	{
		ULONG RegionType;
		struct
		{
			ULONG Private : 1;
			ULONG MappedDataFile : 1;
			ULONG MappedImage : 1;
			ULONG MappedPageFile : 1;
			ULONG MappedPhysical : 1;
			ULONG DirectMapped : 1;
			ULONG SoftwareEnclave : 1; // REDSTONE3
			ULONG PageSize64K : 1;
			ULONG PlaceholderReservation : 1; // REDSTONE4
			ULONG Reserved : 23;
		};
	};
	X32_SIZE_T RegionSize;
	X32_SIZE_T CommitSize;
	X32_ULONG_PTR PartitionId;
};

typedef struct X32__MEMORY_WORKING_SET_EX_INFORMATION {
	X32_PVOID VirtualAddress;
	union
	{
		ULONG /*MEMORY_WORKING_SET_EX_BLOCK*/ VirtualAttributes;
		X32_ULONG_PTR Long;
	} u1;
};

typedef struct X32__SECTION_BASIC_INFORMATION {
	X32_PVOID BaseAddress;
	ULONG AllocationAttributes;
	LARGE_INTEGER MaximumSize;
};

typedef struct X32__SECTION_IMAGE_INFORMATION {
	X32_PVOID TransferAddress;
	ULONG ZeroBits;
	X32_SIZE_T MaximumStackSize;
	X32_SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	union
	{
		struct
		{
			USHORT MajorOperatingSystemVersion;
			USHORT MinorOperatingSystemVersion;
		};
		ULONG OperatingSystemVersion;
	};
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR ComPlusPrefer32bit : 1;
			UCHAR Reserved : 2;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
};

typedef struct X32__OBJECT_NAME_INFORMATION {
	X32_UNICODE_STRING Name;
};

typedef struct X32__OBJECT_TYPE_INFORMATION {
	X32_UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
};

typedef struct X32__PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	WOW64_POINTER(X32_PPEB) PebBaseAddress;
	X32_ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	X32_HANDLE UniqueProcessId;
	X32_HANDLE InheritedFromUniqueProcessId;
};

typedef struct X32__QUOTA_LIMITS {
	X32_SIZE_T PagedPoolLimit;
	X32_SIZE_T NonPagedPoolLimit;
	X32_SIZE_T MinimumWorkingSetSize;
	X32_SIZE_T MaximumWorkingSetSize;
	X32_SIZE_T PagefileLimit;
	LARGE_INTEGER TimeLimit;
};

typedef struct X32__VM_COUNTERS {
	X32_SIZE_T PeakVirtualSize;
	X32_SIZE_T VirtualSize;
	ULONG PageFaultCount;
	X32_SIZE_T PeakWorkingSetSize;
	X32_SIZE_T WorkingSetSize;
	X32_SIZE_T QuotaPeakPagedPoolUsage;
	X32_SIZE_T QuotaPagedPoolUsage;
	X32_SIZE_T QuotaPeakNonPagedPoolUsage;
	X32_SIZE_T QuotaNonPagedPoolUsage;
	X32_SIZE_T PagefileUsage;
	X32_SIZE_T PeakPagefileUsage;
};

typedef struct X32__POOLED_USAGE_AND_LIMITS {
	X32_SIZE_T PeakPagedPoolUsage;
	X32_SIZE_T PagedPoolUsage;
	X32_SIZE_T PagedPoolLimit;
	X32_SIZE_T PeakNonPagedPoolUsage;
	X32_SIZE_T NonPagedPoolUsage;
	X32_SIZE_T NonPagedPoolLimit;
	X32_SIZE_T PeakPagefileUsage;
	X32_SIZE_T PagefileUsage;
	X32_SIZE_T PagefileLimit;
};

typedef struct X32__PROCESS_WS_WATCH_INFORMATION {
	X32_PVOID FaultingPc;
	X32_PVOID FaultingVa;
} X32_PROCESS_WS_WATCH_INFORMATION;

typedef struct X32__PROCESS_DEVICEMAP_INFORMATION {
	union
	{
		struct
		{
			X32_HANDLE DirectoryHandle;
		} Set;
		struct
		{
			ULONG DriveMap;
			UCHAR DriveType[32];
		} Query;
	};
};

typedef struct X32__PROCESS_HANDLE_TRACING_ENTRY {
	X32_HANDLE Handle;
	X32_CLIENT_ID ClientId;
	ULONG Type;
	X32_PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} X32_PROCESS_HANDLE_TRACING_ENTRY;

typedef struct X32__PROCESS_HANDLE_TRACING_QUERY {
	X32_HANDLE Handle;
	ULONG TotalTraces;
	X32_PROCESS_HANDLE_TRACING_ENTRY HandleTrace[1];
};

typedef struct X32__PROCESS_WS_WATCH_INFORMATION_EX {
	X32_PROCESS_WS_WATCH_INFORMATION BasicInfo;
	X32_ULONG_PTR FaultingThreadId;
	X32_ULONG_PTR Flags;
};

typedef struct X32__PROCESS_HANDLE_TABLE_ENTRY_INFO {
	X32_HANDLE HandleValue;
	X32_ULONG_PTR HandleCount;
	X32_ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} X32_PROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct X32__PROCESS_HANDLE_SNAPSHOT_INFORMATION {
	X32_ULONG_PTR NumberOfHandles;
	X32_ULONG_PTR Reserved;
	X32_PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

typedef struct X32__PROCESS_EXCEPTION_PORT {
	X32_HANDLE ExceptionPortHandle;
	ULONG StateFlags;
};

typedef struct X32__PROCESS_ACCESS_TOKEN {
	X32_HANDLE Token;
	X32_HANDLE Thread;
};

typedef struct X32__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
	ULONG Version;
	ULONG Reserved;
	X32_PVOID Callback;
};

typedef struct X32__PROCESS_STACK_ALLOCATION_INFORMATION {
	X32_SIZE_T ReserveSize;
	X32_SIZE_T ZeroBits;
	X32_PVOID StackBase;
};

typedef struct X32__PROCESS_MEMORY_EXHAUSTION_INFO {
	USHORT Version;
	USHORT Reserved;
	PROCESS_MEMORY_EXHAUSTION_TYPE Type;
	X32_ULONG_PTR Value;
};

typedef struct X32__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION {
	X32_HANDLE ProcessHandle;
};

typedef struct X32__THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	WOW64_POINTER(X32_PTEB) TebBaseAddress;
	X32_CLIENT_ID ClientId;
	X32_ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
};

typedef struct X32__THREAD_LAST_SYSCALL_INFORMATION {
	X32_PVOID FirstArgument;
	USHORT SystemCallNumber;
	USHORT Pad[1];
	ULONG64 WaitTime;
};

typedef struct X32__THREAD_TEB_INFORMATION {
	X32_PVOID TebInformation;
	ULONG TebOffset;
	ULONG BytesToRead;
};

typedef struct X32__GROUP_AFFINITY {
	X32_KAFFINITY Mask;
	USHORT Group;
	USHORT Reserved[3];
};

typedef struct X32__THREAD_PROFILING_INFORMATION {
	ULONG64 HardwareCounters;
	ULONG Flags;
	ULONG Enable;
	WOW64_POINTER(PTHREAD_PERFORMANCE_DATA) PerformanceData;
};

typedef struct X32__THREAD_NAME_INFORMATION {
	X32_UNICODE_STRING ThreadName;
};

typedef struct X32__FILE_RENAME_INFORMATION {
	BOOLEAN ReplaceIfExists;
	X32_HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
};

typedef struct X32__FILE_LINK_INFORMATION {
	BOOLEAN ReplaceIfExists;
	X32_HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
};

typedef struct X32__FILE_MAILSLOT_SET_INFORMATION {
	WOW64_POINTER(PLARGE_INTEGER) ReadTimeout;
};

typedef struct X32__FILE_COMPLETION_INFORMATION {
	X32_HANDLE Port;
	X32_PVOID Key;
};

typedef struct X32__FILE_MOVE_CLUSTER_INFORMATION {
	ULONG ClusterCount;
	X32_HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
};

typedef struct X32__FILE_TRACKING_INFORMATION {
	X32_HANDLE DestinationFile;
	ULONG ObjectInformationLength;
	CHAR ObjectInformation[1];
};

typedef struct X32__FILE_IOSTATUSBLOCK_RANGE_INFORMATION {
	WOW64_POINTER(PUCHAR) IoStatusBlockRange;
	ULONG Length;
};

typedef struct X32__FILE_RENAME_INFORMATION_EX {
	ULONG Flags;
	X32_HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
};

typedef struct X32__FILE_MEMORY_PARTITION_INFORMATION {
	X32_HANDLE OwnerPartitionHandle;
	union
	{
		struct
		{
			UCHAR NoCrossPartitionAccess;
			UCHAR Spare[3];
		};
		ULONG AllFlags;
	} Flags;
};

typedef struct X32__FILE_LINK_INFORMATION_EX {
	ULONG Flags;
	X32_HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
};

typedef struct X32__ALPC_BASIC_INFORMATION {
	ULONG Flags;
	ULONG SequenceNo;
	X32_PVOID PortContext;
};

typedef struct X32__ALPC_SERVER_INFORMATION {
	union
	{
		struct
		{
			X32_HANDLE ThreadHandle;
		} In;
		struct
		{
			BOOLEAN ThreadBlocked;
			X32_HANDLE ConnectedProcessId;
			X32_UNICODE_STRING ConnectionPortName;
		} Out;
	};
};

typedef struct X32__ALPC_PORT_ATTRIBUTES {
	ULONG Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	X32_SIZE_T MaxMessageLength;
	X32_SIZE_T MemoryBandwidth;
	X32_SIZE_T MaxPoolUsage;
	X32_SIZE_T MaxSectionSize;
	X32_SIZE_T MaxViewSize;
	X32_SIZE_T MaxTotalSectionSize;
	ULONG DupObjectTypes;
	ULONG Reserved;
};

typedef struct X32__ALPC_PORT_ASSOCIATE_COMPLETION_PORT {
	X32_PVOID CompletionKey;
	X32_HANDLE CompletionPort;
};

typedef struct X32__ALPC_PORT_MESSAGE_ZONE_INFORMATION {
	X32_PVOID Buffer;
	ULONG Size;
};

typedef struct X32__ALPC_PORT_COMPLETION_LIST_INFORMATION {
	X32_PVOID Buffer;
	ULONG Size;
	ULONG ConcurrencyCount;
	ULONG AttributeFlags;
};

typedef struct X32_MEM_EXTENDED_PARAMETER {
	struct {
		DWORD64 Type : MEM_EXTENDED_PARAMETER_TYPE_BITS;
		DWORD64 Reserved : 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
	};

	union {
		DWORD64 ULong64;
		X32_PVOID Pointer;
		X32_SIZE_T Size;
		X32_HANDLE Handle;
		DWORD ULong;
	};
};

typedef struct X32__OBJECT_ATTRIBUTES {
	ULONG Length;
	X32_HANDLE RootDirectory;
	WOW64_POINTER(X32_UNICODE_STRING*) ObjectName;
	ULONG Attributes;
	X32_PVOID SecurityDescriptor;
	X32_PVOID SecurityQualityOfService;
};

typedef struct X32__FILE_IO_COMPLETION_INFORMATION {
	X32_PVOID KeyContext;
	X32_PVOID ApcContext;
	X32_IO_STATUS_BLOCK IoStatusBlock;
};

typedef struct X32__MEMORY_RANGE_ENTRY {
	X32_PVOID VirtualAddress;
	X32_SIZE_T NumberOfBytes;
};

typedef struct X32__INITIAL_TEB {
	struct {
		X32_PVOID OldStackBase;
		X32_PVOID OldStackLimit;
	} OldInitialTeb;
	X32_PVOID StackBase;
	X32_PVOID StackLimit;
	X32_PVOID StackAllocationBase;
};

typedef struct X32__PS_CREATE_INFO {
	X32_SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct
		{
			X32_HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct
		{
			X32_HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			X32_HANDLE FileHandle;
			X32_HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
};

typedef struct X32__PS_ATTRIBUTE {
	X32_ULONG_PTR Attribute;
	X32_SIZE_T Size;
	union {
		X32_ULONG_PTR Value;
		X32_PVOID ValuePtr;
	};

	WOW64_POINTER(X32_SIZE_T*) ReturnLength;
} X32_PS_ATTRIBUTE;

typedef struct X32__PS_ATTRIBUTE_LIST {
	X32_SIZE_T TotalLength;
	X32_PS_ATTRIBUTE Attributes[1];
};

typedef struct X32__JOB_SET_ARRAY {
	X32_HANDLE JobHandle;
	DWORD MemberLevel;
	DWORD Flags;
};

typedef struct X32__DBGUI_WAIT_STATE_CHANGE {
	DBG_STATE NewState;
	X32_CLIENT_ID AppClientId;
//#pragma error('Here Ignored union fix it')
//	X32__DBGUI_WAIT_STATE_CHANGE StateInfo;
};

typedef struct X32__FILE_SEGMENT_ELEMENT {
	PVOID64 Buffer;
	ULONGLONG Alignment;
};

typedef struct X32__PORT_VIEW {
	ULONG Length;
	X32_HANDLE SectionHandle;
	ULONG SectionOffset;
	X32_SIZE_T ViewSize;
	X32_PVOID ViewBase;
	X32_PVOID ViewRemoteBase;
};

typedef struct X32__REMOTE_PORT_VIEW {
	ULONG Length;
	X32_SIZE_T ViewSize;
	X32_PVOID ViewBase;
};

typedef struct X32__PORT_MESSAGE {
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		X32_CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		X32_SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
};

typedef struct X32__ALPC_DATA_VIEW_ATTR {
	ULONG Flags;
	X32_ALPC_HANDLE SectionHandle;
	X32_PVOID ViewBase;
	X32_SIZE_T ViewSize;
};

typedef struct X32__ALPC_SECURITY_ATTR {
	ULONG Flags;
	WOW64_POINTER(PSECURITY_QUALITY_OF_SERVICE) QoS;
	X32_ALPC_HANDLE ContextHandle;
};

typedef struct X32__ALPC_CONTEXT_ATTR {
	X32_PVOID PortContext;
	X32_PVOID MessageContext;
	ULONG Sequence;
	ULONG MessageId;
	ULONG CallbackId;
};

typedef struct X32__KEY_VALUE_ENTRY {
	WOW64_POINTER(X32_UNICODE_STRING*) ValueName;
	ULONG DataLength;
	ULONG DataOffset;
	ULONG Type;
};

typedef struct X32__SID_AND_ATTRIBUTES {
	X32_PSID Sid;
	DWORD Attributes;
} X32_SID_AND_ATTRIBUTES;

typedef struct X32__TOKEN_USER {
	X32_SID_AND_ATTRIBUTES User;
};

typedef struct X32__TOKEN_GROUPS {
	DWORD GroupCount;
	X32_SID_AND_ATTRIBUTES Groups[1];
};

typedef struct X32__TOKEN_OWNER {
	X32_PSID Owner;
};

typedef struct X32__TOKEN_PRIMARY_GROUP {
	X32_PSID PrimaryGroup;
};

typedef struct X32__TOKEN_DEFAULT_DACL {
	WOW64_POINTER(PACL) DefaultDacl;
};

typedef struct X32__TOKEN_SECURITY_ATTRIBUTES_INFORMATION {
	USHORT Version;
	USHORT Reserved;
	ULONG AttributeCount;
	union {
		WOW64_POINTER(PTOKEN_SECURITY_ATTRIBUTE_V1) pAttributeV1;
	} Attribute;
};

typedef struct X32__OBJECT_TYPE_LIST {
	WORD Level;
	WORD Sbz;
	WOW64_POINTER(GUID*) ObjectType;
};

typedef struct X32__TRANSACTION_NOTIFICATION {
	X32_PVOID TransactionKey;
	ULONG TransactionNotification;
	LARGE_INTEGER TmVirtualClock;
	ULONG ArgumentLength;
};

typedef struct X32__EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	WOW64_POINTER(X32__EXCEPTION_RECORD*) ExceptionRecord;
	X32_PVOID ExceptionAddress;
	DWORD NumberParameters;
	X32_ULONG_PTR ExceptionInformation[15];
};


#pragma pack(pop)