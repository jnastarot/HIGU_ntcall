
#pragma warning(push)
#pragma warning(disable: 4244)


#define NESTED_CVT_64TO32(type, var_name) \
	{\
		convert_##type##_64TO32(ctx, &ptr64->##var_name, (uint32_t)&x32_used_ptr->##var_name);\
	}

#define CVT_COPY_STRING(type, var_name, var_len_name) __movsb((PBYTE)&x32_used_ptr->##var_name[0], (PBYTE)&(*ptr64)->##var_name[0], x32_used_ptr->##var_len_name);

#define CVT_UNICODE_STRING_OFFSETABLE(base_name, var_name) \
	{\
		convert__UNICODE_STRING_64TO32(ctx, &(ptr64)->##var_name, (uint32_t)&x32_used_ptr->##var_name);\
		x32_used_ptr->##var_name.Buffer = (ULONG)ptr32 + (((uint64_t)(ptr64)->##var_name.Buffer) - ((uint64_t)base_name));\
		__movsb((PBYTE)x32_used_ptr->##var_name.Buffer, (PBYTE)&(ptr64)->##var_name.Buffer[0], (ptr64)->##var_name.Length);\
	}

#define CVT_UNICODE_STRING_OFFSETABLE_FUNC64TO32(ptr64, ptr32) \
	{\
		convert__UNICODE_STRING_64TO32(ctx, ptr64, (uint32_t)ptr32);\
		((X32__UNICODE_STRING*)ptr32)->Buffer = (ULONG)ptr32 + (((uint64_t)(ptr64)->Buffer) - ((uint64_t)ptr64));\
		__movsb((PBYTE)((X32__UNICODE_STRING*)ptr32)->Buffer, (PBYTE)&(ptr64)->Buffer[0], (ptr64)->Length);\
	}

void convert__SYSTEM_BASIC_INFORMATION_64TO32(void* ctx, _SYSTEM_BASIC_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_PROCESS_INFORMATION_64TO32(void* ctx, _SYSTEM_PROCESS_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_POOL_INFORMATION_64TO32(void* ctx, _SYSTEM_POOL_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_PAGEFILE_INFORMATION_64TO32(void* ctx, _SYSTEM_PAGEFILE_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_FILECACHE_INFORMATION_64TO32(void* ctx, _SYSTEM_FILECACHE_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_64TO32(void* ctx, _SYSTEM_REGISTRY_QUOTA_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_LEGACY_DRIVER_INFORMATION_64TO32(void* ctx, _SYSTEM_LEGACY_DRIVER_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_VERIFIER_INFORMATION_64TO32(void* ctx, _SYSTEM_VERIFIER_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_SESSION_PROCESS_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_PROCESS_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_HANDLE_INFORMATION_EX_64TO32(void* ctx, _SYSTEM_HANDLE_INFORMATION_EX*, uint32_t ptr32);
void convert__SYSTEM_SESSION_POOLTAG_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_POOLTAG_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_FIRMWARE_TABLE_HANDLER_64TO32(void* ctx, _SYSTEM_FIRMWARE_TABLE_HANDLER*, uint32_t ptr32);
void convert__RTL_PROCESS_MODULE_INFORMATION_EX_64TO32(void* ctx, _RTL_PROCESS_MODULE_INFORMATION_EX*, uint32_t ptr32);
void convert__SUPERFETCH_INFORMATION_64TO32(void* ctx, _SUPERFETCH_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_MEMORY_LIST_INFORMATION_64TO32(void* ctx, _SYSTEM_MEMORY_LIST_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_REF_TRACE_INFORMATION_64TO32(void* ctx, _SYSTEM_REF_TRACE_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_PROCESS_ID_INFORMATION_64TO32(void* ctx, _SYSTEM_PROCESS_ID_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_VERIFIER_INFORMATION_EX_64TO32(void* ctx, _SYSTEM_VERIFIER_INFORMATION_EX*, uint32_t ptr32);
void convert__SYSTEM_SYSTEM_PARTITION_INFORMATION_64TO32(void* ctx, _SYSTEM_SYSTEM_PARTITION_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_SYSTEM_DISK_INFORMATION_64TO32(void* ctx, _SYSTEM_SYSTEM_DISK_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_BASIC_PERFORMANCE_INFORMATION_64TO32(void* ctx, _SYSTEM_BASIC_PERFORMANCE_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_POLICY_INFORMATION_64TO32(void* ctx, _SYSTEM_POLICY_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_MANUFACTURING_INFORMATION_64TO32(void* ctx, _SYSTEM_MANUFACTURING_INFORMATION*, uint32_t ptr32);
void convert__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS_64TO32(void* ctx, _SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS*, uint32_t ptr32);
void convert__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION_64TO32(void* ctx, _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION*, uint32_t ptr32);
void convert__UNICODE_STRING_64TO32(void* ctx, _UNICODE_STRING*, uint32_t ptr32);
void convert__MEMORY_BASIC_INFORMATION_64TO32(void* ctx, _MEMORY_BASIC_INFORMATION*, uint32_t ptr32);
void convert__MEMORY_WORKING_SET_INFORMATION_64TO32(void* ctx, _MEMORY_WORKING_SET_INFORMATION*, uint32_t ptr32);
void convert__MEMORY_REGION_INFORMATION_64TO32(void* ctx, _MEMORY_REGION_INFORMATION*, uint32_t ptr32);
void convert__MEMORY_WORKING_SET_EX_INFORMATION_64TO32(void* ctx, _MEMORY_WORKING_SET_EX_INFORMATION*, uint32_t ptr32);
void convert__SECTION_BASIC_INFORMATION_64TO32(void* ctx, _SECTION_BASIC_INFORMATION*, uint32_t ptr32);
void convert__SECTION_IMAGE_INFORMATION_64TO32(void* ctx, _SECTION_IMAGE_INFORMATION*, uint32_t ptr32);
void convert__OBJECT_NAME_INFORMATION_64TO32(void* ctx, _OBJECT_NAME_INFORMATION*, uint32_t ptr32);
void convert__OBJECT_TYPE_INFORMATION_64TO32(void* ctx, _OBJECT_TYPE_INFORMATION*, uint32_t ptr32);
void convert__PROCESS_BASIC_INFORMATION_64TO32(void* ctx, _PROCESS_BASIC_INFORMATION*, uint32_t ptr32);
void convert__QUOTA_LIMITS_64TO32(void* ctx, _QUOTA_LIMITS*, uint32_t ptr32);
void convert__VM_COUNTERS_64TO32(void* ctx, _VM_COUNTERS*, uint32_t ptr32);
void convert__POOLED_USAGE_AND_LIMITS_64TO32(void* ctx, _POOLED_USAGE_AND_LIMITS*, uint32_t ptr32);
void convert__PROCESS_WS_WATCH_INFORMATION_64TO32(void* ctx, _PROCESS_WS_WATCH_INFORMATION*, uint32_t ptr32);
void convert__PROCESS_DEVICEMAP_INFORMATION_64TO32(void* ctx, _PROCESS_DEVICEMAP_INFORMATION*, uint32_t ptr32);
void convert__PROCESS_HANDLE_TRACING_QUERY_64TO32(void* ctx, _PROCESS_HANDLE_TRACING_QUERY*, uint32_t ptr32);
void convert__PROCESS_WS_WATCH_INFORMATION_EX_64TO32(void* ctx, _PROCESS_WS_WATCH_INFORMATION_EX*, uint32_t ptr32);
void convert__PROCESS_HANDLE_SNAPSHOT_INFORMATION_64TO32(void* ctx, _PROCESS_HANDLE_SNAPSHOT_INFORMATION*, uint32_t ptr32);
void convert__THREAD_BASIC_INFORMATION_64TO32(void* ctx, _THREAD_BASIC_INFORMATION*, uint32_t ptr32);
void convert__THREAD_LAST_SYSCALL_INFORMATION_64TO32(void* ctx, _THREAD_LAST_SYSCALL_INFORMATION*, uint32_t ptr32);
void convert__THREAD_TEB_INFORMATION_64TO32(void* ctx, _THREAD_TEB_INFORMATION*, uint32_t ptr32);
void convert__GROUP_AFFINITY_64TO32(void* ctx, _GROUP_AFFINITY*, uint32_t ptr32);
void convert__THREAD_PROFILING_INFORMATION_64TO32(void* ctx, _THREAD_PROFILING_INFORMATION*, uint32_t ptr32);
void convert__THREAD_NAME_INFORMATION_64TO32(void* ctx, _THREAD_NAME_INFORMATION*, uint32_t ptr32);
void convert__ALPC_BASIC_INFORMATION_64TO32(void* ctx, _ALPC_BASIC_INFORMATION*, uint32_t ptr32);
void convert__ALPC_SERVER_INFORMATION_64TO32(void* ctx, _ALPC_SERVER_INFORMATION*, uint32_t ptr32);
void convert_MEM_EXTENDED_PARAMETER_64TO32(void* ctx, MEM_EXTENDED_PARAMETER*, uint32_t ptr32);
void convert_HANDLE_64TO32(void* ctx, HANDLE*, uint32_t ptr32);
void convert__FILE_IO_COMPLETION_INFORMATION_64TO32(void* ctx, _FILE_IO_COMPLETION_INFORMATION*, uint32_t ptr32);
void convert__CLIENT_ID_64TO32(void* ctx, _CLIENT_ID*, uint32_t ptr32);
void convert__PS_CREATE_INFO_64TO32(void* ctx, _PS_CREATE_INFO*, uint32_t ptr32);
void convert__DBGUI_WAIT_STATE_CHANGE_64TO32(void* ctx, _DBGUI_WAIT_STATE_CHANGE*, uint32_t ptr32);
void convert__IO_STATUS_BLOCK_64TO32(void* ctx, _IO_STATUS_BLOCK*, uint32_t ptr32);
void convert__PORT_VIEW_64TO32(void* ctx, _PORT_VIEW*, uint32_t ptr32);
void convert__REMOTE_PORT_VIEW_64TO32(void* ctx, _REMOTE_PORT_VIEW*, uint32_t ptr32);
void convert__PORT_MESSAGE_64TO32(void* ctx, _PORT_MESSAGE*, uint32_t ptr32);
void convert__ALPC_DATA_VIEW_ATTR_64TO32(void* ctx, _ALPC_DATA_VIEW_ATTR*, uint32_t ptr32);
void convert__ALPC_SECURITY_ATTR_64TO32(void* ctx, _ALPC_SECURITY_ATTR*, uint32_t ptr32);
void convert__KEY_VALUE_ENTRY_64TO32(void* ctx, _KEY_VALUE_ENTRY*, uint32_t ptr32);
void convert__TOKEN_GROUPS_64TO32(void* ctx, _TOKEN_GROUPS*, uint32_t ptr32);
void convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_64TO32(void* ctx, _TOKEN_SECURITY_ATTRIBUTES_INFORMATION*, uint32_t ptr32);
void convert__TRANSACTION_NOTIFICATION_64TO32(void* ctx, _TRANSACTION_NOTIFICATION*, uint32_t ptr32);


void convert__SYSTEM_BASIC_INFORMATION_64TO32(void* ctx, _SYSTEM_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_BASIC_INFORMATION* x32_used_ptr = (X32__SYSTEM_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->Reserved = (long unsigned int)ptr64->Reserved;
	x32_used_ptr->TimerResolution = (long unsigned int)ptr64->TimerResolution;
	x32_used_ptr->PageSize = (long unsigned int)ptr64->PageSize;
	x32_used_ptr->NumberOfPhysicalPages = (long unsigned int)ptr64->NumberOfPhysicalPages;
	x32_used_ptr->LowestPhysicalPageNumber = (long unsigned int)ptr64->LowestPhysicalPageNumber;
	x32_used_ptr->HighestPhysicalPageNumber = (long unsigned int)ptr64->HighestPhysicalPageNumber;
	x32_used_ptr->AllocationGranularity = (long unsigned int)ptr64->AllocationGranularity;
	x32_used_ptr->MinimumUserModeAddress = (long long unsigned int)ptr64->MinimumUserModeAddress;
	x32_used_ptr->MaximumUserModeAddress = (long long unsigned int)ptr64->MaximumUserModeAddress;
	x32_used_ptr->ActiveProcessorsAffinityMask = (long long unsigned int)ptr64->ActiveProcessorsAffinityMask;
	x32_used_ptr->NumberOfProcessors = (char)ptr64->NumberOfProcessors;
};

void convert__SYSTEM_THREAD_INFORMATION_64TO32(void* ctx, _SYSTEM_THREAD_INFORMATION* ptr64, uint32_t ptr32) {
	X32_SYSTEM_THREAD_INFORMATION* x32_used_ptr = (X32__SYSTEM_THREAD_INFORMATION*)ptr32;
	x32_used_ptr->KernelTime = ptr64->KernelTime;
	x32_used_ptr->UserTime = ptr64->UserTime;
	x32_used_ptr->CreateTime = ptr64->CreateTime;
	x32_used_ptr->WaitTime = ptr64->WaitTime;
	x32_used_ptr->StartAddress = (X32_PVOID)ptr64->StartAddress;
	NESTED_CVT_64TO32(_CLIENT_ID, ClientId);
	x32_used_ptr->Priority = ptr64->Priority;
	x32_used_ptr->BasePriority = ptr64->BasePriority;
	x32_used_ptr->ContextSwitches = ptr64->ContextSwitches;
	x32_used_ptr->ThreadState = ptr64->ThreadState;
	x32_used_ptr->WaitReason = ptr64->WaitReason;
}


void convert__SYSTEM_PROCESS_INFORMATION_64TO32(void* ctx, _SYSTEM_PROCESS_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_PROCESS_INFORMATION* x32_used_ptr = (X32__SYSTEM_PROCESS_INFORMATION*)ptr32;

	_SYSTEM_PROCESS_INFORMATION* ptr64_original = ptr64;

	do {

		x32_used_ptr->NextEntryOffset = (long unsigned int)ptr64->NextEntryOffset;
		x32_used_ptr->NumberOfThreads = (long unsigned int)ptr64->NumberOfThreads;
		x32_used_ptr->WorkingSetPrivateSize = (_LARGE_INTEGER)ptr64->WorkingSetPrivateSize;
		x32_used_ptr->HardFaultCount = (long unsigned int)ptr64->HardFaultCount;
		x32_used_ptr->NumberOfThreadsHighWatermark = (long unsigned int)ptr64->NumberOfThreadsHighWatermark;
		x32_used_ptr->CycleTime = (long long unsigned int)ptr64->CycleTime;
		x32_used_ptr->CreateTime = (_LARGE_INTEGER)ptr64->CreateTime;
		x32_used_ptr->UserTime = (_LARGE_INTEGER)ptr64->UserTime;
		x32_used_ptr->KernelTime = (_LARGE_INTEGER)ptr64->KernelTime;

		CVT_UNICODE_STRING_OFFSETABLE(ptr64_original, ImageName);

		x32_used_ptr->BasePriority = (long int)ptr64->BasePriority;
		x32_used_ptr->UniqueProcessId = (X32_PVOID)ptr64->UniqueProcessId;
		x32_used_ptr->InheritedFromUniqueProcessId = (X32_PVOID)ptr64->InheritedFromUniqueProcessId;
		x32_used_ptr->HandleCount = (long unsigned int)ptr64->HandleCount;
		x32_used_ptr->SessionId = (long unsigned int)ptr64->SessionId;
		x32_used_ptr->UniqueProcessKey = (long long unsigned int)ptr64->UniqueProcessKey;
		x32_used_ptr->PeakVirtualSize = (long long unsigned int)ptr64->PeakVirtualSize;
		x32_used_ptr->VirtualSize = (long long unsigned int)ptr64->VirtualSize;
		x32_used_ptr->PageFaultCount = (long unsigned int)ptr64->PageFaultCount;
		x32_used_ptr->PeakWorkingSetSize = (long long unsigned int)ptr64->PeakWorkingSetSize;
		x32_used_ptr->WorkingSetSize = (long long unsigned int)ptr64->WorkingSetSize;
		x32_used_ptr->QuotaPeakPagedPoolUsage = (long long unsigned int)ptr64->QuotaPeakPagedPoolUsage;
		x32_used_ptr->QuotaPagedPoolUsage = (long long unsigned int)ptr64->QuotaPagedPoolUsage;
		x32_used_ptr->QuotaPeakNonPagedPoolUsage = (long long unsigned int)ptr64->QuotaPeakNonPagedPoolUsage;
		x32_used_ptr->QuotaNonPagedPoolUsage = (long long unsigned int)ptr64->QuotaNonPagedPoolUsage;
		x32_used_ptr->PagefileUsage = (long long unsigned int)ptr64->PagefileUsage;
		x32_used_ptr->PeakPagefileUsage = (long long unsigned int)ptr64->PeakPagefileUsage;
		x32_used_ptr->PrivatePageCount = (long long unsigned int)ptr64->PrivatePageCount;
		x32_used_ptr->ReadOperationCount = (_LARGE_INTEGER)ptr64->ReadOperationCount;
		x32_used_ptr->WriteOperationCount = (_LARGE_INTEGER)ptr64->WriteOperationCount;
		x32_used_ptr->OtherOperationCount = (_LARGE_INTEGER)ptr64->OtherOperationCount;
		x32_used_ptr->ReadTransferCount = (_LARGE_INTEGER)ptr64->ReadTransferCount;
		x32_used_ptr->WriteTransferCount = (_LARGE_INTEGER)ptr64->WriteTransferCount;
		x32_used_ptr->OtherTransferCount = (_LARGE_INTEGER)ptr64->OtherTransferCount;

		for (size_t idx = 0; idx < x32_used_ptr->NumberOfThreads; idx++) {
			NESTED_CVT_64TO32(_SYSTEM_THREAD_INFORMATION, Threads[idx]);
		}

	} while (ptr64->NextEntryOffset ? 
			((x32_used_ptr = (X32__SYSTEM_PROCESS_INFORMATION*)((LPBYTE)x32_used_ptr + ptr64->NextEntryOffset)) &&
			(ptr64 = (_SYSTEM_PROCESS_INFORMATION*)((LPBYTE)ptr64 + ptr64->NextEntryOffset)))
		: FALSE);
};

void convert__SYSTEM_POOL_ENTRY_64TO32(void* ctx, _SYSTEM_POOL_ENTRY* ptr64, uint32_t ptr32) {
	X32__SYSTEM_POOL_ENTRY* x32_used_ptr = (X32__SYSTEM_POOL_ENTRY*)ptr32;
	///////////////////
}

void convert__SYSTEM_POOL_INFORMATION_64TO32(void* ctx, _SYSTEM_POOL_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_POOL_INFORMATION* x32_used_ptr = (X32__SYSTEM_POOL_INFORMATION*)ptr32;
	x32_used_ptr->TotalSize = (long long unsigned int)ptr64->TotalSize;
	x32_used_ptr->FirstEntry = (X32_PVOID)ptr64->FirstEntry;
	x32_used_ptr->EntryOverhead = (short unsigned int)ptr64->EntryOverhead;
	x32_used_ptr->PoolTagPresent = (unsigned char)ptr64->PoolTagPresent;
	x32_used_ptr->Spare0 = (unsigned char)ptr64->Spare0;
	x32_used_ptr->NumberOfEntries = (long unsigned int)ptr64->NumberOfEntries;
	
	for (size_t idx = 0; idx < x32_used_ptr->NumberOfEntries; idx++) {
		NESTED_CVT_64TO32(_SYSTEM_POOL_ENTRY, Entries[idx]);
	}
};

void convert__SYSTEM_PAGEFILE_INFORMATION_64TO32(void* ctx, _SYSTEM_PAGEFILE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_PAGEFILE_INFORMATION* x32_used_ptr = (X32__SYSTEM_PAGEFILE_INFORMATION*)ptr32;
	x32_used_ptr->NextEntryOffset = (long unsigned int)ptr64->NextEntryOffset;
	x32_used_ptr->TotalSize = (long unsigned int)ptr64->TotalSize;
	x32_used_ptr->TotalInUse = (long unsigned int)ptr64->TotalInUse;
	x32_used_ptr->PeakUsage = (long unsigned int)ptr64->PeakUsage;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, PageFileName);
};

void convert__SYSTEM_FILECACHE_INFORMATION_64TO32(void* ctx, _SYSTEM_FILECACHE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_FILECACHE_INFORMATION* x32_used_ptr = (X32__SYSTEM_FILECACHE_INFORMATION*)ptr32;
	x32_used_ptr->CurrentSize = (long long unsigned int)ptr64->CurrentSize;
	x32_used_ptr->PeakSize = (long long unsigned int)ptr64->PeakSize;
	x32_used_ptr->PageFaultCount = (long unsigned int)ptr64->PageFaultCount;
	x32_used_ptr->MinimumWorkingSet = (long long unsigned int)ptr64->MinimumWorkingSet;
	x32_used_ptr->MaximumWorkingSet = (long long unsigned int)ptr64->MaximumWorkingSet;
	x32_used_ptr->CurrentSizeIncludingTransitionInPages = (long long unsigned int)ptr64->CurrentSizeIncludingTransitionInPages;
	x32_used_ptr->PeakSizeIncludingTransitionInPages = (long long unsigned int)ptr64->PeakSizeIncludingTransitionInPages;
	x32_used_ptr->TransitionRePurposeCount = (long unsigned int)ptr64->TransitionRePurposeCount;
	x32_used_ptr->Flags = (long unsigned int)ptr64->Flags;
};

void convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_64TO32(void* ctx, _SYSTEM_REGISTRY_QUOTA_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_REGISTRY_QUOTA_INFORMATION* x32_used_ptr = (X32__SYSTEM_REGISTRY_QUOTA_INFORMATION*)ptr32;
	x32_used_ptr->RegistryQuotaAllowed = (long unsigned int)ptr64->RegistryQuotaAllowed;
	x32_used_ptr->RegistryQuotaUsed = (long unsigned int)ptr64->RegistryQuotaUsed;
	x32_used_ptr->PagedPoolSize = (long long unsigned int)ptr64->PagedPoolSize;
};

void convert__SYSTEM_LEGACY_DRIVER_INFORMATION_64TO32(void* ctx, _SYSTEM_LEGACY_DRIVER_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_LEGACY_DRIVER_INFORMATION* x32_used_ptr = (X32__SYSTEM_LEGACY_DRIVER_INFORMATION*)ptr32;
	x32_used_ptr->VetoType = (long unsigned int)ptr64->VetoType;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, VetoList);
};

void convert__SYSTEM_VERIFIER_INFORMATION_64TO32(void* ctx, _SYSTEM_VERIFIER_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_VERIFIER_INFORMATION* x32_used_ptr = (X32__SYSTEM_VERIFIER_INFORMATION*)ptr32;
	x32_used_ptr->NextEntryOffset = (long unsigned int)ptr64->NextEntryOffset;
	x32_used_ptr->Level = (long unsigned int)ptr64->Level;
	x32_used_ptr->RuleClasses[0] = (long unsigned int)ptr64->RuleClasses[0];
	x32_used_ptr->RuleClasses[1] = (long unsigned int)ptr64->RuleClasses[1];
	x32_used_ptr->TriageContext = (long unsigned int)ptr64->TriageContext;
	x32_used_ptr->AreAllDriversBeingVerified = (long unsigned int)ptr64->AreAllDriversBeingVerified;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, DriverName);
	x32_used_ptr->RaiseIrqls = (long unsigned int)ptr64->RaiseIrqls;
	x32_used_ptr->AcquireSpinLocks = (long unsigned int)ptr64->AcquireSpinLocks;
	x32_used_ptr->SynchronizeExecutions = (long unsigned int)ptr64->SynchronizeExecutions;
	x32_used_ptr->AllocationsAttempted = (long unsigned int)ptr64->AllocationsAttempted;
	x32_used_ptr->AllocationsSucceeded = (long unsigned int)ptr64->AllocationsSucceeded;
	x32_used_ptr->AllocationsSucceededSpecialPool = (long unsigned int)ptr64->AllocationsSucceededSpecialPool;
	x32_used_ptr->AllocationsWithNoTag = (long unsigned int)ptr64->AllocationsWithNoTag;
	x32_used_ptr->TrimRequests = (long unsigned int)ptr64->TrimRequests;
	x32_used_ptr->Trims = (long unsigned int)ptr64->Trims;
	x32_used_ptr->AllocationsFailed = (long unsigned int)ptr64->AllocationsFailed;
	x32_used_ptr->AllocationsFailedDeliberately = (long unsigned int)ptr64->AllocationsFailedDeliberately;
	x32_used_ptr->Loads = (long unsigned int)ptr64->Loads;
	x32_used_ptr->Unloads = (long unsigned int)ptr64->Unloads;
	x32_used_ptr->UnTrackedPool = (long unsigned int)ptr64->UnTrackedPool;
	x32_used_ptr->CurrentPagedPoolAllocations = (long unsigned int)ptr64->CurrentPagedPoolAllocations;
	x32_used_ptr->CurrentNonPagedPoolAllocations = (long unsigned int)ptr64->CurrentNonPagedPoolAllocations;
	x32_used_ptr->PeakPagedPoolAllocations = (long unsigned int)ptr64->PeakPagedPoolAllocations;
	x32_used_ptr->PeakNonPagedPoolAllocations = (long unsigned int)ptr64->PeakNonPagedPoolAllocations;
	x32_used_ptr->PagedPoolUsageInBytes = (long long unsigned int)ptr64->PagedPoolUsageInBytes;
	x32_used_ptr->NonPagedPoolUsageInBytes = (long long unsigned int)ptr64->NonPagedPoolUsageInBytes;
	x32_used_ptr->PeakPagedPoolUsageInBytes = (long long unsigned int)ptr64->PeakPagedPoolUsageInBytes;
	x32_used_ptr->PeakNonPagedPoolUsageInBytes = (long long unsigned int)ptr64->PeakNonPagedPoolUsageInBytes;
};

void convert__SYSTEM_SESSION_PROCESS_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_PROCESS_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_SESSION_PROCESS_INFORMATION* x32_used_ptr = (X32__SYSTEM_SESSION_PROCESS_INFORMATION*)ptr32;
	x32_used_ptr->SessionId = (long unsigned int)ptr64->SessionId;
	x32_used_ptr->SizeOfBuf = (long unsigned int)ptr64->SizeOfBuf;
	x32_used_ptr->Buffer = (X32_PVOID)ptr64->Buffer;
};


void convert__SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_64TO32(void* ctx, _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* ptr64, uint32_t ptr32) {
	X32__SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* x32_used_ptr = (X32__SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)ptr32;

	NESTED_CVT_64TO32(HANDLE, Object);
	x32_used_ptr->UniqueProcessId = ptr64->UniqueProcessId;
	x32_used_ptr->HandleValue = ptr64->HandleValue;
	x32_used_ptr->GrantedAccess = ptr64->GrantedAccess;
	x32_used_ptr->CreatorBackTraceIndex = ptr64->CreatorBackTraceIndex;
	x32_used_ptr->ObjectTypeIndex = ptr64->ObjectTypeIndex;
	x32_used_ptr->HandleAttributes = ptr64->HandleAttributes;
	x32_used_ptr->Reserved = ptr64->Reserved;
}

void convert__SYSTEM_HANDLE_INFORMATION_EX_64TO32(void* ctx, _SYSTEM_HANDLE_INFORMATION_EX* ptr64, uint32_t ptr32) {
	X32__SYSTEM_HANDLE_INFORMATION_EX* x32_used_ptr = (X32__SYSTEM_HANDLE_INFORMATION_EX*)ptr32;
	x32_used_ptr->NumberOfHandles = (long long unsigned int)ptr64->NumberOfHandles;
	x32_used_ptr->Reserved = (long long unsigned int)ptr64->Reserved;

	for (size_t idx = 0; idx < x32_used_ptr->NumberOfHandles; idx++) {
		NESTED_CVT_64TO32(_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, Handles[idx]);
	}
};

void convert__SYSTEM_SESSION_POOLTAG_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_POOLTAG_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_SESSION_POOLTAG_INFORMATION* x32_used_ptr = (X32__SYSTEM_SESSION_POOLTAG_INFORMATION*)ptr32;
	x32_used_ptr->NextEntryOffset = (long long unsigned int)ptr64->NextEntryOffset;
	x32_used_ptr->SessionId = (long unsigned int)ptr64->SessionId;
	x32_used_ptr->Count = (long unsigned int)ptr64->Count;

//	x32_used_ptr->TagInfo = (_SYSTEM_POOLTAG[1])ptr64->TagInfo;
};

void convert__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION_64TO32(void* ctx, _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION* x32_used_ptr = (X32__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*)ptr32;
	x32_used_ptr->NextEntryOffset = (long long unsigned int)ptr64->NextEntryOffset;
	x32_used_ptr->SessionId = (long unsigned int)ptr64->SessionId;
	x32_used_ptr->ViewFailures = (long unsigned int)ptr64->ViewFailures;
	x32_used_ptr->NumberOfBytesAvailable = (long long unsigned int)ptr64->NumberOfBytesAvailable;
	x32_used_ptr->NumberOfBytesAvailableContiguous = (long long unsigned int)ptr64->NumberOfBytesAvailableContiguous;
};

void convert__SYSTEM_FIRMWARE_TABLE_HANDLER_64TO32(void* ctx, _SYSTEM_FIRMWARE_TABLE_HANDLER* ptr64, uint32_t ptr32) {
	X32__SYSTEM_FIRMWARE_TABLE_HANDLER* x32_used_ptr = (X32__SYSTEM_FIRMWARE_TABLE_HANDLER*)ptr32;
	x32_used_ptr->ProviderSignature = (long unsigned int)ptr64->ProviderSignature;
	x32_used_ptr->Register = (unsigned char)ptr64->Register;

//	x32_used_ptr->FirmwareTableHandler = (NTSTATUS(*)(::PSYSTEM_FIRMWARE_TABLE_INFORMATION))ptr64->FirmwareTableHandler;
//	x32_used_ptr->DriverObject = (void*)ptr64->DriverObject;
};

void convert__RTL_PROCESS_MODULE_INFORMATION_EX_64TO32(void* ctx, _RTL_PROCESS_MODULE_INFORMATION_EX* ptr64, uint32_t ptr32) {
	X32__RTL_PROCESS_MODULE_INFORMATION_EX* x32_used_ptr = (X32__RTL_PROCESS_MODULE_INFORMATION_EX*)ptr32;
	x32_used_ptr->NextOffset = (short unsigned int)ptr64->NextOffset;
	//NESTED_CVT_64TO32(_RTL_PROCESS_MODULE_INFORMATION, BaseInfo);
	//x32_used_ptr->BaseInfo = (_RTL_PROCESS_MODULE_INFORMATION)ptr64->BaseInfo;
	x32_used_ptr->ImageChecksum = (long unsigned int)ptr64->ImageChecksum;
	x32_used_ptr->TimeDateStamp = (long unsigned int)ptr64->TimeDateStamp;
	x32_used_ptr->DefaultBase = (X32_PVOID)ptr64->DefaultBase;
};

void convert__SUPERFETCH_INFORMATION_64TO32(void* ctx, _SUPERFETCH_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SUPERFETCH_INFORMATION* x32_used_ptr = (X32__SUPERFETCH_INFORMATION*)ptr32;
	x32_used_ptr->Version	= (long unsigned int)ptr64->Version;
	x32_used_ptr->Magic		= (long unsigned int)ptr64->Magic;
	x32_used_ptr->InfoClass = (_SUPERFETCH_INFORMATION_CLASS)ptr64->InfoClass;
	x32_used_ptr->Data		= (X32_PVOID)ptr64->Data;
	x32_used_ptr->Length	= (long unsigned int)ptr64->Length;
};

void convert__SYSTEM_MEMORY_LIST_INFORMATION_64TO32(void* ctx, _SYSTEM_MEMORY_LIST_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_MEMORY_LIST_INFORMATION* x32_used_ptr = (X32__SYSTEM_MEMORY_LIST_INFORMATION*)ptr32;
	x32_used_ptr->ZeroPageCount = (long long unsigned int)ptr64->ZeroPageCount;
	x32_used_ptr->FreePageCount = (long long unsigned int)ptr64->FreePageCount;
	x32_used_ptr->ModifiedPageCount = (long long unsigned int)ptr64->ModifiedPageCount;
	x32_used_ptr->ModifiedNoWritePageCount = (long long unsigned int)ptr64->ModifiedNoWritePageCount;
	x32_used_ptr->BadPageCount = (long long unsigned int)ptr64->BadPageCount;
//	x32_used_ptr->PageCountByPriority = (long long unsigned int[8])ptr64->PageCountByPriority;
//	x32_used_ptr->RepurposedPagesByPriority = (long long unsigned int[8])ptr64->RepurposedPagesByPriority;
	x32_used_ptr->ModifiedPageCountPageFile = (long long unsigned int)ptr64->ModifiedPageCountPageFile;
};

void convert__SYSTEM_REF_TRACE_INFORMATION_64TO32(void* ctx, _SYSTEM_REF_TRACE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_REF_TRACE_INFORMATION* x32_used_ptr = (X32__SYSTEM_REF_TRACE_INFORMATION*)ptr32;
	x32_used_ptr->TraceEnable = (unsigned char)ptr64->TraceEnable;
	x32_used_ptr->TracePermanent = (unsigned char)ptr64->TracePermanent;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, TraceProcessName);
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, TracePoolTags);
};

void convert__SYSTEM_PROCESS_ID_INFORMATION_64TO32(void* ctx, _SYSTEM_PROCESS_ID_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_PROCESS_ID_INFORMATION* x32_used_ptr = (X32__SYSTEM_PROCESS_ID_INFORMATION*)ptr32;
	x32_used_ptr->ProcessId = (X32_HANDLE)ptr64->ProcessId;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, ImageName);
};

void convert__SYSTEM_VERIFIER_INFORMATION_EX_64TO32(void* ctx, _SYSTEM_VERIFIER_INFORMATION_EX* ptr64, uint32_t ptr32) {
	X32__SYSTEM_VERIFIER_INFORMATION_EX* x32_used_ptr = (X32__SYSTEM_VERIFIER_INFORMATION_EX*)ptr32;
	x32_used_ptr->VerifyMode = (long unsigned int)ptr64->VerifyMode;
	x32_used_ptr->OptionChanges = (long unsigned int)ptr64->OptionChanges;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, PreviousBucketName);
	x32_used_ptr->IrpCancelTimeoutMsec = (long unsigned int)ptr64->IrpCancelTimeoutMsec;
	x32_used_ptr->VerifierExtensionEnabled = (long unsigned int)ptr64->VerifierExtensionEnabled;
	x32_used_ptr->Reserved[0] = (long unsigned int)ptr64->Reserved[0];
};

void convert__SYSTEM_SYSTEM_PARTITION_INFORMATION_64TO32(void* ctx, _SYSTEM_SYSTEM_PARTITION_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_SYSTEM_PARTITION_INFORMATION* x32_used_ptr = (X32__SYSTEM_SYSTEM_PARTITION_INFORMATION*)ptr32;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, SystemPartition);
};

void convert__SYSTEM_SYSTEM_DISK_INFORMATION_64TO32(void* ctx, _SYSTEM_SYSTEM_DISK_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_SYSTEM_DISK_INFORMATION* x32_used_ptr = (X32__SYSTEM_SYSTEM_DISK_INFORMATION*)ptr32;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, SystemDisk);
};

void convert__SYSTEM_BASIC_PERFORMANCE_INFORMATION_64TO32(void* ctx, _SYSTEM_BASIC_PERFORMANCE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_BASIC_PERFORMANCE_INFORMATION* x32_used_ptr = (X32__SYSTEM_BASIC_PERFORMANCE_INFORMATION*)ptr32;
	x32_used_ptr->AvailablePages = (long long unsigned int)ptr64->AvailablePages;
	x32_used_ptr->CommittedPages = (long long unsigned int)ptr64->CommittedPages;
	x32_used_ptr->CommitLimit = (long long unsigned int)ptr64->CommitLimit;
	x32_used_ptr->PeakCommitment = (long long unsigned int)ptr64->PeakCommitment;
};

void convert__SYSTEM_POLICY_INFORMATION_64TO32(void* ctx, _SYSTEM_POLICY_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_POLICY_INFORMATION* x32_used_ptr = (X32__SYSTEM_POLICY_INFORMATION*)ptr32;
	x32_used_ptr->InputData = (X32_PVOID)ptr64->InputData;
	x32_used_ptr->OutputData = (X32_PVOID)ptr64->OutputData;
	x32_used_ptr->InputDataSize = (long unsigned int)ptr64->InputDataSize;
	x32_used_ptr->OutputDataSize = (long unsigned int)ptr64->OutputDataSize;
	x32_used_ptr->Version = (long unsigned int)ptr64->Version;
};

void convert__SYSTEM_MANUFACTURING_INFORMATION_64TO32(void* ctx, _SYSTEM_MANUFACTURING_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_MANUFACTURING_INFORMATION* x32_used_ptr = (X32__SYSTEM_MANUFACTURING_INFORMATION*)ptr32;
	x32_used_ptr->Options = (long unsigned int)ptr64->Options;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, ProfileName);
};

void convert__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS_64TO32(void* ctx, _SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS* ptr64, uint32_t ptr32) {
	X32__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS* x32_used_ptr = (X32__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS*)ptr32;
	NESTED_CVT_64TO32(HANDLE, UserKeyHandle);
};

void convert__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION_64TO32(void* ctx, _SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION* x32_used_ptr = (X32__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION*)ptr32;
	x32_used_ptr->HypervisorSharedUserVa = (X32_PVOID)ptr64->HypervisorSharedUserVa;
};

void convert__UNICODE_STRING_64TO32(void* ctx, _UNICODE_STRING* ptr64, uint32_t ptr32) {
	X32__UNICODE_STRING* x32_used_ptr = (X32__UNICODE_STRING*)ptr32;
	x32_used_ptr->Length = (short unsigned int)ptr64->Length;
	x32_used_ptr->MaximumLength = (short unsigned int)ptr64->MaximumLength;
	x32_used_ptr->Buffer = (WOW64_POINTER(wchar_t*))ptr64->Buffer;
};

void convert__MEMORY_BASIC_INFORMATION_64TO32(void* ctx, _MEMORY_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__MEMORY_BASIC_INFORMATION* x32_used_ptr = (X32__MEMORY_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->BaseAddress = (X32_PVOID)ptr64->BaseAddress;
	x32_used_ptr->AllocationBase = (X32_PVOID)ptr64->AllocationBase;
	x32_used_ptr->AllocationProtect = (long unsigned int)ptr64->AllocationProtect;
	x32_used_ptr->RegionSize = (long long unsigned int)ptr64->RegionSize;
	x32_used_ptr->State = (long unsigned int)ptr64->State;
	x32_used_ptr->Protect = (long unsigned int)ptr64->Protect;
	x32_used_ptr->Type = (long unsigned int)ptr64->Type;
};

void convert__MEMORY_WORKING_SET_INFORMATION_64TO32(void* ctx, _MEMORY_WORKING_SET_INFORMATION* ptr64, uint32_t ptr32) {
	X32__MEMORY_WORKING_SET_INFORMATION* x32_used_ptr = (X32__MEMORY_WORKING_SET_INFORMATION*)ptr32;
	x32_used_ptr->NumberOfEntries = (long long unsigned int)ptr64->NumberOfEntries;
	
	//x32_used_ptr->WorkingSetInfo = (_MEMORY_WORKING_SET_BLOCK[1])ptr64->WorkingSetInfo;
};

void convert__MEMORY_REGION_INFORMATION_64TO32(void* ctx, _MEMORY_REGION_INFORMATION* ptr64, uint32_t ptr32) {
	X32__MEMORY_REGION_INFORMATION* x32_used_ptr = (X32__MEMORY_REGION_INFORMATION*)ptr32;
	x32_used_ptr->AllocationBase = (X32_PVOID)ptr64->AllocationBase;
	x32_used_ptr->AllocationProtect = (long unsigned int)ptr64->AllocationProtect;
	x32_used_ptr->RegionType = ptr64->RegionType;
	x32_used_ptr->RegionSize = (long long unsigned int)ptr64->RegionSize;
	x32_used_ptr->CommitSize = (long long unsigned int)ptr64->CommitSize;
	x32_used_ptr->PartitionId = (long long unsigned int)ptr64->PartitionId;
};

void convert__MEMORY_WORKING_SET_EX_INFORMATION_64TO32(void* ctx, _MEMORY_WORKING_SET_EX_INFORMATION* ptr64, uint32_t ptr32) {
	X32__MEMORY_WORKING_SET_EX_INFORMATION* x32_used_ptr = (X32__MEMORY_WORKING_SET_EX_INFORMATION*)ptr32;
	x32_used_ptr->VirtualAddress = (X32_PVOID)ptr64->VirtualAddress;

//#pragma error('Here Ignored union fix it')
//	x32_used_ptr->u1 = (_MEMORY_WORKING_SET_EX_INFORMATION)ptr64->u1;
};

void convert__SECTION_BASIC_INFORMATION_64TO32(void* ctx, _SECTION_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SECTION_BASIC_INFORMATION* x32_used_ptr = (X32__SECTION_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->BaseAddress = (X32_PVOID)ptr64->BaseAddress;
	x32_used_ptr->AllocationAttributes = (long unsigned int)ptr64->AllocationAttributes;
	x32_used_ptr->MaximumSize = (_LARGE_INTEGER)ptr64->MaximumSize;
};

void convert__SECTION_IMAGE_INFORMATION_64TO32(void* ctx, _SECTION_IMAGE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__SECTION_IMAGE_INFORMATION* x32_used_ptr = (X32__SECTION_IMAGE_INFORMATION*)ptr32;
	x32_used_ptr->TransferAddress = (X32_PVOID)ptr64->TransferAddress;
	x32_used_ptr->ZeroBits = (long unsigned int)ptr64->ZeroBits;
	x32_used_ptr->MaximumStackSize = (long long unsigned int)ptr64->MaximumStackSize;
	x32_used_ptr->CommittedStackSize = (long long unsigned int)ptr64->CommittedStackSize;
	x32_used_ptr->SubSystemType = (long unsigned int)ptr64->SubSystemType;
	x32_used_ptr->SubSystemVersion = ptr64->SubSystemVersion;
	x32_used_ptr->OperatingSystemVersion = ptr64->OperatingSystemVersion;
	x32_used_ptr->ImageCharacteristics = (short unsigned int)ptr64->ImageCharacteristics;
	x32_used_ptr->DllCharacteristics = (short unsigned int)ptr64->DllCharacteristics;
	x32_used_ptr->Machine = (short unsigned int)ptr64->Machine;
	x32_used_ptr->ImageContainsCode = (unsigned char)ptr64->ImageContainsCode;
	x32_used_ptr->ImageFlags = ptr64->ImageFlags;
	x32_used_ptr->LoaderFlags = (long unsigned int)ptr64->LoaderFlags;
	x32_used_ptr->ImageFileSize = (long unsigned int)ptr64->ImageFileSize;
	x32_used_ptr->CheckSum = (long unsigned int)ptr64->CheckSum;
};

void convert__OBJECT_NAME_INFORMATION_64TO32(void* ctx, _OBJECT_NAME_INFORMATION* ptr64, uint32_t ptr32) {
	X32__OBJECT_NAME_INFORMATION* x32_used_ptr = (X32__OBJECT_NAME_INFORMATION*)ptr32;
	NESTED_CVT_64TO32(_UNICODE_STRING, Name);
};

void convert__OBJECT_TYPE_INFORMATION_64TO32(void* ctx, _OBJECT_TYPE_INFORMATION* ptr64, uint32_t ptr32) {
	X32__OBJECT_TYPE_INFORMATION* x32_used_ptr = (X32__OBJECT_TYPE_INFORMATION*)ptr32;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, TypeName);
	x32_used_ptr->TotalNumberOfObjects = (long unsigned int)ptr64->TotalNumberOfObjects;
	x32_used_ptr->TotalNumberOfHandles = (long unsigned int)ptr64->TotalNumberOfHandles;
	x32_used_ptr->TotalPagedPoolUsage = (long unsigned int)ptr64->TotalPagedPoolUsage;
	x32_used_ptr->TotalNonPagedPoolUsage = (long unsigned int)ptr64->TotalNonPagedPoolUsage;
	x32_used_ptr->TotalNamePoolUsage = (long unsigned int)ptr64->TotalNamePoolUsage;
	x32_used_ptr->TotalHandleTableUsage = (long unsigned int)ptr64->TotalHandleTableUsage;
	x32_used_ptr->HighWaterNumberOfObjects = (long unsigned int)ptr64->HighWaterNumberOfObjects;
	x32_used_ptr->HighWaterNumberOfHandles = (long unsigned int)ptr64->HighWaterNumberOfHandles;
	x32_used_ptr->HighWaterPagedPoolUsage = (long unsigned int)ptr64->HighWaterPagedPoolUsage;
	x32_used_ptr->HighWaterNonPagedPoolUsage = (long unsigned int)ptr64->HighWaterNonPagedPoolUsage;
	x32_used_ptr->HighWaterNamePoolUsage = (long unsigned int)ptr64->HighWaterNamePoolUsage;
	x32_used_ptr->HighWaterHandleTableUsage = (long unsigned int)ptr64->HighWaterHandleTableUsage;
	x32_used_ptr->InvalidAttributes = (long unsigned int)ptr64->InvalidAttributes;
	x32_used_ptr->GenericMapping = (_GENERIC_MAPPING)ptr64->GenericMapping;
	x32_used_ptr->ValidAccessMask = (long unsigned int)ptr64->ValidAccessMask;
	x32_used_ptr->SecurityRequired = (unsigned char)ptr64->SecurityRequired;
	x32_used_ptr->MaintainHandleCount = (unsigned char)ptr64->MaintainHandleCount;
	x32_used_ptr->TypeIndex = (unsigned char)ptr64->TypeIndex;
	x32_used_ptr->ReservedByte = (char)ptr64->ReservedByte;
	x32_used_ptr->PoolType = (long unsigned int)ptr64->PoolType;
	x32_used_ptr->DefaultPagedPoolCharge = (long unsigned int)ptr64->DefaultPagedPoolCharge;
	x32_used_ptr->DefaultNonPagedPoolCharge = (long unsigned int)ptr64->DefaultNonPagedPoolCharge;
};

void convert__PROCESS_BASIC_INFORMATION_64TO32(void* ctx, _PROCESS_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__PROCESS_BASIC_INFORMATION* x32_used_ptr = (X32__PROCESS_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->ExitStatus = (long int)ptr64->ExitStatus;
	x32_used_ptr->PebBaseAddress = (WOW64_POINTER(_PEB*))ptr64->PebBaseAddress;
	x32_used_ptr->AffinityMask = (long long unsigned int)ptr64->AffinityMask;
	x32_used_ptr->BasePriority = (long int)ptr64->BasePriority;
	x32_used_ptr->UniqueProcessId = (X32_HANDLE)ptr64->UniqueProcessId;
	x32_used_ptr->InheritedFromUniqueProcessId = (X32_HANDLE)ptr64->InheritedFromUniqueProcessId;
};

void convert__QUOTA_LIMITS_64TO32(void* ctx, _QUOTA_LIMITS* ptr64, uint32_t ptr32) {
	X32__QUOTA_LIMITS* x32_used_ptr = (X32__QUOTA_LIMITS*)ptr32;
	x32_used_ptr->PagedPoolLimit = (long long unsigned int)ptr64->PagedPoolLimit;
	x32_used_ptr->NonPagedPoolLimit = (long long unsigned int)ptr64->NonPagedPoolLimit;
	x32_used_ptr->MinimumWorkingSetSize = (long long unsigned int)ptr64->MinimumWorkingSetSize;
	x32_used_ptr->MaximumWorkingSetSize = (long long unsigned int)ptr64->MaximumWorkingSetSize;
	x32_used_ptr->PagefileLimit = (long long unsigned int)ptr64->PagefileLimit;
	x32_used_ptr->TimeLimit = (LARGE_INTEGER)ptr64->TimeLimit;
};

void convert__VM_COUNTERS_64TO32(void* ctx, _VM_COUNTERS* ptr64, uint32_t ptr32) {
	X32__VM_COUNTERS* x32_used_ptr = (X32__VM_COUNTERS*)ptr32;
	x32_used_ptr->PeakVirtualSize = (long long unsigned int)ptr64->PeakVirtualSize;
	x32_used_ptr->VirtualSize = (long long unsigned int)ptr64->VirtualSize;
	x32_used_ptr->PageFaultCount = (long unsigned int)ptr64->PageFaultCount;
	x32_used_ptr->PeakWorkingSetSize = (long long unsigned int)ptr64->PeakWorkingSetSize;
	x32_used_ptr->WorkingSetSize = (long long unsigned int)ptr64->WorkingSetSize;
	x32_used_ptr->QuotaPeakPagedPoolUsage = (long long unsigned int)ptr64->QuotaPeakPagedPoolUsage;
	x32_used_ptr->QuotaPagedPoolUsage = (long long unsigned int)ptr64->QuotaPagedPoolUsage;
	x32_used_ptr->QuotaPeakNonPagedPoolUsage = (long long unsigned int)ptr64->QuotaPeakNonPagedPoolUsage;
	x32_used_ptr->QuotaNonPagedPoolUsage = (long long unsigned int)ptr64->QuotaNonPagedPoolUsage;
	x32_used_ptr->PagefileUsage = (long long unsigned int)ptr64->PagefileUsage;
	x32_used_ptr->PeakPagefileUsage = (long long unsigned int)ptr64->PeakPagefileUsage;
};

void convert__POOLED_USAGE_AND_LIMITS_64TO32(void* ctx, _POOLED_USAGE_AND_LIMITS* ptr64, uint32_t ptr32) {
	X32__POOLED_USAGE_AND_LIMITS* x32_used_ptr = (X32__POOLED_USAGE_AND_LIMITS*)ptr32;
	x32_used_ptr->PeakPagedPoolUsage = (long long unsigned int)ptr64->PeakPagedPoolUsage;
	x32_used_ptr->PagedPoolUsage = (long long unsigned int)ptr64->PagedPoolUsage;
	x32_used_ptr->PagedPoolLimit = (long long unsigned int)ptr64->PagedPoolLimit;
	x32_used_ptr->PeakNonPagedPoolUsage = (long long unsigned int)ptr64->PeakNonPagedPoolUsage;
	x32_used_ptr->NonPagedPoolUsage = (long long unsigned int)ptr64->NonPagedPoolUsage;
	x32_used_ptr->NonPagedPoolLimit = (long long unsigned int)ptr64->NonPagedPoolLimit;
	x32_used_ptr->PeakPagefileUsage = (long long unsigned int)ptr64->PeakPagefileUsage;
	x32_used_ptr->PagefileUsage = (long long unsigned int)ptr64->PagefileUsage;
	x32_used_ptr->PagefileLimit = (long long unsigned int)ptr64->PagefileLimit;
};

void convert__PROCESS_WS_WATCH_INFORMATION_64TO32(void* ctx, _PROCESS_WS_WATCH_INFORMATION* ptr64, uint32_t ptr32) {
	X32__PROCESS_WS_WATCH_INFORMATION* x32_used_ptr = (X32__PROCESS_WS_WATCH_INFORMATION*)ptr32;
	x32_used_ptr->FaultingPc = (X32_PVOID)ptr64->FaultingPc;
	x32_used_ptr->FaultingVa = (X32_PVOID)ptr64->FaultingVa;
};

void convert__PROCESS_DEVICEMAP_INFORMATION_64TO32(void* ctx, _PROCESS_DEVICEMAP_INFORMATION* ptr64, uint32_t ptr32) {
	X32__PROCESS_DEVICEMAP_INFORMATION* x32_used_ptr = (X32__PROCESS_DEVICEMAP_INFORMATION*)ptr32;

//#pragma error('Here Ignored union fix it')
//	x32_used_ptr-> = (_PROCESS_DEVICEMAP_INFORMATION)ptr64->;
};

void convert__PROCESS_HANDLE_TRACING_QUERY_64TO32(void* ctx, _PROCESS_HANDLE_TRACING_QUERY* ptr64, uint32_t ptr32) {
	X32__PROCESS_HANDLE_TRACING_QUERY* x32_used_ptr = (X32__PROCESS_HANDLE_TRACING_QUERY*)ptr32;
	NESTED_CVT_64TO32(HANDLE, Handle);
	x32_used_ptr->TotalTraces = (long unsigned int)ptr64->TotalTraces;

//	x32_used_ptr->HandleTrace = (_PROCESS_HANDLE_TRACING_ENTRY[1])ptr64->HandleTrace;
};

void convert__PROCESS_WS_WATCH_INFORMATION_EX_64TO32(void* ctx, _PROCESS_WS_WATCH_INFORMATION_EX* ptr64, uint32_t ptr32) {
	X32__PROCESS_WS_WATCH_INFORMATION_EX* x32_used_ptr = (X32__PROCESS_WS_WATCH_INFORMATION_EX*)ptr32;
	NESTED_CVT_64TO32(_PROCESS_WS_WATCH_INFORMATION, BasicInfo);
	x32_used_ptr->FaultingThreadId = (long long unsigned int)ptr64->FaultingThreadId;
	x32_used_ptr->Flags = (long long unsigned int)ptr64->Flags;
};

void convert__PROCESS_HANDLE_SNAPSHOT_INFORMATION_64TO32(void* ctx, _PROCESS_HANDLE_SNAPSHOT_INFORMATION* ptr64, uint32_t ptr32) {
	X32__PROCESS_HANDLE_SNAPSHOT_INFORMATION* x32_used_ptr = (X32__PROCESS_HANDLE_SNAPSHOT_INFORMATION*)ptr32;
	x32_used_ptr->NumberOfHandles = (long long unsigned int)ptr64->NumberOfHandles;
	x32_used_ptr->Reserved = (long long unsigned int)ptr64->Reserved;

//	x32_used_ptr->Handles = (_PROCESS_HANDLE_TABLE_ENTRY_INFO[1])ptr64->Handles;
};

void convert__THREAD_BASIC_INFORMATION_64TO32(void* ctx, _THREAD_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__THREAD_BASIC_INFORMATION* x32_used_ptr = (X32__THREAD_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->ExitStatus = (long int)ptr64->ExitStatus;
	x32_used_ptr->TebBaseAddress = (WOW64_POINTER(_TEB*))ptr64->TebBaseAddress + 0x2000;
	NESTED_CVT_64TO32(_CLIENT_ID, ClientId);
	x32_used_ptr->AffinityMask = (long long unsigned int)ptr64->AffinityMask;
	x32_used_ptr->Priority = (long int)ptr64->Priority;
	x32_used_ptr->BasePriority = (long int)ptr64->BasePriority;
};

void convert__THREAD_LAST_SYSCALL_INFORMATION_64TO32(void* ctx, _THREAD_LAST_SYSCALL_INFORMATION* ptr64, uint32_t ptr32) {
	X32__THREAD_LAST_SYSCALL_INFORMATION* x32_used_ptr = (X32__THREAD_LAST_SYSCALL_INFORMATION*)ptr32;
	x32_used_ptr->FirstArgument = (X32_PVOID)ptr64->FirstArgument;
	x32_used_ptr->SystemCallNumber = (short unsigned int)ptr64->SystemCallNumber;
	x32_used_ptr->Pad[0] = (short unsigned int)ptr64->Pad[0];
	x32_used_ptr->WaitTime = (long long unsigned int)ptr64->WaitTime;
};

void convert__THREAD_TEB_INFORMATION_64TO32(void* ctx, _THREAD_TEB_INFORMATION* ptr64, uint32_t ptr32) {
	X32__THREAD_TEB_INFORMATION* x32_used_ptr = (X32__THREAD_TEB_INFORMATION*)ptr32;
	x32_used_ptr->TebInformation = (X32_PVOID)ptr64->TebInformation;
	x32_used_ptr->TebOffset = (long unsigned int)ptr64->TebOffset;
	x32_used_ptr->BytesToRead = (long unsigned int)ptr64->BytesToRead;
};

void convert__GROUP_AFFINITY_64TO32(void* ctx, _GROUP_AFFINITY* ptr64, uint32_t ptr32) {
	X32__GROUP_AFFINITY* x32_used_ptr = (X32__GROUP_AFFINITY*)ptr32;
	x32_used_ptr->Mask = (long long unsigned int)ptr64->Mask;
	x32_used_ptr->Group = (short unsigned int)ptr64->Group;
	x32_used_ptr->Reserved[0] = (short unsigned int)ptr64->Reserved[0];
	x32_used_ptr->Reserved[1] = (short unsigned int)ptr64->Reserved[1];
	x32_used_ptr->Reserved[2] = (short unsigned int)ptr64->Reserved[2];
};

void convert__THREAD_PROFILING_INFORMATION_64TO32(void* ctx, _THREAD_PROFILING_INFORMATION* ptr64, uint32_t ptr32) {
	X32__THREAD_PROFILING_INFORMATION* x32_used_ptr = (X32__THREAD_PROFILING_INFORMATION*)ptr32;
	x32_used_ptr->HardwareCounters = (long long unsigned int)ptr64->HardwareCounters;
	x32_used_ptr->Flags = (long unsigned int)ptr64->Flags;
	x32_used_ptr->Enable = (long unsigned int)ptr64->Enable;
	x32_used_ptr->PerformanceData = (WOW64_POINTER(_THREAD_PERFORMANCE_DATA*))ptr64->PerformanceData;
};

void convert__THREAD_NAME_INFORMATION_64TO32(void* ctx, _THREAD_NAME_INFORMATION* ptr64, uint32_t ptr32) {
	X32__THREAD_NAME_INFORMATION* x32_used_ptr = (X32__THREAD_NAME_INFORMATION*)ptr32;
	CVT_UNICODE_STRING_OFFSETABLE(ptr64, ThreadName);
};

void convert__ALPC_BASIC_INFORMATION_64TO32(void* ctx, _ALPC_BASIC_INFORMATION* ptr64, uint32_t ptr32) {
	X32__ALPC_BASIC_INFORMATION* x32_used_ptr = (X32__ALPC_BASIC_INFORMATION*)ptr32;
	x32_used_ptr->Flags = (long unsigned int)ptr64->Flags;
	x32_used_ptr->SequenceNo = (long unsigned int)ptr64->SequenceNo;
	x32_used_ptr->PortContext = (X32_PVOID)ptr64->PortContext;
};

void convert__ALPC_SERVER_INFORMATION_64TO32(void* ctx, _ALPC_SERVER_INFORMATION* ptr64, uint32_t ptr32) {
	X32__ALPC_SERVER_INFORMATION* x32_used_ptr = (X32__ALPC_SERVER_INFORMATION*)ptr32;

//#pragma error('Here Ignored union fix it')
//	x32_used_ptr-> = (_ALPC_SERVER_INFORMATION)ptr64->;
};

void convert_MEM_EXTENDED_PARAMETER_64TO32(void* ctx, MEM_EXTENDED_PARAMETER* ptr64, uint32_t ptr32) {
	X32_MEM_EXTENDED_PARAMETER* x32_used_ptr = (X32_MEM_EXTENDED_PARAMETER*)ptr32;
	x32_used_ptr->Type = ptr64->Type;
	x32_used_ptr->Reserved = ptr64->Reserved;
	x32_used_ptr->ULong64 = ptr64->ULong64;
};

void convert_HANDLE_64TO32(void* ctx, HANDLE* ptr64, uint32_t ptr32) {
	X32_HANDLE* x32_used_ptr = (X32_HANDLE*)ptr32;
	*x32_used_ptr = (X32_HANDLE)HandleToHandle32(*ptr64);
};

void convert__FILE_IO_COMPLETION_INFORMATION_64TO32(void* ctx, _FILE_IO_COMPLETION_INFORMATION* ptr64, uint32_t ptr32) {
	X32__FILE_IO_COMPLETION_INFORMATION* x32_used_ptr = (X32__FILE_IO_COMPLETION_INFORMATION*)ptr32;
	x32_used_ptr->KeyContext = (X32_PVOID)ptr64->KeyContext;
	x32_used_ptr->ApcContext = (X32_PVOID)ptr64->ApcContext;
	NESTED_CVT_64TO32(_IO_STATUS_BLOCK, IoStatusBlock);
};

void convert__CLIENT_ID_64TO32(void* ctx, _CLIENT_ID* ptr64, uint32_t ptr32) {
	X32__CLIENT_ID* x32_used_ptr = (X32__CLIENT_ID*)ptr32;
	x32_used_ptr->UniqueProcess = (X32_PVOID)ptr64->UniqueProcess;
	x32_used_ptr->UniqueThread = (X32_PVOID)ptr64->UniqueThread;
};

void convert__PS_CREATE_INFO_64TO32(void* ctx, _PS_CREATE_INFO* ptr64, uint32_t ptr32) {
	X32__PS_CREATE_INFO* x32_used_ptr = (X32__PS_CREATE_INFO*)ptr32;
	x32_used_ptr->Size = (long long unsigned int)ptr64->Size;
	x32_used_ptr->State = (_PS_CREATE_STATE)ptr64->State;

//#pragma error('Here Ignored union fix it')
//	x32_used_ptr-> = (_PS_CREATE_INFO)ptr64->;
};

void convert__DBGUI_WAIT_STATE_CHANGE_64TO32(void* ctx, _DBGUI_WAIT_STATE_CHANGE* ptr64, uint32_t ptr32) {
	X32__DBGUI_WAIT_STATE_CHANGE* x32_used_ptr = (X32__DBGUI_WAIT_STATE_CHANGE*)ptr32;
	x32_used_ptr->NewState = (_DBG_STATE)ptr64->NewState;
	NESTED_CVT_64TO32(_CLIENT_ID, AppClientId);

//#pragma error('Here Ignored union fix it')
//	x32_used_ptr->StateInfo = (_DBGUI_WAIT_STATE_CHANGE)ptr64->StateInfo;
};

void convert__IO_STATUS_BLOCK_64TO32(void* ctx, _IO_STATUS_BLOCK* ptr64, uint32_t ptr32) {
	X32__IO_STATUS_BLOCK* x32_used_ptr = (X32__IO_STATUS_BLOCK*)ptr32;
	x32_used_ptr->Status = ptr64->Status;
	x32_used_ptr->Information = (long long unsigned int)ptr64->Information;
};

void convert__PORT_VIEW_64TO32(void* ctx, _PORT_VIEW* ptr64, uint32_t ptr32) {
	X32__PORT_VIEW* x32_used_ptr = (X32__PORT_VIEW*)ptr32;
	x32_used_ptr->Length = (long unsigned int)ptr64->Length;
	x32_used_ptr->SectionHandle = (X32_PVOID)ptr64->SectionHandle;
	x32_used_ptr->SectionOffset = (long unsigned int)ptr64->SectionOffset;
	x32_used_ptr->ViewSize = (long long unsigned int)ptr64->ViewSize;
	x32_used_ptr->ViewBase = (X32_PVOID)ptr64->ViewBase;
	x32_used_ptr->ViewRemoteBase = (X32_PVOID)ptr64->ViewRemoteBase;
};

void convert__REMOTE_PORT_VIEW_64TO32(void* ctx, _REMOTE_PORT_VIEW* ptr64, uint32_t ptr32) {
	X32__REMOTE_PORT_VIEW* x32_used_ptr = (X32__REMOTE_PORT_VIEW*)ptr32;
	x32_used_ptr->Length = (long unsigned int)ptr64->Length;
	x32_used_ptr->ViewSize = (long long unsigned int)ptr64->ViewSize;
	x32_used_ptr->ViewBase = (X32_PVOID)ptr64->ViewBase;
};

void convert__PORT_MESSAGE_64TO32(void* ctx, _PORT_MESSAGE* ptr64, uint32_t ptr32) {
	X32__PORT_MESSAGE* x32_used_ptr = (X32__PORT_MESSAGE*)ptr32;
	/*
#pragma error('Here Ignored union fix it')
	x32_used_ptr->u1 = (_PORT_MESSAGE)ptr64->u1;
#pragma error('Here Ignored union fix it')
	x32_used_ptr->u2 = (_PORT_MESSAGE)ptr64->u2;
#pragma error('Here Ignored union fix it')
	x32_used_ptr-> = (_PORT_MESSAGE)ptr64->;
	x32_used_ptr->MessageId = (long unsigned int)ptr64->MessageId;
#pragma error('Here Ignored union fix it')
	x32_used_ptr-> = (_PORT_MESSAGE)ptr64->;
	*/
};

void convert__ALPC_DATA_VIEW_ATTR_64TO32(void* ctx, _ALPC_DATA_VIEW_ATTR* ptr64, uint32_t ptr32) {
	X32__ALPC_DATA_VIEW_ATTR* x32_used_ptr = (X32__ALPC_DATA_VIEW_ATTR*)ptr32;
	x32_used_ptr->Flags = (long unsigned int)ptr64->Flags;
	x32_used_ptr->SectionHandle = (X32_PVOID)ptr64->SectionHandle;
	x32_used_ptr->ViewBase = (X32_PVOID)ptr64->ViewBase;
	x32_used_ptr->ViewSize = (long long unsigned int)ptr64->ViewSize;
};

void convert__ALPC_SECURITY_ATTR_64TO32(void* ctx, _ALPC_SECURITY_ATTR* ptr64, uint32_t ptr32) {
	X32__ALPC_SECURITY_ATTR* x32_used_ptr = (X32__ALPC_SECURITY_ATTR*)ptr32;
	x32_used_ptr->Flags = (long unsigned int)ptr64->Flags;
	//x32_used_ptr->QoS = (_SECURITY_QUALITY_OF_SERVICE*)ptr64->QoS;
	NESTED_CVT_64TO32(HANDLE, ContextHandle);
};

void convert__KEY_VALUE_ENTRY_64TO32(void* ctx, _KEY_VALUE_ENTRY* ptr64, uint32_t ptr32) {
	X32__KEY_VALUE_ENTRY* x32_used_ptr = (X32__KEY_VALUE_ENTRY*)ptr32;
//	x32_used_ptr->ValueName = (_UNICODE_STRING*)ptr64->ValueName;
	x32_used_ptr->DataLength = (long unsigned int)ptr64->DataLength;
	x32_used_ptr->DataOffset = (long unsigned int)ptr64->DataOffset;
	x32_used_ptr->Type = (long unsigned int)ptr64->Type;
};

void convert__TOKEN_GROUPS_64TO32(void* ctx, _TOKEN_GROUPS* ptr64, uint32_t ptr32) {
	X32__TOKEN_GROUPS* x32_used_ptr = (X32__TOKEN_GROUPS*)ptr32;
	x32_used_ptr->GroupCount = (long unsigned int)ptr64->GroupCount;

//	x32_used_ptr->Groups = (_SID_AND_ATTRIBUTES[1])ptr64->Groups;
};

void convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_64TO32(void* ctx, _TOKEN_SECURITY_ATTRIBUTES_INFORMATION* ptr64, uint32_t ptr32) {
	X32__TOKEN_SECURITY_ATTRIBUTES_INFORMATION* x32_used_ptr = (X32__TOKEN_SECURITY_ATTRIBUTES_INFORMATION*)ptr32;
	x32_used_ptr->Version = (short unsigned int)ptr64->Version;
	x32_used_ptr->Reserved = (short unsigned int)ptr64->Reserved;
	x32_used_ptr->AttributeCount = (long unsigned int)ptr64->AttributeCount;

	//#pragma error('Here Ignored union fix it')
//	x32_used_ptr->Attribute = (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)ptr64->Attribute;
};

void convert__TRANSACTION_NOTIFICATION_64TO32(void* ctx, _TRANSACTION_NOTIFICATION* ptr64, uint32_t ptr32) {
	X32__TRANSACTION_NOTIFICATION* x32_used_ptr = (X32__TRANSACTION_NOTIFICATION*)ptr32;
	x32_used_ptr->TransactionKey = (X32_PVOID)ptr64->TransactionKey;
	x32_used_ptr->TransactionNotification = (long unsigned int)ptr64->TransactionNotification;
	x32_used_ptr->TmVirtualClock = (LARGE_INTEGER)ptr64->TmVirtualClock;
	x32_used_ptr->ArgumentLength = (long unsigned int)ptr64->ArgumentLength;
};


#pragma warning(pop)