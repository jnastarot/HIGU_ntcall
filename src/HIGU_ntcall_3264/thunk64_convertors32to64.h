
#define NESTED_CVT_32TO64(type, var_name) \
	{\
		type * var_name = &(*ptr64)->##var_name;\
		convert_##type##_32TO64(ctx, &##var_name, (uint32_t)&x32_used_ptr->##var_name);\
	}

#define NESTED_CVT_32TO64_WITH_ALLOC(type, var_name) \
	{\
		if (x32_used_ptr->##var_name) {\
			type * var_name = (##type##*)intrnl__ntcallmalloc(ctx, sizeof(##type##));\
			convert_##type##_32TO64(ctx, &##var_name, (uint32_t)x32_used_ptr->##var_name);\
			(*ptr64)->##var_name = var_name ;\
		} else {\
			(*ptr64)->##var_name = 0;\
		}\
	}

#define CVT_COPY_STRING(type, var_name, var_len_name) __movsb((PBYTE)&(*ptr64)->##var_name[0], (PBYTE)&x32_used_ptr->##var_name[0], x32_used_ptr->##var_len_name);



void convert__SYSTEM_POOL_INFORMATION_32TO64(void* ctx, _SYSTEM_POOL_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_FILECACHE_INFORMATION_32TO64(void* ctx, _SYSTEM_FILECACHE_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_32TO64(void* ctx, _SYSTEM_REGISTRY_QUOTA_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_VERIFIER_INFORMATION_32TO64(void* ctx, _SYSTEM_VERIFIER_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_REF_TRACE_INFORMATION_32TO64(void* ctx, _SYSTEM_REF_TRACE_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_VERIFIER_INFORMATION_EX_32TO64(void* ctx, _SYSTEM_VERIFIER_INFORMATION_EX**, uint32_t ptr32);
void convert__SYSTEM_POLICY_INFORMATION_32TO64(void* ctx, _SYSTEM_POLICY_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_32TO64(void* ctx, _SYSTEM_LOGICAL_PROCESSOR_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_32TO64(void* ctx, _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX**, uint32_t ptr32);
void convert__SYSTEM_FEATURE_CONFIGURATION_INFORMATION_32TO64(void* ctx, _SYSTEM_FEATURE_CONFIGURATION_INFORMATION**, uint32_t ptr32);
void convert__UNICODE_STRING_32TO64(void* ctx, _UNICODE_STRING**, uint32_t ptr32);
void convert__SYSTEM_THREAD_CID_PRIORITY_INFORMATION_32TO64(void* ctx, _SYSTEM_THREAD_CID_PRIORITY_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_VERIFIER_FAULTS_INFORMATION_32TO64(void* ctx, _SYSTEM_VERIFIER_FAULTS_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS_32TO64(void* ctx, _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS**, uint32_t ptr32);
void convert__SYSTEM_ELAM_CERTIFICATE_INFORMATION_32TO64(void* ctx, _SYSTEM_ELAM_CERTIFICATE_INFORMATION**, uint32_t ptr32);
void convert__SYSTEM_ACTIVITY_MODERATION_EXE_STATE_32TO64(void* ctx, _SYSTEM_ACTIVITY_MODERATION_EXE_STATE**, uint32_t ptr32);
void convert__QUOTA_LIMITS_32TO64(void* ctx, _QUOTA_LIMITS**, uint32_t ptr32);
void convert__PROCESS_EXCEPTION_PORT_32TO64(void* ctx, _PROCESS_EXCEPTION_PORT**, uint32_t ptr32);
void convert__PROCESS_ACCESS_TOKEN_32TO64(void* ctx, _PROCESS_ACCESS_TOKEN**, uint32_t ptr32);
void convert__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32TO64(void* ctx, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION**, uint32_t ptr32);
void convert__PROCESS_STACK_ALLOCATION_INFORMATION_32TO64(void* ctx, _PROCESS_STACK_ALLOCATION_INFORMATION**, uint32_t ptr32);
void convert__PROCESS_MEMORY_EXHAUSTION_INFO_32TO64(void* ctx, _PROCESS_MEMORY_EXHAUSTION_INFO**, uint32_t ptr32);
void convert__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION_32TO64(void* ctx, _PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION**, uint32_t ptr32);
void convert__GROUP_AFFINITY_32TO64(void* ctx, _GROUP_AFFINITY**, uint32_t ptr32);
void convert__THREAD_PROFILING_INFORMATION_32TO64(void* ctx, _THREAD_PROFILING_INFORMATION**, uint32_t ptr32);
void convert__THREAD_NAME_INFORMATION_32TO64(void* ctx, _THREAD_NAME_INFORMATION**, uint32_t ptr32);
void convert__FILE_RENAME_INFORMATION_32TO64(void* ctx, _FILE_RENAME_INFORMATION**, uint32_t ptr32);
void convert__FILE_LINK_INFORMATION_32TO64(void* ctx, _FILE_LINK_INFORMATION**, uint32_t ptr32);
void convert__FILE_MAILSLOT_SET_INFORMATION_32TO64(void* ctx, _FILE_MAILSLOT_SET_INFORMATION**, uint32_t ptr32);
void convert__FILE_COMPLETION_INFORMATION_32TO64(void* ctx, _FILE_COMPLETION_INFORMATION**, uint32_t ptr32);
void convert__FILE_MOVE_CLUSTER_INFORMATION_32TO64(void* ctx, _FILE_MOVE_CLUSTER_INFORMATION**, uint32_t ptr32);
void convert__FILE_TRACKING_INFORMATION_32TO64(void* ctx, _FILE_TRACKING_INFORMATION**, uint32_t ptr32);
void convert__FILE_IOSTATUSBLOCK_RANGE_INFORMATION_32TO64(void* ctx, _FILE_IOSTATUSBLOCK_RANGE_INFORMATION**, uint32_t ptr32);
void convert__FILE_RENAME_INFORMATION_EX_32TO64(void* ctx, _FILE_RENAME_INFORMATION_EX**, uint32_t ptr32);
void convert__FILE_MEMORY_PARTITION_INFORMATION_32TO64(void* ctx, _FILE_MEMORY_PARTITION_INFORMATION**, uint32_t ptr32);
void convert__FILE_LINK_INFORMATION_EX_32TO64(void* ctx, _FILE_LINK_INFORMATION_EX**, uint32_t ptr32);
void convert__ALPC_BASIC_INFORMATION_32TO64(void* ctx, _ALPC_BASIC_INFORMATION**, uint32_t ptr32);
void convert__ALPC_PORT_ATTRIBUTES_32TO64(void* ctx, _ALPC_PORT_ATTRIBUTES**, uint32_t ptr32);
void convert__ALPC_PORT_ASSOCIATE_COMPLETION_PORT_32TO64(void* ctx, _ALPC_PORT_ASSOCIATE_COMPLETION_PORT**, uint32_t ptr32);
void convert__ALPC_PORT_MESSAGE_ZONE_INFORMATION_32TO64(void* ctx, _ALPC_PORT_MESSAGE_ZONE_INFORMATION**, uint32_t ptr32);
void convert__ALPC_PORT_COMPLETION_LIST_INFORMATION_32TO64(void* ctx, _ALPC_PORT_COMPLETION_LIST_INFORMATION**, uint32_t ptr32);
void convert_MEM_EXTENDED_PARAMETER_32TO64(void* ctx, MEM_EXTENDED_PARAMETER**, uint32_t ptr32);
void convert__OBJECT_ATTRIBUTES_32TO64(void* ctx, _OBJECT_ATTRIBUTES**, uint32_t ptr32);
void convert_HANDLE_32TO64(void* ctx, HANDLE**, uint32_t ptr32);
void convert__MEMORY_RANGE_ENTRY_32TO64(void* ctx, _MEMORY_RANGE_ENTRY**, uint32_t ptr32);
void convert__CLIENT_ID_32TO64(void* ctx, _CLIENT_ID**, uint32_t ptr32);
void convert__INITIAL_TEB_32TO64(void* ctx, _INITIAL_TEB**, uint32_t ptr32);
void convert__PS_CREATE_INFO_32TO64(void* ctx, _PS_CREATE_INFO**, uint32_t ptr32);
void convert__PS_ATTRIBUTE_LIST_32TO64(void* ctx, _PS_ATTRIBUTE_LIST**, uint32_t ptr32);
void convert__JOB_SET_ARRAY_32TO64(void* ctx, _JOB_SET_ARRAY**, uint32_t ptr32);
void convert__IO_STATUS_BLOCK_32TO64(void* ctx, _IO_STATUS_BLOCK**, uint32_t ptr32);
void convert__FILE_SEGMENT_ELEMENT_32TO64(void* ctx, _FILE_SEGMENT_ELEMENT**, uint32_t ptr32);
void convert__PORT_VIEW_32TO64(void* ctx, _PORT_VIEW**, uint32_t ptr32);
void convert__REMOTE_PORT_VIEW_32TO64(void* ctx, _REMOTE_PORT_VIEW**, uint32_t ptr32);
void convert__PORT_MESSAGE_32TO64(void* ctx, _PORT_MESSAGE**, uint32_t ptr32);
void convert__ALPC_DATA_VIEW_ATTR_32TO64(void* ctx, _ALPC_DATA_VIEW_ATTR**, uint32_t ptr32);
void convert__ALPC_SECURITY_ATTR_32TO64(void* ctx, _ALPC_SECURITY_ATTR**, uint32_t ptr32);
void convert__ALPC_CONTEXT_ATTR_32TO64(void* ctx, _ALPC_CONTEXT_ATTR**, uint32_t ptr32);
void convert__KEY_VALUE_ENTRY_32TO64(void* ctx, _KEY_VALUE_ENTRY**, uint32_t ptr32);
void convert__TOKEN_USER_32TO64(void* ctx, _TOKEN_USER**, uint32_t ptr32);
void convert__TOKEN_GROUPS_32TO64(void* ctx, _TOKEN_GROUPS**, uint32_t ptr32);
void convert__TOKEN_OWNER_32TO64(void* ctx, _TOKEN_OWNER**, uint32_t ptr32);
void convert__TOKEN_PRIMARY_GROUP_32TO64(void* ctx, _TOKEN_PRIMARY_GROUP**, uint32_t ptr32);
void convert__TOKEN_DEFAULT_DACL_32TO64(void* ctx, _TOKEN_DEFAULT_DACL**, uint32_t ptr32);
void convert__SID_AND_ATTRIBUTES_32TO64(void* ctx, _SID_AND_ATTRIBUTES**, uint32_t ptr32);
void convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(void* ctx, _TOKEN_SECURITY_ATTRIBUTES_INFORMATION**, uint32_t ptr32);
void convert__OBJECT_TYPE_LIST_32TO64(void* ctx, _OBJECT_TYPE_LIST**, uint32_t ptr32);
void convert__EXCEPTION_RECORD_32TO64(void* ctx, _EXCEPTION_RECORD**, uint32_t ptr32);


void convert__SYSTEM_POOL_INFORMATION_32TO64(void* ctx, _SYSTEM_POOL_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_POOL_INFORMATION* x32_used_ptr = (X32__SYSTEM_POOL_INFORMATION*)ptr32;
	(*ptr64)->TotalSize = (long long unsigned int)x32_used_ptr->TotalSize;
	(*ptr64)->FirstEntry = (void*)x32_used_ptr->FirstEntry;
	(*ptr64)->EntryOverhead = (short unsigned int)x32_used_ptr->EntryOverhead;
	(*ptr64)->PoolTagPresent = (unsigned char)x32_used_ptr->PoolTagPresent;
	(*ptr64)->Spare0 = (unsigned char)x32_used_ptr->Spare0;
	(*ptr64)->NumberOfEntries = (long unsigned int)x32_used_ptr->NumberOfEntries;


	//(*ptr64)->Entries = (_SYSTEM_POOL_ENTRY[1])x32_used_ptr->Entries;
};

void convert__SYSTEM_FILECACHE_INFORMATION_32TO64(void* ctx, _SYSTEM_FILECACHE_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_FILECACHE_INFORMATION* x32_used_ptr = (X32__SYSTEM_FILECACHE_INFORMATION*)ptr32;
	(*ptr64)->CurrentSize = (long long unsigned int)x32_used_ptr->CurrentSize;
	(*ptr64)->PeakSize = (long long unsigned int)x32_used_ptr->PeakSize;
	(*ptr64)->PageFaultCount = (long unsigned int)x32_used_ptr->PageFaultCount;
	(*ptr64)->MinimumWorkingSet = (long long unsigned int)x32_used_ptr->MinimumWorkingSet;
	(*ptr64)->MaximumWorkingSet = (long long unsigned int)x32_used_ptr->MaximumWorkingSet;
	(*ptr64)->CurrentSizeIncludingTransitionInPages = (long long unsigned int)x32_used_ptr->CurrentSizeIncludingTransitionInPages;
	(*ptr64)->PeakSizeIncludingTransitionInPages = (long long unsigned int)x32_used_ptr->PeakSizeIncludingTransitionInPages;
	(*ptr64)->TransitionRePurposeCount = (long unsigned int)x32_used_ptr->TransitionRePurposeCount;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
};

void convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_32TO64(void* ctx, _SYSTEM_REGISTRY_QUOTA_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_REGISTRY_QUOTA_INFORMATION* x32_used_ptr = (X32__SYSTEM_REGISTRY_QUOTA_INFORMATION*)ptr32;
	(*ptr64)->RegistryQuotaAllowed = (long unsigned int)x32_used_ptr->RegistryQuotaAllowed;
	(*ptr64)->RegistryQuotaUsed = (long unsigned int)x32_used_ptr->RegistryQuotaUsed;
	(*ptr64)->PagedPoolSize = (long long unsigned int)x32_used_ptr->PagedPoolSize;
};

void convert__SYSTEM_VERIFIER_INFORMATION_32TO64(void* ctx, _SYSTEM_VERIFIER_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_VERIFIER_INFORMATION* x32_used_ptr = (X32__SYSTEM_VERIFIER_INFORMATION*)ptr32;
	(*ptr64)->NextEntryOffset = (long unsigned int)x32_used_ptr->NextEntryOffset;
	(*ptr64)->Level = (long unsigned int)x32_used_ptr->Level;
	
	(*ptr64)->RuleClasses[0] = (long unsigned int)x32_used_ptr->RuleClasses[0];
	(*ptr64)->RuleClasses[1] = (long unsigned int)x32_used_ptr->RuleClasses[1];

	(*ptr64)->TriageContext = (long unsigned int)x32_used_ptr->TriageContext;
	(*ptr64)->AreAllDriversBeingVerified = (long unsigned int)x32_used_ptr->AreAllDriversBeingVerified;
	
	NESTED_CVT_32TO64(_UNICODE_STRING, DriverName);

	(*ptr64)->RaiseIrqls = (long unsigned int)x32_used_ptr->RaiseIrqls;
	(*ptr64)->AcquireSpinLocks = (long unsigned int)x32_used_ptr->AcquireSpinLocks;
	(*ptr64)->SynchronizeExecutions = (long unsigned int)x32_used_ptr->SynchronizeExecutions;
	(*ptr64)->AllocationsAttempted = (long unsigned int)x32_used_ptr->AllocationsAttempted;
	(*ptr64)->AllocationsSucceeded = (long unsigned int)x32_used_ptr->AllocationsSucceeded;
	(*ptr64)->AllocationsSucceededSpecialPool = (long unsigned int)x32_used_ptr->AllocationsSucceededSpecialPool;
	(*ptr64)->AllocationsWithNoTag = (long unsigned int)x32_used_ptr->AllocationsWithNoTag;
	(*ptr64)->TrimRequests = (long unsigned int)x32_used_ptr->TrimRequests;
	(*ptr64)->Trims = (long unsigned int)x32_used_ptr->Trims;
	(*ptr64)->AllocationsFailed = (long unsigned int)x32_used_ptr->AllocationsFailed;
	(*ptr64)->AllocationsFailedDeliberately = (long unsigned int)x32_used_ptr->AllocationsFailedDeliberately;
	(*ptr64)->Loads = (long unsigned int)x32_used_ptr->Loads;
	(*ptr64)->Unloads = (long unsigned int)x32_used_ptr->Unloads;
	(*ptr64)->UnTrackedPool = (long unsigned int)x32_used_ptr->UnTrackedPool;
	(*ptr64)->CurrentPagedPoolAllocations = (long unsigned int)x32_used_ptr->CurrentPagedPoolAllocations;
	(*ptr64)->CurrentNonPagedPoolAllocations = (long unsigned int)x32_used_ptr->CurrentNonPagedPoolAllocations;
	(*ptr64)->PeakPagedPoolAllocations = (long unsigned int)x32_used_ptr->PeakPagedPoolAllocations;
	(*ptr64)->PeakNonPagedPoolAllocations = (long unsigned int)x32_used_ptr->PeakNonPagedPoolAllocations;
	(*ptr64)->PagedPoolUsageInBytes = (long long unsigned int)x32_used_ptr->PagedPoolUsageInBytes;
	(*ptr64)->NonPagedPoolUsageInBytes = (long long unsigned int)x32_used_ptr->NonPagedPoolUsageInBytes;
	(*ptr64)->PeakPagedPoolUsageInBytes = (long long unsigned int)x32_used_ptr->PeakPagedPoolUsageInBytes;
	(*ptr64)->PeakNonPagedPoolUsageInBytes = (long long unsigned int)x32_used_ptr->PeakNonPagedPoolUsageInBytes;
};

void convert__SYSTEM_REF_TRACE_INFORMATION_32TO64(void* ctx, _SYSTEM_REF_TRACE_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_REF_TRACE_INFORMATION* x32_used_ptr = (X32__SYSTEM_REF_TRACE_INFORMATION*)ptr32;
	(*ptr64)->TraceEnable = (unsigned char)x32_used_ptr->TraceEnable;
	(*ptr64)->TracePermanent = (unsigned char)x32_used_ptr->TracePermanent;

	NESTED_CVT_32TO64(_UNICODE_STRING, TraceProcessName);
	NESTED_CVT_32TO64(_UNICODE_STRING, TracePoolTags);
};

void convert__SYSTEM_VERIFIER_INFORMATION_EX_32TO64(void* ctx, _SYSTEM_VERIFIER_INFORMATION_EX** ptr64, uint32_t ptr32) {
	X32__SYSTEM_VERIFIER_INFORMATION_EX* x32_used_ptr = (X32__SYSTEM_VERIFIER_INFORMATION_EX*)ptr32;
	(*ptr64)->VerifyMode = (long unsigned int)x32_used_ptr->VerifyMode;
	(*ptr64)->OptionChanges = (long unsigned int)x32_used_ptr->OptionChanges;
	NESTED_CVT_32TO64(_UNICODE_STRING, PreviousBucketName);
	(*ptr64)->IrpCancelTimeoutMsec = (long unsigned int)x32_used_ptr->IrpCancelTimeoutMsec;
	(*ptr64)->VerifierExtensionEnabled = (long unsigned int)x32_used_ptr->VerifierExtensionEnabled;
	//(*ptr64)->Reserved = (long unsigned int[1])x32_used_ptr->Reserved;
};

void convert__SYSTEM_POLICY_INFORMATION_32TO64(void* ctx, _SYSTEM_POLICY_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_POLICY_INFORMATION* x32_used_ptr = (X32__SYSTEM_POLICY_INFORMATION*)ptr32;
	(*ptr64)->InputData = (void*)x32_used_ptr->InputData;
	(*ptr64)->OutputData = (void*)x32_used_ptr->OutputData;
	(*ptr64)->InputDataSize = (long unsigned int)x32_used_ptr->InputDataSize;
	(*ptr64)->OutputDataSize = (long unsigned int)x32_used_ptr->OutputDataSize;
	(*ptr64)->Version = (long unsigned int)x32_used_ptr->Version;
};

void convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_32TO64(void* ctx, _SYSTEM_LOGICAL_PROCESSOR_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION* x32_used_ptr = (X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)ptr32;
	(*ptr64)->ProcessorMask = (long long unsigned int)x32_used_ptr->ProcessorMask;
	(*ptr64)->Relationship = (_LOGICAL_PROCESSOR_RELATIONSHIP)x32_used_ptr->Relationship;
//#pragma error('Here Ignored union fix it')
	//(*ptr64)-> = (_SYSTEM_LOGICAL_PROCESSOR_INFORMATION)x32_used_ptr->;
};

void convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_32TO64(void* ctx, _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX** ptr64, uint32_t ptr32) {
	X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* x32_used_ptr = (X32__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)ptr32;
	(*ptr64)->Relationship = (_LOGICAL_PROCESSOR_RELATIONSHIP)x32_used_ptr->Relationship;
	(*ptr64)->Size = (long unsigned int)x32_used_ptr->Size;
//#pragma error('Here Ignored union fix it')
	//(*ptr64)-> = (_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)x32_used_ptr->;
};

void convert__SYSTEM_FEATURE_CONFIGURATION_INFORMATION_32TO64(void* ctx, _SYSTEM_FEATURE_CONFIGURATION_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_FEATURE_CONFIGURATION_INFORMATION* x32_used_ptr = (X32__SYSTEM_FEATURE_CONFIGURATION_INFORMATION*)ptr32;
	(*ptr64)->ChangeStamp = (long long unsigned int)x32_used_ptr->ChangeStamp;
	(*ptr64)->Configuration = (_RTL_FEATURE_CONFIGURATION*)x32_used_ptr->Configuration;
};

void convert__UNICODE_STRING_32TO64(void* ctx, _UNICODE_STRING** ptr64, uint32_t ptr32) {
	X32__UNICODE_STRING* x32_used_ptr = (X32__UNICODE_STRING*)ptr32;
	(*ptr64)->Length = (short unsigned int)x32_used_ptr->Length;
	(*ptr64)->MaximumLength = (short unsigned int)x32_used_ptr->MaximumLength;
	(*ptr64)->Buffer = (wchar_t*)x32_used_ptr->Buffer;
};

void convert__SYSTEM_THREAD_CID_PRIORITY_INFORMATION_32TO64(void* ctx, _SYSTEM_THREAD_CID_PRIORITY_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_THREAD_CID_PRIORITY_INFORMATION* x32_used_ptr = (X32__SYSTEM_THREAD_CID_PRIORITY_INFORMATION*)ptr32;
	NESTED_CVT_32TO64(_CLIENT_ID, ClientId);
	(*ptr64)->Priority = (long int)x32_used_ptr->Priority;
};

void convert__SYSTEM_VERIFIER_FAULTS_INFORMATION_32TO64(void* ctx, _SYSTEM_VERIFIER_FAULTS_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_VERIFIER_FAULTS_INFORMATION* x32_used_ptr = (X32__SYSTEM_VERIFIER_FAULTS_INFORMATION*)ptr32;
	(*ptr64)->Probability = (long unsigned int)x32_used_ptr->Probability;
	(*ptr64)->MaxProbability = (long unsigned int)x32_used_ptr->MaxProbability;

	NESTED_CVT_32TO64(_UNICODE_STRING, PoolTags);
	NESTED_CVT_32TO64(_UNICODE_STRING, Applications);
};

void convert__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS_32TO64(void* ctx, _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS** ptr64, uint32_t ptr32) {
	X32__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS* x32_used_ptr = (X32__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS*)ptr32;
	(*ptr64)->KeyHandle = (void*)x32_used_ptr->KeyHandle;
	
	NESTED_CVT_32TO64_WITH_ALLOC(_UNICODE_STRING, ValueNamePointer);

	(*ptr64)->RequiredLengthPointer = (long unsigned int*)x32_used_ptr->RequiredLengthPointer;
	(*ptr64)->Buffer = (unsigned char*)x32_used_ptr->Buffer;
	(*ptr64)->BufferLength = (long unsigned int)x32_used_ptr->BufferLength;
	(*ptr64)->Type = (long unsigned int)x32_used_ptr->Type;
	(*ptr64)->AppendBuffer = (unsigned char*)x32_used_ptr->AppendBuffer;
	(*ptr64)->AppendBufferLength = (long unsigned int)x32_used_ptr->AppendBufferLength;
	(*ptr64)->CreateIfDoesntExist = (unsigned char)x32_used_ptr->CreateIfDoesntExist;
	(*ptr64)->TruncateExistingValue = (unsigned char)x32_used_ptr->TruncateExistingValue;
};

void convert__SYSTEM_ELAM_CERTIFICATE_INFORMATION_32TO64(void* ctx, _SYSTEM_ELAM_CERTIFICATE_INFORMATION** ptr64, uint32_t ptr32) {
	X32__SYSTEM_ELAM_CERTIFICATE_INFORMATION* x32_used_ptr = (X32__SYSTEM_ELAM_CERTIFICATE_INFORMATION*)ptr32;
	(*ptr64)->ElamDriverFile = (void*)x32_used_ptr->ElamDriverFile;
};

void convert__SYSTEM_ACTIVITY_MODERATION_EXE_STATE_32TO64(void* ctx, _SYSTEM_ACTIVITY_MODERATION_EXE_STATE** ptr64, uint32_t ptr32) {
	X32__SYSTEM_ACTIVITY_MODERATION_EXE_STATE* x32_used_ptr = (X32__SYSTEM_ACTIVITY_MODERATION_EXE_STATE*)ptr32;
	
	NESTED_CVT_32TO64(_UNICODE_STRING, ExePathNt);

	(*ptr64)->ModerationState = (_SYSTEM_ACTIVITY_MODERATION_STATE)x32_used_ptr->ModerationState;
};

void convert__QUOTA_LIMITS_32TO64(void* ctx, _QUOTA_LIMITS** ptr64, uint32_t ptr32) {
	X32__QUOTA_LIMITS* x32_used_ptr = (X32__QUOTA_LIMITS*)ptr32;
	(*ptr64)->PagedPoolLimit = (long long unsigned int)x32_used_ptr->PagedPoolLimit;
	(*ptr64)->NonPagedPoolLimit = (long long unsigned int)x32_used_ptr->NonPagedPoolLimit;
	(*ptr64)->MinimumWorkingSetSize = (long long unsigned int)x32_used_ptr->MinimumWorkingSetSize;
	(*ptr64)->MaximumWorkingSetSize = (long long unsigned int)x32_used_ptr->MaximumWorkingSetSize;
	(*ptr64)->PagefileLimit = (long long unsigned int)x32_used_ptr->PagefileLimit;
	(*ptr64)->TimeLimit = (LARGE_INTEGER)x32_used_ptr->TimeLimit;
};

void convert__PROCESS_EXCEPTION_PORT_32TO64(void* ctx, _PROCESS_EXCEPTION_PORT** ptr64, uint32_t ptr32) {
	X32__PROCESS_EXCEPTION_PORT* x32_used_ptr = (X32__PROCESS_EXCEPTION_PORT*)ptr32;
	(*ptr64)->ExceptionPortHandle = (void*)x32_used_ptr->ExceptionPortHandle;
	(*ptr64)->StateFlags = (long unsigned int)x32_used_ptr->StateFlags;
};

void convert__PROCESS_ACCESS_TOKEN_32TO64(void* ctx, _PROCESS_ACCESS_TOKEN** ptr64, uint32_t ptr32) {
	X32__PROCESS_ACCESS_TOKEN* x32_used_ptr = (X32__PROCESS_ACCESS_TOKEN*)ptr32;
	(*ptr64)->Token = (void*)x32_used_ptr->Token;
	(*ptr64)->Thread = (void*)x32_used_ptr->Thread;
};

void convert__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32TO64(void* ctx, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION** ptr64, uint32_t ptr32) {
	X32__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION* x32_used_ptr = (X32__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION*)ptr32;
	(*ptr64)->Version = (long unsigned int)x32_used_ptr->Version;
	(*ptr64)->Reserved = (long unsigned int)x32_used_ptr->Reserved;
	(*ptr64)->Callback = (void*)x32_used_ptr->Callback;
};

void convert__PROCESS_STACK_ALLOCATION_INFORMATION_32TO64(void* ctx, _PROCESS_STACK_ALLOCATION_INFORMATION** ptr64, uint32_t ptr32) {
	X32__PROCESS_STACK_ALLOCATION_INFORMATION* x32_used_ptr = (X32__PROCESS_STACK_ALLOCATION_INFORMATION*)ptr32;
	(*ptr64)->ReserveSize = (long long unsigned int)x32_used_ptr->ReserveSize;
	(*ptr64)->ZeroBits = (long long unsigned int)x32_used_ptr->ZeroBits;
	(*ptr64)->StackBase = (void*)x32_used_ptr->StackBase;
};

void convert__PROCESS_MEMORY_EXHAUSTION_INFO_32TO64(void* ctx, _PROCESS_MEMORY_EXHAUSTION_INFO** ptr64, uint32_t ptr32) {
	X32__PROCESS_MEMORY_EXHAUSTION_INFO* x32_used_ptr = (X32__PROCESS_MEMORY_EXHAUSTION_INFO*)ptr32;
	(*ptr64)->Version = (short unsigned int)x32_used_ptr->Version;
	(*ptr64)->Reserved = (short unsigned int)x32_used_ptr->Reserved;
	(*ptr64)->Type = (_PROCESS_MEMORY_EXHAUSTION_TYPE)x32_used_ptr->Type;
	(*ptr64)->Value = (long long unsigned int)x32_used_ptr->Value;
};

void convert__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION_32TO64(void* ctx, _PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION** ptr64, uint32_t ptr32) {
	X32__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION* x32_used_ptr = (X32__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION*)ptr32;
	(*ptr64)->ProcessHandle = (void*)x32_used_ptr->ProcessHandle;
};

void convert__GROUP_AFFINITY_32TO64(void* ctx, _GROUP_AFFINITY** ptr64, uint32_t ptr32) {
	X32__GROUP_AFFINITY* x32_used_ptr = (X32__GROUP_AFFINITY*)ptr32;
	(*ptr64)->Mask = (long long unsigned int)x32_used_ptr->Mask;
	(*ptr64)->Group = (short unsigned int)x32_used_ptr->Group;
	(*ptr64)->Reserved[0] = (short unsigned int)x32_used_ptr->Reserved[0];
	(*ptr64)->Reserved[1] = (short unsigned int)x32_used_ptr->Reserved[1];
	(*ptr64)->Reserved[2] = (short unsigned int)x32_used_ptr->Reserved[2];

};

void convert__THREAD_PROFILING_INFORMATION_32TO64(void* ctx, _THREAD_PROFILING_INFORMATION** ptr64, uint32_t ptr32) {
	X32__THREAD_PROFILING_INFORMATION* x32_used_ptr = (X32__THREAD_PROFILING_INFORMATION*)ptr32;
	(*ptr64)->HardwareCounters = (long long unsigned int)x32_used_ptr->HardwareCounters;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->Enable = (long unsigned int)x32_used_ptr->Enable;
	(*ptr64)->PerformanceData = (_THREAD_PERFORMANCE_DATA*)x32_used_ptr->PerformanceData;
};

void convert__THREAD_NAME_INFORMATION_32TO64(void* ctx, _THREAD_NAME_INFORMATION** ptr64, uint32_t ptr32) {
	X32__THREAD_NAME_INFORMATION* x32_used_ptr = (X32__THREAD_NAME_INFORMATION*)ptr32;

	NESTED_CVT_32TO64(_UNICODE_STRING, ThreadName);
};

void convert__FILE_RENAME_INFORMATION_32TO64(void* ctx, _FILE_RENAME_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_RENAME_INFORMATION* x32_used_ptr = (X32__FILE_RENAME_INFORMATION*)ptr32;
	(*ptr64)->ReplaceIfExists = (unsigned char)x32_used_ptr->ReplaceIfExists;
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;
	(*ptr64)->FileNameLength = (long unsigned int)x32_used_ptr->FileNameLength;
	
	CVT_COPY_STRING(wchar_t, FileName, FileNameLength);
};

void convert__FILE_LINK_INFORMATION_32TO64(void* ctx, _FILE_LINK_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_LINK_INFORMATION* x32_used_ptr = (X32__FILE_LINK_INFORMATION*)ptr32;
	(*ptr64)->ReplaceIfExists = (unsigned char)x32_used_ptr->ReplaceIfExists;
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;
	(*ptr64)->FileNameLength = (long unsigned int)x32_used_ptr->FileNameLength;

	CVT_COPY_STRING(wchar_t, FileName, FileNameLength);
};

void convert__FILE_MAILSLOT_SET_INFORMATION_32TO64(void* ctx, _FILE_MAILSLOT_SET_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_MAILSLOT_SET_INFORMATION* x32_used_ptr = (X32__FILE_MAILSLOT_SET_INFORMATION*)ptr32;
	(*ptr64)->ReadTimeout = (_LARGE_INTEGER*)x32_used_ptr->ReadTimeout;
};

void convert__FILE_COMPLETION_INFORMATION_32TO64(void* ctx, _FILE_COMPLETION_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_COMPLETION_INFORMATION* x32_used_ptr = (X32__FILE_COMPLETION_INFORMATION*)ptr32;
	(*ptr64)->Port = (void*)x32_used_ptr->Port;
	(*ptr64)->Key = (void*)x32_used_ptr->Key;
};

void convert__FILE_MOVE_CLUSTER_INFORMATION_32TO64(void* ctx, _FILE_MOVE_CLUSTER_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_MOVE_CLUSTER_INFORMATION* x32_used_ptr = (X32__FILE_MOVE_CLUSTER_INFORMATION*)ptr32;
	(*ptr64)->ClusterCount = (long unsigned int)x32_used_ptr->ClusterCount;
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;
	(*ptr64)->FileNameLength = (long unsigned int)x32_used_ptr->FileNameLength;

	CVT_COPY_STRING(wchar_t, FileName, FileNameLength);
};

void convert__FILE_TRACKING_INFORMATION_32TO64(void* ctx, _FILE_TRACKING_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_TRACKING_INFORMATION* x32_used_ptr = (X32__FILE_TRACKING_INFORMATION*)ptr32;
	(*ptr64)->DestinationFile = (void*)x32_used_ptr->DestinationFile;
	(*ptr64)->ObjectInformationLength = (long unsigned int)x32_used_ptr->ObjectInformationLength;

//	(*ptr64)->ObjectInformation = (char[1])x32_used_ptr->ObjectInformation;
};

void convert__FILE_IOSTATUSBLOCK_RANGE_INFORMATION_32TO64(void* ctx, _FILE_IOSTATUSBLOCK_RANGE_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_IOSTATUSBLOCK_RANGE_INFORMATION* x32_used_ptr = (X32__FILE_IOSTATUSBLOCK_RANGE_INFORMATION*)ptr32;
	(*ptr64)->IoStatusBlockRange = (unsigned char*)x32_used_ptr->IoStatusBlockRange;
	(*ptr64)->Length = (long unsigned int)x32_used_ptr->Length;
};

void convert__FILE_RENAME_INFORMATION_EX_32TO64(void* ctx, _FILE_RENAME_INFORMATION_EX** ptr64, uint32_t ptr32) {
	X32__FILE_RENAME_INFORMATION_EX* x32_used_ptr = (X32__FILE_RENAME_INFORMATION_EX*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;
	(*ptr64)->FileNameLength = (long unsigned int)x32_used_ptr->FileNameLength;
	
	CVT_COPY_STRING(wchar_t, FileName, FileNameLength);
};

void convert__FILE_MEMORY_PARTITION_INFORMATION_32TO64(void* ctx, _FILE_MEMORY_PARTITION_INFORMATION** ptr64, uint32_t ptr32) {
	X32__FILE_MEMORY_PARTITION_INFORMATION* x32_used_ptr = (X32__FILE_MEMORY_PARTITION_INFORMATION*)ptr32;
	(*ptr64)->OwnerPartitionHandle = (void*)x32_used_ptr->OwnerPartitionHandle;

//#pragma error('Here Ignored union fix it')
	//(*ptr64)->Flags = (_FILE_MEMORY_PARTITION_INFORMATION)x32_used_ptr->Flags;
};

void convert__FILE_LINK_INFORMATION_EX_32TO64(void* ctx, _FILE_LINK_INFORMATION_EX** ptr64, uint32_t ptr32) {
	X32__FILE_LINK_INFORMATION_EX* x32_used_ptr = (X32__FILE_LINK_INFORMATION_EX*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;
	(*ptr64)->FileNameLength = (long unsigned int)x32_used_ptr->FileNameLength;

	CVT_COPY_STRING(wchar_t, FileName, FileNameLength);
};

void convert__ALPC_BASIC_INFORMATION_32TO64(void* ctx, _ALPC_BASIC_INFORMATION** ptr64, uint32_t ptr32) {
	X32__ALPC_BASIC_INFORMATION* x32_used_ptr = (X32__ALPC_BASIC_INFORMATION*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->SequenceNo = (long unsigned int)x32_used_ptr->SequenceNo;
	(*ptr64)->PortContext = (void*)x32_used_ptr->PortContext;
};

void convert__ALPC_PORT_ATTRIBUTES_32TO64(void* ctx, _ALPC_PORT_ATTRIBUTES** ptr64, uint32_t ptr32) {
	X32__ALPC_PORT_ATTRIBUTES* x32_used_ptr = (X32__ALPC_PORT_ATTRIBUTES*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->SecurityQos = (_SECURITY_QUALITY_OF_SERVICE)x32_used_ptr->SecurityQos;
	(*ptr64)->MaxMessageLength = (long long unsigned int)x32_used_ptr->MaxMessageLength;
	(*ptr64)->MemoryBandwidth = (long long unsigned int)x32_used_ptr->MemoryBandwidth;
	(*ptr64)->MaxPoolUsage = (long long unsigned int)x32_used_ptr->MaxPoolUsage;
	(*ptr64)->MaxSectionSize = (long long unsigned int)x32_used_ptr->MaxSectionSize;
	(*ptr64)->MaxViewSize = (long long unsigned int)x32_used_ptr->MaxViewSize;
	(*ptr64)->MaxTotalSectionSize = (long long unsigned int)x32_used_ptr->MaxTotalSectionSize;
	(*ptr64)->DupObjectTypes = (long unsigned int)x32_used_ptr->DupObjectTypes;
	(*ptr64)->Reserved = (long unsigned int)x32_used_ptr->Reserved;
};

void convert__ALPC_PORT_ASSOCIATE_COMPLETION_PORT_32TO64(void* ctx, _ALPC_PORT_ASSOCIATE_COMPLETION_PORT** ptr64, uint32_t ptr32) {
	X32__ALPC_PORT_ASSOCIATE_COMPLETION_PORT* x32_used_ptr = (X32__ALPC_PORT_ASSOCIATE_COMPLETION_PORT*)ptr32;
	(*ptr64)->CompletionKey = (void*)x32_used_ptr->CompletionKey;
	(*ptr64)->CompletionPort = (void*)x32_used_ptr->CompletionPort;
};

void convert__ALPC_PORT_MESSAGE_ZONE_INFORMATION_32TO64(void* ctx, _ALPC_PORT_MESSAGE_ZONE_INFORMATION** ptr64, uint32_t ptr32) {
	X32__ALPC_PORT_MESSAGE_ZONE_INFORMATION* x32_used_ptr = (X32__ALPC_PORT_MESSAGE_ZONE_INFORMATION*)ptr32;
	(*ptr64)->Buffer = (void*)x32_used_ptr->Buffer;
	(*ptr64)->Size = (long unsigned int)x32_used_ptr->Size;
};

void convert__ALPC_PORT_COMPLETION_LIST_INFORMATION_32TO64(void* ctx, _ALPC_PORT_COMPLETION_LIST_INFORMATION** ptr64, uint32_t ptr32) {
	X32__ALPC_PORT_COMPLETION_LIST_INFORMATION* x32_used_ptr = (X32__ALPC_PORT_COMPLETION_LIST_INFORMATION*)ptr32;
	(*ptr64)->Buffer = (void*)x32_used_ptr->Buffer;
	(*ptr64)->Size = (long unsigned int)x32_used_ptr->Size;
	(*ptr64)->ConcurrencyCount = (long unsigned int)x32_used_ptr->ConcurrencyCount;
	(*ptr64)->AttributeFlags = (long unsigned int)x32_used_ptr->AttributeFlags;
};

void convert_MEM_EXTENDED_PARAMETER_32TO64(void* ctx, MEM_EXTENDED_PARAMETER** ptr64, uint32_t ptr32) {
	X32_MEM_EXTENDED_PARAMETER* x32_used_ptr = (X32_MEM_EXTENDED_PARAMETER*)ptr32;
//#pragma error('Here Ignored struct fix it')
//	(*ptr64)-> = (MEM_EXTENDED_PARAMETER)x32_used_ptr->;
//#pragma error('Here Ignored union fix it')
//	(*ptr64)-> = (MEM_EXTENDED_PARAMETER)x32_used_ptr->;
};

void convert__OBJECT_ATTRIBUTES_32TO64(void* ctx, _OBJECT_ATTRIBUTES** ptr64, uint32_t ptr32) {
	X32__OBJECT_ATTRIBUTES* x32_used_ptr = (X32__OBJECT_ATTRIBUTES*)ptr32;

	(*ptr64)->Length = sizeof(_OBJECT_ATTRIBUTES);
	(*ptr64)->RootDirectory = (void*)x32_used_ptr->RootDirectory;

	NESTED_CVT_32TO64_WITH_ALLOC(_UNICODE_STRING, ObjectName);

	(*ptr64)->Attributes = (long unsigned int)x32_used_ptr->Attributes;
	(*ptr64)->SecurityDescriptor = (void*)x32_used_ptr->SecurityDescriptor;
	(*ptr64)->SecurityQualityOfService = (void*)x32_used_ptr->SecurityQualityOfService;
};

void convert_HANDLE_32TO64(void* ctx, HANDLE** ptr64, uint32_t ptr32) {
	X32_HANDLE* x32_used_ptr = (X32_HANDLE*)ptr32;
	*(*ptr64) = Handle32ToHandle((const void* __ptr32) * x32_used_ptr);
};

void convert__MEMORY_RANGE_ENTRY_32TO64(void* ctx, _MEMORY_RANGE_ENTRY** ptr64, uint32_t ptr32) {
	X32__MEMORY_RANGE_ENTRY* x32_used_ptr = (X32__MEMORY_RANGE_ENTRY*)ptr32;
	(*ptr64)->VirtualAddress = (void*)x32_used_ptr->VirtualAddress;
	(*ptr64)->NumberOfBytes = (long long unsigned int)x32_used_ptr->NumberOfBytes;
};

void convert__CLIENT_ID_32TO64(void* ctx, _CLIENT_ID** ptr64, uint32_t ptr32) {
	X32__CLIENT_ID* x32_used_ptr = (X32__CLIENT_ID*)ptr32;
	(*ptr64)->UniqueProcess = (void*)x32_used_ptr->UniqueProcess;
	(*ptr64)->UniqueThread = (void*)x32_used_ptr->UniqueThread;
};

void convert__INITIAL_TEB_32TO64(void* ctx, _INITIAL_TEB** ptr64, uint32_t ptr32) {
	X32__INITIAL_TEB* x32_used_ptr = (X32__INITIAL_TEB*)ptr32;
//#pragma error('Here Ignored struct fix it')
//	(*ptr64)->OldInitialTeb = (_INITIAL_TEB)x32_used_ptr->OldInitialTeb;
	(*ptr64)->StackBase = (void*)x32_used_ptr->StackBase;
	(*ptr64)->StackLimit = (void*)x32_used_ptr->StackLimit;
	(*ptr64)->StackAllocationBase = (void*)x32_used_ptr->StackAllocationBase;
};

void convert__PS_CREATE_INFO_32TO64(void* ctx, _PS_CREATE_INFO** ptr64, uint32_t ptr32) {
	X32__PS_CREATE_INFO* x32_used_ptr = (X32__PS_CREATE_INFO*)ptr32;
	(*ptr64)->Size = (long long unsigned int)x32_used_ptr->Size;
	(*ptr64)->State = (_PS_CREATE_STATE)x32_used_ptr->State;

//#pragma error('Here Ignored union fix it')
//	(*ptr64)-> = (_PS_CREATE_INFO)x32_used_ptr->;
};

void convert__PS_ATTRIBUTE_LIST_32TO64(void* ctx, _PS_ATTRIBUTE_LIST** ptr64, uint32_t ptr32) {
	X32__PS_ATTRIBUTE_LIST* x32_used_ptr = (X32__PS_ATTRIBUTE_LIST*)ptr32;
	(*ptr64)->TotalLength = (long long unsigned int)x32_used_ptr->TotalLength;

//	(*ptr64)->Attributes = (_PS_ATTRIBUTE[1])x32_used_ptr->Attributes;
};

void convert__JOB_SET_ARRAY_32TO64(void* ctx, _JOB_SET_ARRAY** ptr64, uint32_t ptr32) {
	X32__JOB_SET_ARRAY* x32_used_ptr = (X32__JOB_SET_ARRAY*)ptr32;
	(*ptr64)->JobHandle = (void*)x32_used_ptr->JobHandle;
	(*ptr64)->MemberLevel = (long unsigned int)x32_used_ptr->MemberLevel;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
};

void convert__IO_STATUS_BLOCK_32TO64(void* ctx, _IO_STATUS_BLOCK** ptr64, uint32_t ptr32) {
	X32__IO_STATUS_BLOCK* x32_used_ptr = (X32__IO_STATUS_BLOCK*)ptr32;
	(*ptr64)->Pointer = (PVOID)x32_used_ptr->Pointer;
	(*ptr64)->Information = (long long unsigned int)x32_used_ptr->Information;
};

void convert__FILE_SEGMENT_ELEMENT_32TO64(void* ctx, _FILE_SEGMENT_ELEMENT** ptr64, uint32_t ptr32) {
	X32__FILE_SEGMENT_ELEMENT* x32_used_ptr = (X32__FILE_SEGMENT_ELEMENT*)ptr32;
	(*ptr64)->Buffer = (void*)x32_used_ptr->Buffer;
	(*ptr64)->Alignment = (long long unsigned int)x32_used_ptr->Alignment;
};

void convert__PORT_VIEW_32TO64(void* ctx, _PORT_VIEW** ptr64, uint32_t ptr32) {
	X32__PORT_VIEW* x32_used_ptr = (X32__PORT_VIEW*)ptr32;
	(*ptr64)->Length = (long unsigned int)x32_used_ptr->Length;
	(*ptr64)->SectionHandle = (void*)x32_used_ptr->SectionHandle;
	(*ptr64)->SectionOffset = (long unsigned int)x32_used_ptr->SectionOffset;
	(*ptr64)->ViewSize = (long long unsigned int)x32_used_ptr->ViewSize;
	(*ptr64)->ViewBase = (void*)x32_used_ptr->ViewBase;
	(*ptr64)->ViewRemoteBase = (void*)x32_used_ptr->ViewRemoteBase;
};

void convert__REMOTE_PORT_VIEW_32TO64(void* ctx, _REMOTE_PORT_VIEW** ptr64, uint32_t ptr32) {
	X32__REMOTE_PORT_VIEW* x32_used_ptr = (X32__REMOTE_PORT_VIEW*)ptr32;
	(*ptr64)->Length = (long unsigned int)x32_used_ptr->Length;
	(*ptr64)->ViewSize = (long long unsigned int)x32_used_ptr->ViewSize;
	(*ptr64)->ViewBase = (void*)x32_used_ptr->ViewBase;
};

void convert__PORT_MESSAGE_32TO64(void* ctx, _PORT_MESSAGE** ptr64, uint32_t ptr32) {
	X32__PORT_MESSAGE* x32_used_ptr = (X32__PORT_MESSAGE*)ptr32;

	/*
#pragma error('Here Ignored union fix it')
	(*ptr64)->u1 = (_PORT_MESSAGE)x32_used_ptr->u1;
#pragma error('Here Ignored union fix it')
	(*ptr64)->u2 = (_PORT_MESSAGE)x32_used_ptr->u2;
#pragma error('Here Ignored union fix it')
	(*ptr64)-> = (_PORT_MESSAGE)x32_used_ptr->;
	(*ptr64)->MessageId = (long unsigned int)x32_used_ptr->MessageId;
#pragma error('Here Ignored union fix it')
	(*ptr64)-> = (_PORT_MESSAGE)x32_used_ptr->;
	*/
};

void convert__ALPC_DATA_VIEW_ATTR_32TO64(void* ctx, _ALPC_DATA_VIEW_ATTR** ptr64, uint32_t ptr32) {
	X32__ALPC_DATA_VIEW_ATTR* x32_used_ptr = (X32__ALPC_DATA_VIEW_ATTR*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->SectionHandle = (void*)x32_used_ptr->SectionHandle;
	(*ptr64)->ViewBase = (void*)x32_used_ptr->ViewBase;
	(*ptr64)->ViewSize = (long long unsigned int)x32_used_ptr->ViewSize;
};

void convert__ALPC_SECURITY_ATTR_32TO64(void* ctx, _ALPC_SECURITY_ATTR** ptr64, uint32_t ptr32) {
	X32__ALPC_SECURITY_ATTR* x32_used_ptr = (X32__ALPC_SECURITY_ATTR*)ptr32;
	(*ptr64)->Flags = (long unsigned int)x32_used_ptr->Flags;
	(*ptr64)->QoS = (_SECURITY_QUALITY_OF_SERVICE*)x32_used_ptr->QoS;
	(*ptr64)->ContextHandle = (void*)x32_used_ptr->ContextHandle;
};

void convert__ALPC_CONTEXT_ATTR_32TO64(void* ctx, _ALPC_CONTEXT_ATTR** ptr64, uint32_t ptr32) {
	X32__ALPC_CONTEXT_ATTR* x32_used_ptr = (X32__ALPC_CONTEXT_ATTR*)ptr32;
	(*ptr64)->PortContext = (void*)x32_used_ptr->PortContext;
	(*ptr64)->MessageContext = (void*)x32_used_ptr->MessageContext;
	(*ptr64)->Sequence = (long unsigned int)x32_used_ptr->Sequence;
	(*ptr64)->MessageId = (long unsigned int)x32_used_ptr->MessageId;
	(*ptr64)->CallbackId = (long unsigned int)x32_used_ptr->CallbackId;
};

void convert__KEY_VALUE_ENTRY_32TO64(void* ctx, _KEY_VALUE_ENTRY** ptr64, uint32_t ptr32) {
	X32__KEY_VALUE_ENTRY* x32_used_ptr = (X32__KEY_VALUE_ENTRY*)ptr32;
	NESTED_CVT_32TO64_WITH_ALLOC(_UNICODE_STRING, ValueName);
	(*ptr64)->DataLength = (long unsigned int)x32_used_ptr->DataLength;
	(*ptr64)->DataOffset = (long unsigned int)x32_used_ptr->DataOffset;
	(*ptr64)->Type = (long unsigned int)x32_used_ptr->Type;
};

void convert__TOKEN_USER_32TO64(void* ctx, _TOKEN_USER** ptr64, uint32_t ptr32) {
	X32__TOKEN_USER* x32_used_ptr = (X32__TOKEN_USER*)ptr32;
	NESTED_CVT_32TO64(_SID_AND_ATTRIBUTES, User);
};

void convert__TOKEN_GROUPS_32TO64(void* ctx, _TOKEN_GROUPS** ptr64, uint32_t ptr32) {
	X32__TOKEN_GROUPS* x32_used_ptr = (X32__TOKEN_GROUPS*)ptr32;
	(*ptr64)->GroupCount = (long unsigned int)x32_used_ptr->GroupCount;

//	(*ptr64)->Groups = (_SID_AND_ATTRIBUTES[1])x32_used_ptr->Groups;
};

void convert__TOKEN_OWNER_32TO64(void* ctx, _TOKEN_OWNER** ptr64, uint32_t ptr32) {
	X32__TOKEN_OWNER* x32_used_ptr = (X32__TOKEN_OWNER*)ptr32;
	(*ptr64)->Owner = (void*)x32_used_ptr->Owner;
};

void convert__TOKEN_PRIMARY_GROUP_32TO64(void* ctx, _TOKEN_PRIMARY_GROUP** ptr64, uint32_t ptr32) {
	X32__TOKEN_PRIMARY_GROUP* x32_used_ptr = (X32__TOKEN_PRIMARY_GROUP*)ptr32;
	(*ptr64)->PrimaryGroup = (void*)x32_used_ptr->PrimaryGroup;
};

void convert__TOKEN_DEFAULT_DACL_32TO64(void* ctx, _TOKEN_DEFAULT_DACL** ptr64, uint32_t ptr32) {
	X32__TOKEN_DEFAULT_DACL* x32_used_ptr = (X32__TOKEN_DEFAULT_DACL*)ptr32;
	(*ptr64)->DefaultDacl = (_ACL*)x32_used_ptr->DefaultDacl;
};

void convert__SID_AND_ATTRIBUTES_32TO64(void* ctx, _SID_AND_ATTRIBUTES** ptr64, uint32_t ptr32) {
	X32__SID_AND_ATTRIBUTES* x32_used_ptr = (X32__SID_AND_ATTRIBUTES*)ptr32;
	(*ptr64)->Sid = (void*)x32_used_ptr->Sid;
	(*ptr64)->Attributes = (long unsigned int)x32_used_ptr->Attributes;
};

void convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(void* ctx, _TOKEN_SECURITY_ATTRIBUTES_INFORMATION** ptr64, uint32_t ptr32) {
	X32__TOKEN_SECURITY_ATTRIBUTES_INFORMATION* x32_used_ptr = (X32__TOKEN_SECURITY_ATTRIBUTES_INFORMATION*)ptr32;
	(*ptr64)->Version = (short unsigned int)x32_used_ptr->Version;
	(*ptr64)->Reserved = (short unsigned int)x32_used_ptr->Reserved;
	(*ptr64)->AttributeCount = (long unsigned int)x32_used_ptr->AttributeCount;
//#pragma error('Here Ignored union fix it')
//	(*ptr64)->Attribute = (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)x32_used_ptr->Attribute;
};

void convert__OBJECT_TYPE_LIST_32TO64(void* ctx, _OBJECT_TYPE_LIST** ptr64, uint32_t ptr32) {
	X32__OBJECT_TYPE_LIST* x32_used_ptr = (X32__OBJECT_TYPE_LIST*)ptr32;
	(*ptr64)->Level = (short unsigned int)x32_used_ptr->Level;
	(*ptr64)->Sbz = (short unsigned int)x32_used_ptr->Sbz;
	(*ptr64)->ObjectType = (_GUID*)x32_used_ptr->ObjectType;
};

void convert__EXCEPTION_RECORD_32TO64(void* ctx, _EXCEPTION_RECORD** ptr64, uint32_t ptr32) {
	X32__EXCEPTION_RECORD* x32_used_ptr = (X32__EXCEPTION_RECORD*)ptr32;
	(*ptr64)->ExceptionCode = (long unsigned int)x32_used_ptr->ExceptionCode;
	(*ptr64)->ExceptionFlags = (long unsigned int)x32_used_ptr->ExceptionFlags;
	(*ptr64)->ExceptionRecord = (_EXCEPTION_RECORD*)x32_used_ptr->ExceptionRecord;
	(*ptr64)->ExceptionAddress = (void*)x32_used_ptr->ExceptionAddress;
	(*ptr64)->NumberParameters = (long unsigned int)x32_used_ptr->NumberParameters;

	//	(*ptr64)->ExceptionInformation = (long long unsigned int[15])x32_used_ptr->ExceptionInformation;
};

#undef CVT_COPY_STRING