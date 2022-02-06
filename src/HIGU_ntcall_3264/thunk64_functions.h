#pragma warning(push)
#pragma warning(disable: 4312 4065 4302 4311 4244)

static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemBasicInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemNonPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPageFileInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PAGEFILE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemFileCacheInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRegistryQuotaInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemLegacyDriverInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_LEGACY_DRIVER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemVerifierInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_VERIFIER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemExtendedProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemEmulationBasicInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemExtendedHandleInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_HANDLE_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionPoolTagInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_POOLTAG_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionMappedViewInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_MAPPED_VIEW_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRegisterFirmwareTableInformationHandler(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FIRMWARE_TABLE_HANDLER* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemModuleInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ RTL_PROCESS_MODULE_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSuperfetchInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SUPERFETCH_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemMemoryListInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_MEMORY_LIST_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemFileCacheInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRefTraceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_REF_TRACE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemProcessIdInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_ID_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemVerifierInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemPartitionInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SYSTEM_PARTITION_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemDiskInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SYSTEM_DISK_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPagedPoolInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemPtesInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemBasicPerformanceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_PERFORMANCE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPolicyInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POLICY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemManufacturingInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_MANUFACTURING_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemActivityModerationUserSettings(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemHypervisorSharedPageInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemLogicalProcessorInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_LOGICAL_PROCESSOR_INFORMATION* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemLogicalProcessorAndGroupInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemFeatureConfigurationInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FEATURE_CONFIGURATION_INFORMATION* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRegistryQuotaInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemExtendServiceTableInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ UNICODE_STRING* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemThreadPriorityClientIdInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_THREAD_CID_PRIORITY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRefTraceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REF_TRACE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierFaultsInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_FAULTS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRegistryAppendString(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPagedPoolInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPolicyInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_POLICY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemElamCertificateInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_ELAM_CERTIFICATE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemActivityModerationExeState(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_ACTIVITY_MODERATION_EXE_STATE* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemFeatureConfigurationInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FEATURE_CONFIGURATION_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_BASIC_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryWorkingSetInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_WORKING_SET_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryMappedFilenameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ UNICODE_STRING* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryRegionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_REGION_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryWorkingSetExInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_WORKING_SET_EX_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryRegionInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_REGION_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySection_SectionBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_ SECTION_BASIC_INFORMATION* SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQuerySection_SectionImageInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_ SECTION_IMAGE_INFORMATION* SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_ PSIZE_T ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryObject_ObjectNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_ OBJECT_NAME_INFORMATION* ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryObject_ObjectTypeInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_ OBJECT_TYPE_INFORMATION* ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_BASIC_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessQuotaLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ QUOTA_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessVmCounters(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ VM_COUNTERS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessPooledUsageAndLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ POOLED_USAGE_AND_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessWorkingSetWatch(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_WS_WATCH_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessDeviceMap(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_DEVICEMAP_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageFileName(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessHandleTracing(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_HANDLE_TRACING_QUERY* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ SECTION_IMAGE_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessWorkingSetWatchEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_WS_WATCH_INFORMATION_EX* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageFileNameWin32(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessHandleInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_HANDLE_SNAPSHOT_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessCommandLineInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessQuotaLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ QUOTA_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessExceptionPort(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_EXCEPTION_PORT* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessAccessToken(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_ACCESS_TOKEN* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessAffinityMask(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ KAFFINITY* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessInstrumentationCallback(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessThreadStackAllocation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_STACK_ALLOCATION_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessMemoryExhaustion(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_MEMORY_EXHAUSTION_INFO* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessCombineSecurityDomainsInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_BASIC_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadLastSystemCall(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_LAST_SYSCALL_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadTebInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_TEB_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadGroupInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ GROUP_AFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadCounterProfiling(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_PROFILING_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_NAME_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadAffinityMask(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ KAFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadGroupInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ GROUP_AFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadCounterProfiling(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ THREAD_PROFILING_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ THREAD_NAME_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileRenameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_RENAME_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileLinkInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_LINK_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMailslotSetInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MAILSLOT_SET_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileCompletionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_COMPLETION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMoveClusterInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MOVE_CLUSTER_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileTrackingInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_TRACKING_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileIoStatusBlockRangeInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_IOSTATUSBLOCK_RANGE_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileReplaceCompletionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_COMPLETION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileRenameInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_RENAME_INFORMATION_EX* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMemoryPartitionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MEMORY_PARTITION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtSetInformationFile_FileLinkInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_LINK_INFORMATION_EX* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass);
static NTSTATUS WINAPI _w32_NtAlpcQueryInformation_AlpcBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _Out_ ALPC_BASIC_INFORMATION* PortInformation, _In_ ULONG Length, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtAlpcQueryInformation_AlpcServerInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _Out_ ALPC_SERVER_INFORMATION* PortInformation, _In_ ULONG Length, _Out_ PULONG ReturnLength);
static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_BASIC_INFORMATION* PortInformation, _In_ ULONG Length);
static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcPortInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_ATTRIBUTES* PortInformation, _In_ ULONG Length);
static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcAssociateCompletionPortInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_ASSOCIATE_COMPLETION_PORT* PortInformation, _In_ ULONG Length);
static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcMessageZoneInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_MESSAGE_ZONE_INFORMATION* PortInformation, _In_ ULONG Length);
static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcRegisterCompletionListInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_COMPLETION_LIST_INFORMATION* PortInformation, _In_ ULONG Length);

NTSTATUS WINAPI _w32_NtMapViewOfSectionEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCallbackReturn(uint32_t* x32based_args);
void WINAPI _w32_NtFlushProcessWriteBuffers(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDebugFilterState(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetDebugFilterState(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtYieldExecution(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDelayExecution(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySystemEnvironmentValue(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSystemEnvironmentValue(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySystemEnvironmentValueEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSystemEnvironmentValueEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateSystemEnvironmentValuesEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAddBootEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteBootEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtModifyBootEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateBootEntries(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryBootEntryOrder(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetBootEntryOrder(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryBootOptions(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetBootOptions(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTranslateFilePath(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAddDriverEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteDriverEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtModifyDriverEntry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateDriverEntries(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDriverEntryOrder(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetDriverEntryOrder(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFilterBootOption(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetEventBoostPriority(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtClearEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtResetEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPulseEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetLowEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetHighEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitLowEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitHighEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetLowWaitHighEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetHighWaitLowEventPair(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateMutant(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenMutant(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReleaseMutant(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryMutant(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateSemaphore(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenSemaphore(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReleaseSemaphore(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySemaphore(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetTimerEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateIRTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetIRTimer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateTimer2(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetTimer2(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelTimer2(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateProfile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateProfileEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtStartProfile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtStopProfile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryIntervalProfile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetIntervalProfile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateKeyedEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenKeyedEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReleaseKeyedEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForKeyedEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUmsThreadYield(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateWnfStateName(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteWnfStateName(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUpdateWnfStateData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteWnfStateData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryWnfStateData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryWnfStateNameInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSubscribeWnfStateChange(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnsubscribeWnfStateChange(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetCompleteWnfStateSubscription(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetWnfProcessNotificationEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateWorkerFactory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationWorkerFactory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationWorkerFactory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtShutdownWorkerFactory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReleaseWorkerFactoryWorker(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWorkerFactoryWorkerReady(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForWorkViaWorkerFactory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSystemTime(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryTimerResolution(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetTimerResolution(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryPerformanceCounter(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAllocateLocallyUniqueId(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetUuidSeed(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAllocateUuids(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySystemInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySystemInformationEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSystemInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSystemDebugControl(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRaiseHardError(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDefaultLocale(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetDefaultLocale(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInstallUILanguage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushInstallUILanguage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDefaultUILanguage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetDefaultUILanguage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtIsUILanguageComitted(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtInitializeNlsFiles(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetNlsSectionPtr(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMapCMFModule(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetMUIRegistryInfo(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAddAtom(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAddAtomEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFindAtom(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteAtom(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationAtom(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryLicenseValue(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetDefaultHardErrorPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtShutdownSystem(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDisplayString(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDrawText(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAllocateVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFreeVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReadVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWriteVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtProtectVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLockVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnlockVirtualMemory(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateSectionEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMapViewOfSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnmapViewOfSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnmapViewOfSectionEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtExtendSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAreMappedFilesTheSame(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreatePartition(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenPartition(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtManagePartition(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMapUserPhysicalPages(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMapUserPhysicalPagesScatter(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAllocateUserPhysicalPages(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFreeUserPhysicalPages(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetWriteWatch(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtResetWriteWatch(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreatePagingFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushInstructionCache(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushWriteBuffer(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateEnclave(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLoadEnclaveData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtInitializeEnclave(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTerminateEnclave(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCallEnclave(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDuplicateObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMakeTemporaryObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtMakePermanentObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSignalAndWaitForSingleObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForSingleObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForMultipleObjects(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForMultipleObjects32(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSecurityObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySecurityObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtClose(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCompareObjects(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateDirectoryObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateDirectoryObjectEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenDirectoryObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDirectoryObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreatePrivateNamespace(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenPrivateNamespace(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeletePrivateNamespace(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateSymbolicLinkObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenSymbolicLinkObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySymbolicLinkObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateProcessEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTerminateProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSuspendProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtResumeProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetNextProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetNextThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryPortInformationProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTerminateThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSuspendThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtResumeThread(uint32_t* x32based_args);
ULONG WINAPI _w32_NtGetCurrentProcessorNumber(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetContextThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetContextThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlertThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlertResumeThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTestAlert(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtImpersonateThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRegisterThreadTerminatePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetLdtEntries(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueueApcThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueueApcThreadEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlertThreadByThreadId(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForAlertByThreadId(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateUserProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateThreadEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAssignProcessToJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTerminateJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtIsProcessInJob(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationJobObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateJobSet(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRevertContainerImpersonation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAllocateReserveObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateDebugObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDebugActiveProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDebugContinue(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRemoveProcessDebug(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationDebugObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWaitForDebugEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateNamedPipeFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateMailslotFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushBuffersFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushBuffersFileEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationByName(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDirectoryFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryDirectoryFileEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryEaFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetEaFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryQuotaInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetQuotaInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryVolumeInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetVolumeInformationFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelIoFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelIoFileEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelSynchronousIoFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeviceIoControlFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFsControlFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReadFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWriteFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReadFileScatter(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWriteFileGather(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLockFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnlockFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryAttributesFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryFullAttributesFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtNotifyChangeDirectoryFile(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtNotifyChangeDirectoryFileEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLoadDriver(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnloadDriver(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateIoCompletion(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenIoCompletion(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryIoCompletion(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetIoCompletion(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetIoCompletionEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRemoveIoCompletion(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRemoveIoCompletionEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateWaitCompletionPacket(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAssociateWaitCompletionPacket(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCancelWaitCompletionPacket(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenSession(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtNotifyChangeSession(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreatePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateWaitablePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSecureConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtListenPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAcceptConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCompleteConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRequestPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRequestWaitReplyPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplyPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplyWaitReplyPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplyWaitReceivePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplyWaitReceivePortEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtImpersonateClientOfPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReadRequestData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtWriteRequestData(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCreatePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcDisconnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcQueryInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcSetInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCreatePortSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcDeletePortSection(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCreateResourceReserve(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcDeleteResourceReserve(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCreateSectionView(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcDeleteSectionView(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCreateSecurityContext(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcDeleteSecurityContext(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcRevokeSecurityContext(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcQueryInformationMessage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcConnectPortEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcAcceptConnectPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcSendWaitReceivePort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcCancelMessage(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcImpersonateClientOfPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcImpersonateClientContainerOfPort(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcOpenSenderProcess(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAlpcOpenSenderThread(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPlugPlayControl(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSerializeBoot(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnableLastKnownGood(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDisableLastKnownGood(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplacePartitionUnit(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPowerInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetThreadExecutionState(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtInitiatePowerAction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetSystemPowerState(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetDevicePowerState(uint32_t* x32based_args);
BOOLEAN WINAPI _w32_NtIsSystemResumeAutomatic(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateKeyTransacted(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenKeyTransacted(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenKeyEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenKeyTransactedEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRenameKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteValueKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryValueKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetValueKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryMultipleValueKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateValueKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCompactKeys(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCompressKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLoadKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLoadKey2(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLoadKeyEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReplaceKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSaveKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSaveKeyEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSaveMergedKeys(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRestoreKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnloadKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnloadKey2(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtUnloadKeyEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtNotifyChangeKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtNotifyChangeMultipleKeys(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryOpenSubKeys(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryOpenSubKeysEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtInitializeRegistry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLockRegistryKey(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtLockProductActivationKeys(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFreezeRegistry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtThawRegistry(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateLowBoxToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateTokenEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenProcessToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenProcessTokenEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenThreadToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenThreadTokenEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDuplicateToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAdjustPrivilegesToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAdjustGroupsToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAdjustTokenClaimsAndDeviceGroups(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFilterToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFilterTokenEx(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCompareTokens(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrivilegeCheck(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtImpersonateAnonymousToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQuerySecurityAttributesToken(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheck(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckByType(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultList(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetCachedSigningLevel(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetCachedSigningLevel(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckAndAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckByTypeAndAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultListAndAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultListAndAuditAlarmByHandle(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenObjectAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrivilegeObjectAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCloseObjectAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtDeleteObjectAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrivilegedServiceAuditAlarm(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRenameTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRollforwardTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRecoverTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationTransactionManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtEnumerateTransactionObject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCommitTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRollbackTransaction(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRecoverEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrePrepareEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrepareEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCommitEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRollbackEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrePrepareComplete(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPrepareComplete(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCommitComplete(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtReadOnlyEnlistment(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRollbackComplete(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSinglePhaseReject(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtCreateResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtOpenResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRecoverResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtGetNotificationResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtQueryInformationResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtSetInformationResourceManager(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRegisterProtocolAddressInformation(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPropagationComplete(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtPropagationFailed(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFreezeTransactions(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtThawTransactions(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtContinue(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtRaiseException(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtVdmControl(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTraceEvent(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtTraceControl(uint32_t* x32based_args);
NTSTATUS WINAPI _w32_NtFlushVirtualMemory(uint32_t* x32based_args);

static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemBasicInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_BASIC_INFORMATION)];
	SYSTEM_BASIC_INFORMATION* SystemInformation_used = (SYSTEM_BASIC_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_BASIC_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemBasicInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_BASIC_INFORMATION_64TO32(ctx, (_SYSTEM_BASIC_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_PROCESS_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_PROCESS_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_PROCESS_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	// Convert parameters from x32 to x64

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemProcessInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_PROCESS_INFORMATION_64TO32(ctx, (_SYSTEM_PROCESS_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_POOL_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_POOL_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_POOL_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	// Convert parameters from x32 to x64

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemPagedPoolInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_POOL_INFORMATION_64TO32(ctx, (_SYSTEM_POOL_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemNonPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_POOL_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_POOL_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_POOL_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemNonPagedPoolInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_POOL_INFORMATION_64TO32(ctx, (_SYSTEM_POOL_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPageFileInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PAGEFILE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_PAGEFILE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_PAGEFILE_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_PAGEFILE_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemPageFileInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_PAGEFILE_INFORMATION_64TO32(ctx, (_SYSTEM_PAGEFILE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemFileCacheInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FILECACHE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_FILECACHE_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_FILECACHE_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemFileCacheInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_FILECACHE_INFORMATION_64TO32(ctx, (_SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRegistryQuotaInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_REGISTRY_QUOTA_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_REGISTRY_QUOTA_INFORMATION)];
	SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation_used = (SYSTEM_REGISTRY_QUOTA_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_REGISTRY_QUOTA_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemRegistryQuotaInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_64TO32(ctx, (_SYSTEM_REGISTRY_QUOTA_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemLegacyDriverInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_LEGACY_DRIVER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_LEGACY_DRIVER_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_LEGACY_DRIVER_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_LEGACY_DRIVER_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemLegacyDriverInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_LEGACY_DRIVER_INFORMATION_64TO32(ctx, (_SYSTEM_LEGACY_DRIVER_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemVerifierInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_VERIFIER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_VERIFIER_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_VERIFIER_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_VERIFIER_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemVerifierInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_VERIFIER_INFORMATION_64TO32(ctx, (_SYSTEM_VERIFIER_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_SESSION_PROCESS_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_SESSION_PROCESS_INFORMATION* SystemInformation_used = 0;

	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_SESSION_PROCESS_INFORMATION*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSessionProcessInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_SESSION_PROCESS_INFORMATION_64TO32(ctx, (_SYSTEM_SESSION_PROCESS_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemExtendedProcessInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_PROCESS_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_PROCESS_INFORMATION* SystemInformation_used = (SYSTEM_PROCESS_INFORMATION*)SystemInformation;

	// Convert parameters from x32 to x64

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemExtendedProcessInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_PROCESS_INFORMATION_64TO32(ctx, (_SYSTEM_PROCESS_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemEmulationBasicInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_BASIC_INFORMATION)];
	SYSTEM_BASIC_INFORMATION* SystemInformation_used = (SYSTEM_BASIC_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_BASIC_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemEmulationBasicInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_BASIC_INFORMATION_64TO32(ctx, (_SYSTEM_BASIC_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemExtendedHandleInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_HANDLE_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_HANDLE_INFORMATION_EX *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_HANDLE_INFORMATION_EX* SystemInformation_used = 0;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL && SystemInformationLength != 0) {
		SystemInformation_used = (SYSTEM_HANDLE_INFORMATION_EX*)intrnl__ntcallmalloc(ctx, SystemInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemExtendedHandleInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_HANDLE_INFORMATION_EX_64TO32(ctx, (_SYSTEM_HANDLE_INFORMATION_EX*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionPoolTagInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_POOLTAG_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_SESSION_POOLTAG_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_SESSION_POOLTAG_INFORMATION* SystemInformation_used = (SYSTEM_SESSION_POOLTAG_INFORMATION*)SystemInformation;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSessionPoolTagInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_SESSION_POOLTAG_INFORMATION_64TO32(ctx, (_SYSTEM_SESSION_POOLTAG_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSessionMappedViewInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SESSION_MAPPED_VIEW_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_SESSION_MAPPED_VIEW_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	SYSTEM_SESSION_MAPPED_VIEW_INFORMATION* SystemInformation_used = (SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*)SystemInformation;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSessionMappedViewInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_SESSION_MAPPED_VIEW_INFORMATION_64TO32(ctx, (_SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRegisterFirmwareTableInformationHandler(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FIRMWARE_TABLE_HANDLER* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FIRMWARE_TABLE_HANDLER *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FIRMWARE_TABLE_HANDLER)];
	SYSTEM_FIRMWARE_TABLE_HANDLER* SystemInformation_used = (SYSTEM_FIRMWARE_TABLE_HANDLER*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_FIRMWARE_TABLE_HANDLER);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemRegisterFirmwareTableInformationHandler

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_FIRMWARE_TABLE_HANDLER_64TO32(ctx, (_SYSTEM_FIRMWARE_TABLE_HANDLER*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemModuleInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ RTL_PROCESS_MODULE_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // RTL_PROCESS_MODULE_INFORMATION_EX *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX)];
	RTL_PROCESS_MODULE_INFORMATION_EX* SystemInformation_used = (RTL_PROCESS_MODULE_INFORMATION_EX*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemModuleInformationEx

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__RTL_PROCESS_MODULE_INFORMATION_EX_64TO32(ctx, (_RTL_PROCESS_MODULE_INFORMATION_EX*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSuperfetchInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SUPERFETCH_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SUPERFETCH_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SUPERFETCH_INFORMATION)];
	SUPERFETCH_INFORMATION* SystemInformation_used = (SUPERFETCH_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SUPERFETCH_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSuperfetchInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SUPERFETCH_INFORMATION_64TO32(ctx, (_SUPERFETCH_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemMemoryListInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_MEMORY_LIST_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_MEMORY_LIST_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_MEMORY_LIST_INFORMATION)];
	SYSTEM_MEMORY_LIST_INFORMATION* SystemInformation_used = (SYSTEM_MEMORY_LIST_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_MEMORY_LIST_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemMemoryListInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_MEMORY_LIST_INFORMATION_64TO32(ctx, (_SYSTEM_MEMORY_LIST_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemFileCacheInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FILECACHE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FILECACHE_INFORMATION)];
	SYSTEM_FILECACHE_INFORMATION* SystemInformation_used = (SYSTEM_FILECACHE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_FILECACHE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemFileCacheInformationEx

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_FILECACHE_INFORMATION_64TO32(ctx, (_SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemRefTraceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_REF_TRACE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_REF_TRACE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_REF_TRACE_INFORMATION)];
	SYSTEM_REF_TRACE_INFORMATION* SystemInformation_used = (SYSTEM_REF_TRACE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_REF_TRACE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemRefTraceInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_REF_TRACE_INFORMATION_64TO32(ctx, (_SYSTEM_REF_TRACE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemProcessIdInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_PROCESS_ID_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_PROCESS_ID_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_PROCESS_ID_INFORMATION)];
	SYSTEM_PROCESS_ID_INFORMATION* SystemInformation_used = (SYSTEM_PROCESS_ID_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_PROCESS_ID_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemProcessIdInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_PROCESS_ID_INFORMATION_64TO32(ctx, (_SYSTEM_PROCESS_ID_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemVerifierInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_VERIFIER_INFORMATION_EX *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_VERIFIER_INFORMATION_EX)];
	SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation_used = (SYSTEM_VERIFIER_INFORMATION_EX*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_VERIFIER_INFORMATION_EX);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemVerifierInformationEx

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_VERIFIER_INFORMATION_EX_64TO32(ctx, (_SYSTEM_VERIFIER_INFORMATION_EX*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemPartitionInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SYSTEM_PARTITION_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_SYSTEM_PARTITION_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_SYSTEM_PARTITION_INFORMATION)];
	SYSTEM_SYSTEM_PARTITION_INFORMATION* SystemInformation_used = (SYSTEM_SYSTEM_PARTITION_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_SYSTEM_PARTITION_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSystemPartitionInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_SYSTEM_PARTITION_INFORMATION_64TO32(ctx, (_SYSTEM_SYSTEM_PARTITION_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemDiskInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_SYSTEM_DISK_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_SYSTEM_DISK_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_SYSTEM_DISK_INFORMATION)];
	SYSTEM_SYSTEM_DISK_INFORMATION* SystemInformation_used = (SYSTEM_SYSTEM_DISK_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_SYSTEM_DISK_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSystemDiskInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_SYSTEM_DISK_INFORMATION_64TO32(ctx, (_SYSTEM_SYSTEM_DISK_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPagedPoolInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FILECACHE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FILECACHE_INFORMATION)];
	SYSTEM_FILECACHE_INFORMATION* SystemInformation_used = (SYSTEM_FILECACHE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_FILECACHE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemPagedPoolInformationEx

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_FILECACHE_INFORMATION_64TO32(ctx, (_SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemSystemPtesInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FILECACHE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FILECACHE_INFORMATION)];
	SYSTEM_FILECACHE_INFORMATION* SystemInformation_used = (SYSTEM_FILECACHE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_FILECACHE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemSystemPtesInformationEx

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_FILECACHE_INFORMATION_64TO32(ctx, (_SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemBasicPerformanceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_BASIC_PERFORMANCE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_BASIC_PERFORMANCE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_BASIC_PERFORMANCE_INFORMATION)];
	SYSTEM_BASIC_PERFORMANCE_INFORMATION* SystemInformation_used = (SYSTEM_BASIC_PERFORMANCE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_BASIC_PERFORMANCE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemBasicPerformanceInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_BASIC_PERFORMANCE_INFORMATION_64TO32(ctx, (_SYSTEM_BASIC_PERFORMANCE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemPolicyInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_POLICY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_POLICY_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_POLICY_INFORMATION)];
	SYSTEM_POLICY_INFORMATION* SystemInformation_used = (SYSTEM_POLICY_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_POLICY_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemPolicyInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_POLICY_INFORMATION_64TO32(ctx, (_SYSTEM_POLICY_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemManufacturingInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_MANUFACTURING_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_MANUFACTURING_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_MANUFACTURING_INFORMATION)];
	SYSTEM_MANUFACTURING_INFORMATION* SystemInformation_used = (SYSTEM_MANUFACTURING_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_MANUFACTURING_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemManufacturingInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_MANUFACTURING_INFORMATION_64TO32(ctx, (_SYSTEM_MANUFACTURING_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemActivityModerationUserSettings(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS)];
	SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS* SystemInformation_used = (SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemActivityModerationUserSettings

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS_64TO32(ctx, (_SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformation_SystemHypervisorSharedPageInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _Out_ SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION)];
	SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION* SystemInformation_used = (SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation == NULL) {
		SystemInformation_used = 0;
	}
	else {
		SystemInformationLength = sizeof(_SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 4, SystemInformationClass, SystemInformation_used, SystemInformationLength, ReturnLength); // NtQuerySystemInformation_SystemHypervisorSharedPageInformation

	if (NT_SUCCESS(ret_value) && SystemInformation_used != NULL) {
		convert__SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION_64TO32(ctx, (_SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION*)SystemInformation_used, x32based_SystemInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemLogicalProcessorInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_LOGICAL_PROCESSOR_INFORMATION* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_InputBuffer = (uint32_t)(InputBuffer); // SYSTEM_LOGICAL_PROCESSOR_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t InputBuffer_holder[sizeof(_SYSTEM_LOGICAL_PROCESSOR_INFORMATION)];
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* InputBuffer_used = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)&InputBuffer_holder;

	// Convert parameters from x32 to x64
	if (x32based_InputBuffer != NULL) {
		convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_32TO64(ctx, (_SYSTEM_LOGICAL_PROCESSOR_INFORMATION**)&InputBuffer_used, x32based_InputBuffer);

	}
	else {
		InputBuffer_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, SystemInformationClass, InputBuffer_used, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength); // NtQuerySystemInformationEx_SystemLogicalProcessorInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemLogicalProcessorAndGroupInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_InputBuffer = (uint32_t)(InputBuffer); // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t InputBuffer_holder[sizeof(_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)];
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* InputBuffer_used = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)&InputBuffer_holder;

	// Convert parameters from x32 to x64
	if (x32based_InputBuffer != NULL) {
		convert__SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_32TO64(ctx, (_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX**)&InputBuffer_used, x32based_InputBuffer);
	}
	else {
		InputBuffer_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, SystemInformationClass, InputBuffer_used, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength); // NtQuerySystemInformationEx_SystemLogicalProcessorAndGroupInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySystemInformationEx_SystemFeatureConfigurationInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FEATURE_CONFIGURATION_INFORMATION* InputBuffer, _In_ ULONG InputBufferLength, _Out_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_InputBuffer = (uint32_t)(InputBuffer); // SYSTEM_FEATURE_CONFIGURATION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t InputBuffer_holder[sizeof(_SYSTEM_FEATURE_CONFIGURATION_INFORMATION)];
	SYSTEM_FEATURE_CONFIGURATION_INFORMATION* InputBuffer_used = (SYSTEM_FEATURE_CONFIGURATION_INFORMATION*)&InputBuffer_holder;

	// Convert parameters from x32 to x64
	if (x32based_InputBuffer != NULL) {
		convert__SYSTEM_FEATURE_CONFIGURATION_INFORMATION_32TO64(ctx, (_SYSTEM_FEATURE_CONFIGURATION_INFORMATION**)&InputBuffer_used, x32based_InputBuffer);
	}
	else {
		InputBuffer_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, SystemInformationClass, InputBuffer_used, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength); // NtQuerySystemInformationEx_SystemFeatureConfigurationInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPagedPoolInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_POOL_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_POOL_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_POOL_INFORMATION)];
	SYSTEM_POOL_INFORMATION* SystemInformation_used = (SYSTEM_POOL_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_POOL_INFORMATION_32TO64(ctx, (_SYSTEM_POOL_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_POOL_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemPagedPoolInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRegistryQuotaInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_REGISTRY_QUOTA_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_REGISTRY_QUOTA_INFORMATION)];
	SYSTEM_REGISTRY_QUOTA_INFORMATION* SystemInformation_used = (SYSTEM_REGISTRY_QUOTA_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_REGISTRY_QUOTA_INFORMATION_32TO64(ctx, (_SYSTEM_REGISTRY_QUOTA_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_REGISTRY_QUOTA_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemRegistryQuotaInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemExtendServiceTableInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ UNICODE_STRING* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // UNICODE_STRING *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_UNICODE_STRING)];
	UNICODE_STRING* SystemInformation_used = (UNICODE_STRING*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_UNICODE_STRING);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemExtendServiceTableInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_VERIFIER_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_VERIFIER_INFORMATION)];
	SYSTEM_VERIFIER_INFORMATION* SystemInformation_used = (SYSTEM_VERIFIER_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_VERIFIER_INFORMATION_32TO64(ctx, (_SYSTEM_VERIFIER_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_VERIFIER_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemVerifierInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemThreadPriorityClientIdInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_THREAD_CID_PRIORITY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_THREAD_CID_PRIORITY_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_THREAD_CID_PRIORITY_INFORMATION)];
	SYSTEM_THREAD_CID_PRIORITY_INFORMATION* SystemInformation_used = (SYSTEM_THREAD_CID_PRIORITY_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_THREAD_CID_PRIORITY_INFORMATION_32TO64(ctx, (_SYSTEM_THREAD_CID_PRIORITY_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_THREAD_CID_PRIORITY_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemThreadPriorityClientIdInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRefTraceInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REF_TRACE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_REF_TRACE_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_REF_TRACE_INFORMATION)];
	SYSTEM_REF_TRACE_INFORMATION* SystemInformation_used = (SYSTEM_REF_TRACE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_REF_TRACE_INFORMATION_32TO64(ctx, (_SYSTEM_REF_TRACE_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_REF_TRACE_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemRefTraceInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_VERIFIER_INFORMATION_EX *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_VERIFIER_INFORMATION_EX)];
	SYSTEM_VERIFIER_INFORMATION_EX* SystemInformation_used = (SYSTEM_VERIFIER_INFORMATION_EX*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_VERIFIER_INFORMATION_EX_32TO64(ctx, (_SYSTEM_VERIFIER_INFORMATION_EX**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_VERIFIER_INFORMATION_EX);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemVerifierInformationEx

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemVerifierFaultsInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_VERIFIER_FAULTS_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_VERIFIER_FAULTS_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_VERIFIER_FAULTS_INFORMATION)];
	SYSTEM_VERIFIER_FAULTS_INFORMATION* SystemInformation_used = (SYSTEM_VERIFIER_FAULTS_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_VERIFIER_FAULTS_INFORMATION_32TO64(ctx, (_SYSTEM_VERIFIER_FAULTS_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_VERIFIER_FAULTS_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemVerifierFaultsInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemRegistryAppendString(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS)];
	SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS* SystemInformation_used = (SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS_32TO64(ctx, (_SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemRegistryAppendString

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPagedPoolInformationEx(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FILECACHE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FILECACHE_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FILECACHE_INFORMATION)];
	SYSTEM_FILECACHE_INFORMATION* SystemInformation_used = (SYSTEM_FILECACHE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_FILECACHE_INFORMATION_32TO64(ctx, (_SYSTEM_FILECACHE_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_FILECACHE_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemPagedPoolInformationEx

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemPolicyInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_POLICY_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_POLICY_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_POLICY_INFORMATION)];
	SYSTEM_POLICY_INFORMATION* SystemInformation_used = (SYSTEM_POLICY_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_POLICY_INFORMATION_32TO64(ctx, (_SYSTEM_POLICY_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
		SystemInformationLength = sizeof(_SYSTEM_POLICY_INFORMATION);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemPolicyInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemElamCertificateInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_ELAM_CERTIFICATE_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_ELAM_CERTIFICATE_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_ELAM_CERTIFICATE_INFORMATION)];
	SYSTEM_ELAM_CERTIFICATE_INFORMATION* SystemInformation_used = (SYSTEM_ELAM_CERTIFICATE_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_ELAM_CERTIFICATE_INFORMATION_32TO64(ctx, (_SYSTEM_ELAM_CERTIFICATE_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemElamCertificateInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemActivityModerationExeState(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_ACTIVITY_MODERATION_EXE_STATE* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_ACTIVITY_MODERATION_EXE_STATE *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_ACTIVITY_MODERATION_EXE_STATE)];
	SYSTEM_ACTIVITY_MODERATION_EXE_STATE* SystemInformation_used = (SYSTEM_ACTIVITY_MODERATION_EXE_STATE*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_ACTIVITY_MODERATION_EXE_STATE_32TO64(ctx, (_SYSTEM_ACTIVITY_MODERATION_EXE_STATE**)&SystemInformation_used, x32based_SystemInformation);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemActivityModerationExeState

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetSystemInformation_SystemFeatureConfigurationInformation(void* ctx, uint32_t syscall_idx, _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass, _In_ SYSTEM_FEATURE_CONFIGURATION_INFORMATION* SystemInformation, _In_ ULONG SystemInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_SystemInformation = (uint32_t)(SystemInformation); // SYSTEM_FEATURE_CONFIGURATION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SystemInformation_holder[sizeof(_SYSTEM_FEATURE_CONFIGURATION_INFORMATION)];
	SYSTEM_FEATURE_CONFIGURATION_INFORMATION* SystemInformation_used = (SYSTEM_FEATURE_CONFIGURATION_INFORMATION*)&SystemInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SystemInformation != NULL) {
		convert__SYSTEM_FEATURE_CONFIGURATION_INFORMATION_32TO64(ctx, (_SYSTEM_FEATURE_CONFIGURATION_INFORMATION**)&SystemInformation_used, x32based_SystemInformation);
	}
	else {
		SystemInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SystemInformationClass, SystemInformation_used, SystemInformationLength); // NtSetSystemInformation_SystemFeatureConfigurationInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_BASIC_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // MEMORY_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryInformation_holder[sizeof(_MEMORY_BASIC_INFORMATION)];
	MEMORY_BASIC_INFORMATION* MemoryInformation_used = (MEMORY_BASIC_INFORMATION*)&MemoryInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryInformation == NULL) {
		MemoryInformation_used = 0;
	}
	else {
		MemoryInformationLength = sizeof(_MEMORY_BASIC_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryBasicInformation

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		convert__MEMORY_BASIC_INFORMATION_64TO32(ctx, (_MEMORY_BASIC_INFORMATION*)MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryWorkingSetInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_WORKING_SET_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // MEMORY_WORKING_SET_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryInformation_holder[sizeof(_MEMORY_WORKING_SET_INFORMATION)];
	MEMORY_WORKING_SET_INFORMATION* MemoryInformation_used = (MEMORY_WORKING_SET_INFORMATION*)&MemoryInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryInformation == NULL) {
		MemoryInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryWorkingSetInformation

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		convert__MEMORY_WORKING_SET_INFORMATION_64TO32(ctx, (_MEMORY_WORKING_SET_INFORMATION*)MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryMappedFilenameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ UNICODE_STRING* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // UNICODE_STRING *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	UNICODE_STRING* MemoryInformation_used = 0;

	if (x32based_MemoryInformation != NULL && MemoryInformationLength != 0) {
		MemoryInformation_used = (UNICODE_STRING*)intrnl__ntcallmalloc(ctx, MemoryInformationLength);
	}

	// Convert parameters from x32 to x64

	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryMappedFilenameInformation

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		CVT_UNICODE_STRING_OFFSETABLE_FUNC64TO32(MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryRegionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_REGION_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // MEMORY_REGION_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryInformation_holder[sizeof(_MEMORY_REGION_INFORMATION)];
	MEMORY_REGION_INFORMATION* MemoryInformation_used = (MEMORY_REGION_INFORMATION*)&MemoryInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryInformation == NULL) {
		MemoryInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryRegionInformation

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		convert__MEMORY_REGION_INFORMATION_64TO32(ctx, (_MEMORY_REGION_INFORMATION*)MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryWorkingSetExInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_WORKING_SET_EX_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // MEMORY_WORKING_SET_EX_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryInformation_holder[sizeof(_MEMORY_WORKING_SET_EX_INFORMATION)];
	MEMORY_WORKING_SET_EX_INFORMATION* MemoryInformation_used = (MEMORY_WORKING_SET_EX_INFORMATION*)&MemoryInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryInformation == NULL) {
		MemoryInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryWorkingSetExInformation

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		convert__MEMORY_WORKING_SET_EX_INFORMATION_64TO32(ctx, (_MEMORY_WORKING_SET_EX_INFORMATION*)MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryVirtualMemory_MemoryRegionInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PVOID BaseAddress, _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass, _Out_ MEMORY_REGION_INFORMATION* MemoryInformation, _In_ SIZE_T MemoryInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_MemoryInformation = (uint32_t)(MemoryInformation); // MEMORY_REGION_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryInformation_holder[sizeof(_MEMORY_REGION_INFORMATION)];
	MEMORY_REGION_INFORMATION* MemoryInformation_used = (MEMORY_REGION_INFORMATION*)&MemoryInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryInformation == NULL) {
		MemoryInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation_used, MemoryInformationLength, ReturnLength); // NtQueryVirtualMemory_MemoryRegionInformationEx

	if (NT_SUCCESS(ret_value) && MemoryInformation_used != NULL) {
		convert__MEMORY_REGION_INFORMATION_64TO32(ctx, (_MEMORY_REGION_INFORMATION*)MemoryInformation_used, x32based_MemoryInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySection_SectionBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_ SECTION_BASIC_INFORMATION* SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SectionInformation = (uint32_t)(SectionInformation); // SECTION_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionInformation_holder[sizeof(_SECTION_BASIC_INFORMATION)];
	SECTION_BASIC_INFORMATION* SectionInformation_used = (SECTION_BASIC_INFORMATION*)&SectionInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SectionInformation == NULL) {
		SectionInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, SectionHandle, SectionInformationClass, SectionInformation_used, SectionInformationLength, ReturnLength); // NtQuerySection_SectionBasicInformation

	if (NT_SUCCESS(ret_value) && SectionInformation_used != NULL) {
		convert__SECTION_BASIC_INFORMATION_64TO32(ctx, (_SECTION_BASIC_INFORMATION*)SectionInformation_used, x32based_SectionInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQuerySection_SectionImageInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE SectionHandle, _In_ SECTION_INFORMATION_CLASS SectionInformationClass, _Out_ SECTION_IMAGE_INFORMATION* SectionInformation, _In_ SIZE_T SectionInformationLength, _Out_ PSIZE_T ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_SectionInformation = (uint32_t)(SectionInformation); // SECTION_IMAGE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionInformation_holder[sizeof(_SECTION_IMAGE_INFORMATION)];
	SECTION_IMAGE_INFORMATION* SectionInformation_used = (SECTION_IMAGE_INFORMATION*)&SectionInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_SectionInformation == NULL) {
		SectionInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, SectionHandle, SectionInformationClass, SectionInformation_used, SectionInformationLength, ReturnLength); // NtQuerySection_SectionImageInformation

	if (NT_SUCCESS(ret_value) && SectionInformation_used != NULL) {
		convert__SECTION_IMAGE_INFORMATION_64TO32(ctx, (_SECTION_IMAGE_INFORMATION*)SectionInformation_used, x32based_SectionInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryObject_ObjectNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_ OBJECT_NAME_INFORMATION* ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ObjectInformation = (uint32_t)(ObjectInformation); // OBJECT_NAME_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectInformation_holder[sizeof(_OBJECT_NAME_INFORMATION)];
	OBJECT_NAME_INFORMATION* ObjectInformation_used = (OBJECT_NAME_INFORMATION*)&ObjectInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectInformation == NULL) {
		ObjectInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, Handle, ObjectInformationClass, ObjectInformation_used, ObjectInformationLength, ReturnLength); // NtQueryObject_ObjectNameInformation

	if (NT_SUCCESS(ret_value) && ObjectInformation_used != NULL) {
		convert__OBJECT_NAME_INFORMATION_64TO32(ctx, (_OBJECT_NAME_INFORMATION*)ObjectInformation_used, x32based_ObjectInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryObject_ObjectTypeInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE Handle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_ OBJECT_TYPE_INFORMATION* ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ObjectInformation = (uint32_t)(ObjectInformation); // OBJECT_TYPE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectInformation_holder[sizeof(_OBJECT_TYPE_INFORMATION)];
	OBJECT_TYPE_INFORMATION* ObjectInformation_used = (OBJECT_TYPE_INFORMATION*)&ObjectInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectInformation == NULL) {
		ObjectInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, Handle, ObjectInformationClass, ObjectInformation_used, ObjectInformationLength, ReturnLength); // NtQueryObject_ObjectTypeInformation

	if (NT_SUCCESS(ret_value) && ObjectInformation_used != NULL) {
		convert__OBJECT_TYPE_INFORMATION_64TO32(ctx, (_OBJECT_TYPE_INFORMATION*)ObjectInformation_used, x32based_ObjectInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_BASIC_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_BASIC_INFORMATION)];
	PROCESS_BASIC_INFORMATION* ProcessInformation_used = (PROCESS_BASIC_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessBasicInformation

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_BASIC_INFORMATION_64TO32(ctx, (_PROCESS_BASIC_INFORMATION*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessQuotaLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ QUOTA_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // QUOTA_LIMITS *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_QUOTA_LIMITS)];
	QUOTA_LIMITS* ProcessInformation_used = (QUOTA_LIMITS*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessQuotaLimits

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__QUOTA_LIMITS_64TO32(ctx, (_QUOTA_LIMITS*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessVmCounters(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ VM_COUNTERS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // VM_COUNTERS *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_VM_COUNTERS)];
	VM_COUNTERS* ProcessInformation_used = (VM_COUNTERS*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessVmCounters

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__VM_COUNTERS_64TO32(ctx, (_VM_COUNTERS*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessPooledUsageAndLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ POOLED_USAGE_AND_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // POOLED_USAGE_AND_LIMITS *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_POOLED_USAGE_AND_LIMITS)];
	POOLED_USAGE_AND_LIMITS* ProcessInformation_used = (POOLED_USAGE_AND_LIMITS*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessPooledUsageAndLimits

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__POOLED_USAGE_AND_LIMITS_64TO32(ctx, (_POOLED_USAGE_AND_LIMITS*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessWorkingSetWatch(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_WS_WATCH_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_WS_WATCH_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_WS_WATCH_INFORMATION)];
	PROCESS_WS_WATCH_INFORMATION* ProcessInformation_used = (PROCESS_WS_WATCH_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessWorkingSetWatch

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_WS_WATCH_INFORMATION_64TO32(ctx, (_PROCESS_WS_WATCH_INFORMATION*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessDeviceMap(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_DEVICEMAP_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_DEVICEMAP_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_DEVICEMAP_INFORMATION)];
	PROCESS_DEVICEMAP_INFORMATION* ProcessInformation_used = (PROCESS_DEVICEMAP_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessDeviceMap

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_DEVICEMAP_INFORMATION_64TO32(ctx, (_PROCESS_DEVICEMAP_INFORMATION*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageFileName(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // UNICODE_STRING *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	UNICODE_STRING* ProcessInformation_used = 0;

	if (x32based_ProcessInformation != NULL && ProcessInformationLength != 0) {
		ProcessInformation_used = (UNICODE_STRING*)intrnl__ntcallmalloc(ctx, ProcessInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessImageFileName

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		CVT_UNICODE_STRING_OFFSETABLE_FUNC64TO32(ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessHandleTracing(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_HANDLE_TRACING_QUERY* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_HANDLE_TRACING_QUERY *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_HANDLE_TRACING_QUERY)];
	PROCESS_HANDLE_TRACING_QUERY* ProcessInformation_used = (PROCESS_HANDLE_TRACING_QUERY*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessHandleTracing

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_HANDLE_TRACING_QUERY_64TO32(ctx, (_PROCESS_HANDLE_TRACING_QUERY*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ SECTION_IMAGE_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // SECTION_IMAGE_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_SECTION_IMAGE_INFORMATION)];
	SECTION_IMAGE_INFORMATION* ProcessInformation_used = (SECTION_IMAGE_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessImageInformation

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__SECTION_IMAGE_INFORMATION_64TO32(ctx, (_SECTION_IMAGE_INFORMATION*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessWorkingSetWatchEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_WS_WATCH_INFORMATION_EX* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_WS_WATCH_INFORMATION_EX *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_WS_WATCH_INFORMATION_EX)];
	PROCESS_WS_WATCH_INFORMATION_EX* ProcessInformation_used = (PROCESS_WS_WATCH_INFORMATION_EX*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessWorkingSetWatchEx

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_WS_WATCH_INFORMATION_EX_64TO32(ctx, (_PROCESS_WS_WATCH_INFORMATION_EX*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessImageFileNameWin32(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // UNICODE_STRING *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	UNICODE_STRING* ProcessInformation_used = 0;

	if (x32based_ProcessInformation != NULL && ProcessInformationLength != 0) {
		ProcessInformation_used = (UNICODE_STRING*)intrnl__ntcallmalloc(ctx, ProcessInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessImageFileNameWin32

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		CVT_UNICODE_STRING_OFFSETABLE_FUNC64TO32(ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessHandleInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PROCESS_HANDLE_SNAPSHOT_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_HANDLE_SNAPSHOT_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_HANDLE_SNAPSHOT_INFORMATION)];
	PROCESS_HANDLE_SNAPSHOT_INFORMATION* ProcessInformation_used = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation == NULL) {
		ProcessInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessHandleInformation

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		convert__PROCESS_HANDLE_SNAPSHOT_INFORMATION_64TO32(ctx, (_PROCESS_HANDLE_SNAPSHOT_INFORMATION*)ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationProcess_ProcessCommandLineInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ UNICODE_STRING* ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // UNICODE_STRING *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	UNICODE_STRING* ProcessInformation_used = 0;

	if (x32based_ProcessInformation != NULL && ProcessInformationLength != 0) {
		ProcessInformation_used = (UNICODE_STRING*)intrnl__ntcallmalloc(ctx, ProcessInformationLength);
	}

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength, ReturnLength); // NtQueryInformationProcess_ProcessCommandLineInformation

	if (NT_SUCCESS(ret_value) && ProcessInformation_used != NULL) {
		CVT_UNICODE_STRING_OFFSETABLE_FUNC64TO32(ProcessInformation_used, x32based_ProcessInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessQuotaLimits(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ QUOTA_LIMITS* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // QUOTA_LIMITS *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_QUOTA_LIMITS)];
	QUOTA_LIMITS* ProcessInformation_used = (QUOTA_LIMITS*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__QUOTA_LIMITS_32TO64(ctx, (_QUOTA_LIMITS**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessQuotaLimits

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessExceptionPort(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_EXCEPTION_PORT* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_EXCEPTION_PORT *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_EXCEPTION_PORT)];
	PROCESS_EXCEPTION_PORT* ProcessInformation_used = (PROCESS_EXCEPTION_PORT*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_EXCEPTION_PORT_32TO64(ctx, (_PROCESS_EXCEPTION_PORT**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessExceptionPort

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessAccessToken(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_ACCESS_TOKEN* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_ACCESS_TOKEN *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_ACCESS_TOKEN)];
	PROCESS_ACCESS_TOKEN* ProcessInformation_used = (PROCESS_ACCESS_TOKEN*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_ACCESS_TOKEN_32TO64(ctx, (_PROCESS_ACCESS_TOKEN**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessAccessToken

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessAffinityMask(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ KAFFINITY* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // KAFFINITY *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(long long unsigned int)];
	KAFFINITY* ProcessInformation_used = (KAFFINITY*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		*((SIZE_T*)ProcessInformation_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_ProcessInformation));
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessAffinityMask

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessInstrumentationCallback(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION)];
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION* ProcessInformation_used = (PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32TO64(ctx, (_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessInstrumentationCallback

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessThreadStackAllocation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_STACK_ALLOCATION_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_STACK_ALLOCATION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_STACK_ALLOCATION_INFORMATION)];
	PROCESS_STACK_ALLOCATION_INFORMATION* ProcessInformation_used = (PROCESS_STACK_ALLOCATION_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_STACK_ALLOCATION_INFORMATION_32TO64(ctx, (_PROCESS_STACK_ALLOCATION_INFORMATION**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessThreadStackAllocation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessMemoryExhaustion(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_MEMORY_EXHAUSTION_INFO* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_MEMORY_EXHAUSTION_INFO *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_MEMORY_EXHAUSTION_INFO)];
	PROCESS_MEMORY_EXHAUSTION_INFO* ProcessInformation_used = (PROCESS_MEMORY_EXHAUSTION_INFO*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_MEMORY_EXHAUSTION_INFO_32TO64(ctx, (_PROCESS_MEMORY_EXHAUSTION_INFO**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessMemoryExhaustion

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationProcess_ProcessCombineSecurityDomainsInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ProcessHandle, _In_ PROCESSINFOCLASS ProcessInformationClass, _In_ PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION* ProcessInformation, _In_ ULONG ProcessInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ProcessInformation = (uint32_t)(ProcessInformation); // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessInformation_holder[sizeof(_PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION)];
	PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION* ProcessInformation_used = (PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION*)&ProcessInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessInformation != NULL) {
		convert__PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION_32TO64(ctx, (_PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION**)&ProcessInformation_used, x32based_ProcessInformation);
	}
	else {
		ProcessInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle, ProcessInformationClass, ProcessInformation_used, ProcessInformationLength); // NtSetInformationProcess_ProcessCombineSecurityDomainsInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_BASIC_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_THREAD_BASIC_INFORMATION)];
	THREAD_BASIC_INFORMATION* ThreadInformation_used = (THREAD_BASIC_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	else {
		ThreadInformationLength = sizeof(THREAD_BASIC_INFORMATION);
	}

	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadBasicInformation

	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__THREAD_BASIC_INFORMATION_64TO32(ctx, (_THREAD_BASIC_INFORMATION*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadLastSystemCall(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_LAST_SYSCALL_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_LAST_SYSCALL_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_THREAD_LAST_SYSCALL_INFORMATION)];
	THREAD_LAST_SYSCALL_INFORMATION* ThreadInformation_used = (THREAD_LAST_SYSCALL_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadLastSystemCall

	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__THREAD_LAST_SYSCALL_INFORMATION_64TO32(ctx, (_THREAD_LAST_SYSCALL_INFORMATION*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadTebInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_TEB_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_TEB_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_THREAD_TEB_INFORMATION)];
	THREAD_TEB_INFORMATION* ThreadInformation_used = (THREAD_TEB_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadTebInformation

	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__THREAD_TEB_INFORMATION_64TO32(ctx, (_THREAD_TEB_INFORMATION*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadGroupInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ GROUP_AFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // GROUP_AFFINITY *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_GROUP_AFFINITY)];
	GROUP_AFFINITY* ThreadInformation_used = (GROUP_AFFINITY*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadGroupInformation

	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__GROUP_AFFINITY_64TO32(ctx, (_GROUP_AFFINITY*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadCounterProfiling(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_PROFILING_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_PROFILING_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_THREAD_PROFILING_INFORMATION)];
	THREAD_PROFILING_INFORMATION* ThreadInformation_used = (THREAD_PROFILING_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadCounterProfiling

	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__THREAD_PROFILING_INFORMATION_64TO32(ctx, (_THREAD_PROFILING_INFORMATION*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtQueryInformationThread_ThreadNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _Out_ THREAD_NAME_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack

	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_NAME_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters

	uint8_t ThreadInformation_holder[sizeof(_THREAD_NAME_INFORMATION)];
	THREAD_NAME_INFORMATION* ThreadInformation_used = (THREAD_NAME_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64

	if (x32based_ThreadInformation == NULL) {
		ThreadInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength, ReturnLength); // NtQueryInformationThread_ThreadNameInformation


	if (NT_SUCCESS(ret_value) && ThreadInformation_used != NULL) {
		convert__THREAD_NAME_INFORMATION_64TO32(ctx, (_THREAD_NAME_INFORMATION*)ThreadInformation_used, x32based_ThreadInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadAffinityMask(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ KAFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // KAFFINITY *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(long long unsigned int)];
	KAFFINITY* ThreadInformation_used = (KAFFINITY*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation != NULL) {
		*((SIZE_T*)ThreadInformation_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_ThreadInformation));
	}
	else {
		ThreadInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength); // NtSetInformationThread_ThreadAffinityMask

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadGroupInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ GROUP_AFFINITY* ThreadInformation, _In_ ULONG ThreadInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // GROUP_AFFINITY *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_GROUP_AFFINITY)];
	GROUP_AFFINITY* ThreadInformation_used = (GROUP_AFFINITY*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation != NULL) {
		convert__GROUP_AFFINITY_32TO64(ctx, (_GROUP_AFFINITY**)&ThreadInformation_used, x32based_ThreadInformation);
	}
	else {
		ThreadInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength); // NtSetInformationThread_ThreadGroupInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadCounterProfiling(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ THREAD_PROFILING_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength) {

	// Declare parameters from stack
	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_PROFILING_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadInformation_holder[sizeof(_THREAD_PROFILING_INFORMATION)];
	THREAD_PROFILING_INFORMATION* ThreadInformation_used = (THREAD_PROFILING_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadInformation != NULL) {
		convert__THREAD_PROFILING_INFORMATION_32TO64(ctx, (_THREAD_PROFILING_INFORMATION**)&ThreadInformation_used, x32based_ThreadInformation);
	}
	else {
		ThreadInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength); // NtSetInformationThread_ThreadCounterProfiling

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationThread_ThreadNameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE ThreadHandle, _In_ THREADINFOCLASS ThreadInformationClass, _In_ THREAD_NAME_INFORMATION* ThreadInformation, _In_ ULONG ThreadInformationLength) {

	// Declare parameters from stack

	uint32_t x32based_ThreadInformation = (uint32_t)(ThreadInformation); // THREAD_NAME_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters

	uint8_t ThreadInformation_holder[sizeof(_THREAD_NAME_INFORMATION)];
	THREAD_NAME_INFORMATION* ThreadInformation_used = (THREAD_NAME_INFORMATION*)&ThreadInformation_holder;

	// Convert parameters from x32 to x64

	if (x32based_ThreadInformation != NULL) {
		convert__THREAD_NAME_INFORMATION_32TO64(ctx, (_THREAD_NAME_INFORMATION**)&ThreadInformation_used, x32based_ThreadInformation);
	}
	else {
		ThreadInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ThreadHandle, ThreadInformationClass, ThreadInformation_used, ThreadInformationLength); // NtSetInformationThread_ThreadNameInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileRenameInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_RENAME_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_RENAME_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_RENAME_INFORMATION)];
	FILE_RENAME_INFORMATION* FileInformation_used = (FILE_RENAME_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_RENAME_INFORMATION_32TO64(ctx, (_FILE_RENAME_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileRenameInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileLinkInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_LINK_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_LINK_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_LINK_INFORMATION)];
	FILE_LINK_INFORMATION* FileInformation_used = (FILE_LINK_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_LINK_INFORMATION_32TO64(ctx, (_FILE_LINK_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileLinkInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMailslotSetInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MAILSLOT_SET_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_MAILSLOT_SET_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_MAILSLOT_SET_INFORMATION)];
	FILE_MAILSLOT_SET_INFORMATION* FileInformation_used = (FILE_MAILSLOT_SET_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_MAILSLOT_SET_INFORMATION_32TO64(ctx, (_FILE_MAILSLOT_SET_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileMailslotSetInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileCompletionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_COMPLETION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_COMPLETION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_COMPLETION_INFORMATION)];
	FILE_COMPLETION_INFORMATION* FileInformation_used = (FILE_COMPLETION_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_COMPLETION_INFORMATION_32TO64(ctx, (_FILE_COMPLETION_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileCompletionInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMoveClusterInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MOVE_CLUSTER_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_MOVE_CLUSTER_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_MOVE_CLUSTER_INFORMATION)];
	FILE_MOVE_CLUSTER_INFORMATION* FileInformation_used = (FILE_MOVE_CLUSTER_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_MOVE_CLUSTER_INFORMATION_32TO64(ctx, (_FILE_MOVE_CLUSTER_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileMoveClusterInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileTrackingInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_TRACKING_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_TRACKING_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_TRACKING_INFORMATION)];
	FILE_TRACKING_INFORMATION* FileInformation_used = (FILE_TRACKING_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_TRACKING_INFORMATION_32TO64(ctx, (_FILE_TRACKING_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileTrackingInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileIoStatusBlockRangeInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_IOSTATUSBLOCK_RANGE_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_IOSTATUSBLOCK_RANGE_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_IOSTATUSBLOCK_RANGE_INFORMATION)];
	FILE_IOSTATUSBLOCK_RANGE_INFORMATION* FileInformation_used = (FILE_IOSTATUSBLOCK_RANGE_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_IOSTATUSBLOCK_RANGE_INFORMATION_32TO64(ctx, (_FILE_IOSTATUSBLOCK_RANGE_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileIoStatusBlockRangeInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileReplaceCompletionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_COMPLETION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_COMPLETION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_COMPLETION_INFORMATION)];
	FILE_COMPLETION_INFORMATION* FileInformation_used = (FILE_COMPLETION_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_COMPLETION_INFORMATION_32TO64(ctx, (_FILE_COMPLETION_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileReplaceCompletionInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileRenameInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_RENAME_INFORMATION_EX* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_RENAME_INFORMATION_EX *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_RENAME_INFORMATION_EX)];
	FILE_RENAME_INFORMATION_EX* FileInformation_used = (FILE_RENAME_INFORMATION_EX*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_RENAME_INFORMATION_EX_32TO64(ctx, (_FILE_RENAME_INFORMATION_EX**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileRenameInformationEx

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileMemoryPartitionInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_MEMORY_PARTITION_INFORMATION* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_MEMORY_PARTITION_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_MEMORY_PARTITION_INFORMATION)];
	FILE_MEMORY_PARTITION_INFORMATION* FileInformation_used = (FILE_MEMORY_PARTITION_INFORMATION*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_MEMORY_PARTITION_INFORMATION_32TO64(ctx, (_FILE_MEMORY_PARTITION_INFORMATION**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileMemoryPartitionInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtSetInformationFile_FileLinkInformationEx(void* ctx, uint32_t syscall_idx, _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _In_ FILE_LINK_INFORMATION_EX* FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass) {

	// Declare parameters from stack
	uint32_t x32based_FileInformation = (uint32_t)(FileInformation); // FILE_LINK_INFORMATION_EX *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileInformation_holder[sizeof(_FILE_LINK_INFORMATION_EX)];
	FILE_LINK_INFORMATION_EX* FileInformation_used = (FILE_LINK_INFORMATION_EX*)&FileInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileInformation != NULL) {
		convert__FILE_LINK_INFORMATION_EX_32TO64(ctx, (_FILE_LINK_INFORMATION_EX**)&FileInformation_used, x32based_FileInformation);
	}
	else {
		FileInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, FileHandle, IoStatusBlock, FileInformation_used, Length, FileInformationClass); // NtSetInformationFile_FileLinkInformationEx

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcQueryInformation_AlpcBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _Out_ ALPC_BASIC_INFORMATION* PortInformation, _In_ ULONG Length, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_BASIC_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_BASIC_INFORMATION)];
	ALPC_BASIC_INFORMATION* PortInformation_used = (ALPC_BASIC_INFORMATION*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation == NULL) {
		PortInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, PortHandle, PortInformationClass, PortInformation_used, Length, ReturnLength); // NtAlpcQueryInformation_AlpcBasicInformation

	if (NT_SUCCESS(ret_value) && PortInformation_used != NULL) {
		convert__ALPC_BASIC_INFORMATION_64TO32(ctx, (_ALPC_BASIC_INFORMATION*)PortInformation_used, x32based_PortInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcQueryInformation_AlpcServerInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _Out_ ALPC_SERVER_INFORMATION* PortInformation, _In_ ULONG Length, _Out_ PULONG ReturnLength) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_SERVER_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_SERVER_INFORMATION)];
	ALPC_SERVER_INFORMATION* PortInformation_used = (ALPC_SERVER_INFORMATION*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation == NULL) {
		PortInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, PortHandle, PortInformationClass, PortInformation_used, Length, ReturnLength); // NtAlpcQueryInformation_AlpcServerInformation

	if (NT_SUCCESS(ret_value) && PortInformation_used != NULL) {
		convert__ALPC_SERVER_INFORMATION_64TO32(ctx, (_ALPC_SERVER_INFORMATION*)PortInformation_used, x32based_PortInformation);
	}

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcBasicInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_BASIC_INFORMATION* PortInformation, _In_ ULONG Length) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_BASIC_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_BASIC_INFORMATION)];
	ALPC_BASIC_INFORMATION* PortInformation_used = (ALPC_BASIC_INFORMATION*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation != NULL) {
		convert__ALPC_BASIC_INFORMATION_32TO64(ctx, (_ALPC_BASIC_INFORMATION**)&PortInformation_used, x32based_PortInformation);
	}
	else {
		PortInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle, PortInformationClass, PortInformation_used, Length); // NtAlpcSetInformation_AlpcBasicInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcPortInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_ATTRIBUTES* PortInformation, _In_ ULONG Length) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_PORT_ATTRIBUTES *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_PORT_ATTRIBUTES)];
	ALPC_PORT_ATTRIBUTES* PortInformation_used = (ALPC_PORT_ATTRIBUTES*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation != NULL) {
		convert__ALPC_PORT_ATTRIBUTES_32TO64(ctx, (_ALPC_PORT_ATTRIBUTES**)&PortInformation_used, x32based_PortInformation);
	}
	else {
		PortInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle, PortInformationClass, PortInformation_used, Length); // NtAlpcSetInformation_AlpcPortInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcAssociateCompletionPortInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_ASSOCIATE_COMPLETION_PORT* PortInformation, _In_ ULONG Length) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_PORT_ASSOCIATE_COMPLETION_PORT *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_PORT_ASSOCIATE_COMPLETION_PORT)];
	ALPC_PORT_ASSOCIATE_COMPLETION_PORT* PortInformation_used = (ALPC_PORT_ASSOCIATE_COMPLETION_PORT*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation != NULL) {
		convert__ALPC_PORT_ASSOCIATE_COMPLETION_PORT_32TO64(ctx, (_ALPC_PORT_ASSOCIATE_COMPLETION_PORT**)&PortInformation_used, x32based_PortInformation);
	}
	else {
		PortInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle, PortInformationClass, PortInformation_used, Length); // NtAlpcSetInformation_AlpcAssociateCompletionPortInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcMessageZoneInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_MESSAGE_ZONE_INFORMATION* PortInformation, _In_ ULONG Length) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_PORT_MESSAGE_ZONE_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_PORT_MESSAGE_ZONE_INFORMATION)];
	ALPC_PORT_MESSAGE_ZONE_INFORMATION* PortInformation_used = (ALPC_PORT_MESSAGE_ZONE_INFORMATION*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation != NULL) {
		convert__ALPC_PORT_MESSAGE_ZONE_INFORMATION_32TO64(ctx, (_ALPC_PORT_MESSAGE_ZONE_INFORMATION**)&PortInformation_used, x32based_PortInformation);
	}
	else {
		PortInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle, PortInformationClass, PortInformation_used, Length); // NtAlpcSetInformation_AlpcMessageZoneInformation

	return ret_value;
}


static NTSTATUS WINAPI _w32_NtAlpcSetInformation_AlpcRegisterCompletionListInformation(void* ctx, uint32_t syscall_idx, _In_ HANDLE PortHandle, _In_ ALPC_PORT_INFORMATION_CLASS PortInformationClass, _In_ ALPC_PORT_COMPLETION_LIST_INFORMATION* PortInformation, _In_ ULONG Length) {

	// Declare parameters from stack
	uint32_t x32based_PortInformation = (uint32_t)(PortInformation); // ALPC_PORT_COMPLETION_LIST_INFORMATION *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortInformation_holder[sizeof(_ALPC_PORT_COMPLETION_LIST_INFORMATION)];
	ALPC_PORT_COMPLETION_LIST_INFORMATION* PortInformation_used = (ALPC_PORT_COMPLETION_LIST_INFORMATION*)&PortInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortInformation != NULL) {
		convert__ALPC_PORT_COMPLETION_LIST_INFORMATION_32TO64(ctx, (_ALPC_PORT_COMPLETION_LIST_INFORMATION**)&PortInformation_used, x32based_PortInformation);
	}
	else {
		PortInformation_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle, PortInformationClass, PortInformation_used, Length); // NtAlpcSetInformation_AlpcRegisterCompletionListInformation

	return ret_value;
}



NTSTATUS WINAPI _w32_NtMapViewOfSectionEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[4]); // PVOID *  IN  OUT 
	PLARGE_INTEGER SectionOffset_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN  OUT 
	uint32_t x32based_ViewSize = (uint32_t)(x32based_args[6]); // PSIZE_T  IN  OUT 
	ULONG AllocationType_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG Win32Protect_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	uint32_t x32based_Parameters = (uint32_t)(x32based_args[9]); // MEM_EXTENDED_PARAMETER *  IN  OUT 
	ULONG ParameterCount_used = (ULONG)(x32based_args[10]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t ViewSize_holder[sizeof(long long unsigned int)];
	PSIZE_T ViewSize_used = (PSIZE_T)&ViewSize_holder;
	uint8_t Parameters_holder[sizeof(MEM_EXTENDED_PARAMETER)];
	MEM_EXTENDED_PARAMETER* Parameters_used = (MEM_EXTENDED_PARAMETER*)&Parameters_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_ViewSize != NULL) {
		*((SIZE_T*)ViewSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_ViewSize));
	}
	else {
		ViewSize_used = 0;
	}
	if (x32based_Parameters != NULL) {
		convert_MEM_EXTENDED_PARAMETER_32TO64(ctx, (MEM_EXTENDED_PARAMETER**)&Parameters_used, x32based_Parameters);
	}
	else {
		Parameters_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, SectionHandle_used, ProcessHandle_used, BaseAddress_used, SectionOffset_used, ViewSize_used, AllocationType_used, Win32Protect_used, Parameters_used, ParameterCount_used); // NtMapViewOfSectionEx

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_ViewSize != NULL) {
		*((X32_SIZE_T*)x32based_ViewSize) = (X32_SIZE_T)(*(SIZE_T*)ViewSize_used);
	}
	if (Parameters_used != NULL) {
		convert_MEM_EXTENDED_PARAMETER_64TO32(ctx, (MEM_EXTENDED_PARAMETER*)Parameters_used, x32based_Parameters);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCallbackReturn(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID OutputBuffer_used = (PVOID)(x32based_args[2]); // PVOID  IN  OUT 
	ULONG OutputLength_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	NTSTATUS Status_used = (NTSTATUS)(x32based_args[4]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, OutputBuffer_used, OutputLength_used, Status_used); // NtCallbackReturn

	return ret_value;
}


void WINAPI _w32_NtFlushProcessWriteBuffers(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	// Declare space used in parameters
	// Convert parameters from x32 to x64
	__syscall64(syscall_idx, 0); // NtFlushProcessWriteBuffers

}


NTSTATUS WINAPI _w32_NtQueryDebugFilterState(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG ComponentId_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	ULONG Level_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ComponentId_used, Level_used); // NtQueryDebugFilterState

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetDebugFilterState(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG ComponentId_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	ULONG Level_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	BOOLEAN State_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ComponentId_used, Level_used, State_used); // NtSetDebugFilterState

	return ret_value;
}


NTSTATUS WINAPI _w32_NtYieldExecution(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtYieldExecution

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDelayExecution(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[2]); // BOOLEAN  IN 
	PLARGE_INTEGER DelayInterval_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Alertable_used, DelayInterval_used); // NtDelayExecution

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySystemEnvironmentValue(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_VariableName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PWSTR VariableValue_used = (PWSTR)(x32based_args[3]); // PWSTR  OUT 
	USHORT ValueLength_used = (USHORT)(x32based_args[4]); // USHORT  IN 
	PUSHORT ReturnLength_used = (PUSHORT)(x32based_args[5]); // PUSHORT  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t VariableName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING VariableName_used = (PUNICODE_STRING)&VariableName_holder;

	// Convert parameters from x32 to x64
	if (x32based_VariableName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&VariableName_used, x32based_VariableName);
	}
	else {
		VariableName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, VariableName_used, VariableValue_used, ValueLength_used, ReturnLength_used); // NtQuerySystemEnvironmentValue

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSystemEnvironmentValue(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_VariableName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	uint32_t x32based_VariableValue = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t VariableName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING VariableName_used = (PUNICODE_STRING)&VariableName_holder;
	uint8_t VariableValue_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING VariableValue_used = (PUNICODE_STRING)&VariableValue_holder;

	// Convert parameters from x32 to x64
	if (x32based_VariableName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&VariableName_used, x32based_VariableName);
	}
	else {
		VariableName_used = 0;
	}
	if (x32based_VariableValue != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&VariableValue_used, x32based_VariableValue);
	}
	else {
		VariableValue_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, VariableName_used, VariableValue_used); // NtSetSystemEnvironmentValue

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySystemEnvironmentValueEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_VariableName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	LPGUID VendorGuid_used = (LPGUID)(x32based_args[3]); // LPGUID  IN 
	PVOID Value_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	PULONG ValueLength_used = (PULONG)(x32based_args[5]); // PULONG  IN  OUT 
	PULONG Attributes_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t VariableName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING VariableName_used = (PUNICODE_STRING)&VariableName_holder;

	// Convert parameters from x32 to x64
	if (x32based_VariableName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&VariableName_used, x32based_VariableName);
	}
	else {
		VariableName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, VariableName_used, VendorGuid_used, Value_used, ValueLength_used, Attributes_used); // NtQuerySystemEnvironmentValueEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSystemEnvironmentValueEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_VariableName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	LPGUID VendorGuid_used = (LPGUID)(x32based_args[3]); // LPGUID  IN 
	PVOID Value_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ValueLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ULONG Attributes_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t VariableName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING VariableName_used = (PUNICODE_STRING)&VariableName_holder;

	// Convert parameters from x32 to x64
	if (x32based_VariableName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&VariableName_used, x32based_VariableName);
	}
	else {
		VariableName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, VariableName_used, VendorGuid_used, Value_used, ValueLength_used, Attributes_used); // NtSetSystemEnvironmentValueEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateSystemEnvironmentValuesEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG InformationClass_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[3]); // PVOID  OUT 
	PULONG BufferLength_used = (PULONG)(x32based_args[4]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, InformationClass_used, Buffer_used, BufferLength_used); // NtEnumerateSystemEnvironmentValuesEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAddBootEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PBOOT_ENTRY BootEntry_used = (PBOOT_ENTRY)(x32based_args[2]); // PBOOT_ENTRY  IN 
	PULONG Id_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, BootEntry_used, Id_used); // NtAddBootEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteBootEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Id_used = (ULONG)(x32based_args[2]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Id_used); // NtDeleteBootEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtModifyBootEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PBOOT_ENTRY BootEntry_used = (PBOOT_ENTRY)(x32based_args[2]); // PBOOT_ENTRY  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, BootEntry_used); // NtModifyBootEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateBootEntries(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID Buffer_used = (PVOID)(x32based_args[2]); // PVOID  OUT 
	PULONG BufferLength_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Buffer_used, BufferLength_used); // NtEnumerateBootEntries

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryBootEntryOrder(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULONG Ids_used = (PULONG)(x32based_args[2]); // PULONG  OUT 
	PULONG Count_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Ids_used, Count_used); // NtQueryBootEntryOrder

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetBootEntryOrder(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULONG Ids_used = (PULONG)(x32based_args[2]); // PULONG  IN 
	ULONG Count_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Ids_used, Count_used); // NtSetBootEntryOrder

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryBootOptions(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PBOOT_OPTIONS BootOptions_used = (PBOOT_OPTIONS)(x32based_args[2]); // PBOOT_OPTIONS  OUT 
	PULONG BootOptionsLength_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, BootOptions_used, BootOptionsLength_used); // NtQueryBootOptions

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetBootOptions(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PBOOT_OPTIONS BootOptions_used = (PBOOT_OPTIONS)(x32based_args[2]); // PBOOT_OPTIONS  IN 
	ULONG FieldsToChange_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, BootOptions_used, FieldsToChange_used); // NtSetBootOptions

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTranslateFilePath(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PFILE_PATH InputFilePath_used = (PFILE_PATH)(x32based_args[2]); // PFILE_PATH  IN 
	ULONG OutputType_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PFILE_PATH OutputFilePath_used = (PFILE_PATH)(x32based_args[4]); // PFILE_PATH  OUT 
	PULONG OutputFilePathLength_used = (PULONG)(x32based_args[5]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, InputFilePath_used, OutputType_used, OutputFilePath_used, OutputFilePathLength_used); // NtTranslateFilePath

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAddDriverEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PEFI_DRIVER_ENTRY DriverEntry_used = (PEFI_DRIVER_ENTRY)(x32based_args[2]); // PEFI_DRIVER_ENTRY  IN 
	PULONG Id_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, DriverEntry_used, Id_used); // NtAddDriverEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteDriverEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Id_used = (ULONG)(x32based_args[2]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Id_used); // NtDeleteDriverEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtModifyDriverEntry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PEFI_DRIVER_ENTRY DriverEntry_used = (PEFI_DRIVER_ENTRY)(x32based_args[2]); // PEFI_DRIVER_ENTRY  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, DriverEntry_used); // NtModifyDriverEntry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateDriverEntries(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID Buffer_used = (PVOID)(x32based_args[2]); // PVOID  OUT 
	PULONG BufferLength_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Buffer_used, BufferLength_used); // NtEnumerateDriverEntries

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDriverEntryOrder(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULONG Ids_used = (PULONG)(x32based_args[2]); // PULONG  OUT 
	PULONG Count_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Ids_used, Count_used); // NtQueryDriverEntryOrder

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetDriverEntryOrder(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULONG Ids_used = (PULONG)(x32based_args[2]); // PULONG  IN 
	ULONG Count_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Ids_used, Count_used); // NtSetDriverEntryOrder

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFilterBootOption(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	FILTER_BOOT_OPTION_OPERATION FilterOperation_used = (FILTER_BOOT_OPTION_OPERATION)(x32based_args[2]); // FILTER_BOOT_OPTION_OPERATION  IN 
	ULONG ObjectType_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	ULONG ElementType_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Data_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	ULONG DataSize_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, FilterOperation_used, ObjectType_used, ElementType_used, Data_used, DataSize_used); // NtFilterBootOption

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	EVENT_TYPE EventType_used = (EVENT_TYPE)(x32based_args[5]); // EVENT_TYPE  IN 
	BOOLEAN InitialState_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EventHandle_holder[sizeof(PVOID)];
	PHANDLE EventHandle_used = (PHANDLE)&EventHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EventHandle == NULL) {
		EventHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, EventHandle_used, DesiredAccess_used, ObjectAttributes_used, EventType_used, InitialState_used); // NtCreateEvent

	if (EventHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EventHandle_used, x32based_EventHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EventHandle_holder[sizeof(PVOID)];
	PHANDLE EventHandle_used = (PHANDLE)&EventHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EventHandle == NULL) {
		EventHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, EventHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenEvent

	if (EventHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EventHandle_used, x32based_EventHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLONG PreviousState_used = (PLONG)(x32based_args[3]); // PLONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EventHandle_used, PreviousState_used); // NtSetEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetEventBoostPriority(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventHandle_used); // NtSetEventBoostPriority

	return ret_value;
}


NTSTATUS WINAPI _w32_NtClearEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventHandle_used); // NtClearEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtResetEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLONG PreviousState_used = (PLONG)(x32based_args[3]); // PLONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EventHandle_used, PreviousState_used); // NtResetEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPulseEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLONG PreviousState_used = (PLONG)(x32based_args[3]); // PLONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EventHandle_used, PreviousState_used); // NtPulseEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	EVENT_INFORMATION_CLASS EventInformationClass_used = (EVENT_INFORMATION_CLASS)(x32based_args[3]); // EVENT_INFORMATION_CLASS  IN 
	PVOID EventInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG EventInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, EventHandle_used, EventInformationClass_used, EventInformation_used, EventInformationLength_used, ReturnLength_used); // NtQueryEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EventPairHandle_holder[sizeof(PVOID)];
	PHANDLE EventPairHandle_used = (PHANDLE)&EventPairHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EventPairHandle == NULL) {
		EventPairHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, EventPairHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtCreateEventPair

	if (EventPairHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EventPairHandle_used, x32based_EventPairHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EventPairHandle_holder[sizeof(PVOID)];
	PHANDLE EventPairHandle_used = (PHANDLE)&EventPairHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EventPairHandle == NULL) {
		EventPairHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, EventPairHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenEventPair

	if (EventPairHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EventPairHandle_used, x32based_EventPairHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetLowEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtSetLowEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetHighEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtSetHighEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitLowEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtWaitLowEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitHighEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtWaitHighEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetLowWaitHighEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtSetLowWaitHighEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetHighWaitLowEventPair(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EventPairHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EventPairHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EventPairHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, EventPairHandle_used); // NtSetHighWaitLowEventPair

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateMutant(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MutantHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	BOOLEAN InitialOwner_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MutantHandle_holder[sizeof(PVOID)];
	PHANDLE MutantHandle_used = (PHANDLE)&MutantHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_MutantHandle == NULL) {
		MutantHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, MutantHandle_used, DesiredAccess_used, ObjectAttributes_used, InitialOwner_used); // NtCreateMutant

	if (MutantHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)MutantHandle_used, x32based_MutantHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenMutant(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MutantHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MutantHandle_holder[sizeof(PVOID)];
	PHANDLE MutantHandle_used = (PHANDLE)&MutantHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_MutantHandle == NULL) {
		MutantHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, MutantHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenMutant

	if (MutantHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)MutantHandle_used, x32based_MutantHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReleaseMutant(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MutantHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLONG PreviousCount_used = (PLONG)(x32based_args[3]); // PLONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE MutantHandle_used = Handle32ToHandle((const void* __ptr32)x32based_MutantHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, MutantHandle_used, PreviousCount_used); // NtReleaseMutant

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryMutant(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MutantHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	MUTANT_INFORMATION_CLASS MutantInformationClass_used = (MUTANT_INFORMATION_CLASS)(x32based_args[3]); // MUTANT_INFORMATION_CLASS  IN 
	PVOID MutantInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG MutantInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE MutantHandle_used = Handle32ToHandle((const void* __ptr32)x32based_MutantHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, MutantHandle_used, MutantInformationClass_used, MutantInformation_used, MutantInformationLength_used, ReturnLength_used); // NtQueryMutant

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateSemaphore(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SemaphoreHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	LONG InitialCount_used = (LONG)(x32based_args[5]); // LONG  IN 
	LONG MaximumCount_used = (LONG)(x32based_args[6]); // LONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SemaphoreHandle_holder[sizeof(PVOID)];
	PHANDLE SemaphoreHandle_used = (PHANDLE)&SemaphoreHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_SemaphoreHandle == NULL) {
		SemaphoreHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, SemaphoreHandle_used, DesiredAccess_used, ObjectAttributes_used, InitialCount_used, MaximumCount_used); // NtCreateSemaphore

	if (SemaphoreHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SemaphoreHandle_used, x32based_SemaphoreHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenSemaphore(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SemaphoreHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SemaphoreHandle_holder[sizeof(PVOID)];
	PHANDLE SemaphoreHandle_used = (PHANDLE)&SemaphoreHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_SemaphoreHandle == NULL) {
		SemaphoreHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SemaphoreHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenSemaphore

	if (SemaphoreHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SemaphoreHandle_used, x32based_SemaphoreHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReleaseSemaphore(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SemaphoreHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	LONG ReleaseCount_used = (LONG)(x32based_args[3]); // LONG  IN 
	PLONG PreviousCount_used = (PLONG)(x32based_args[4]); // PLONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SemaphoreHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SemaphoreHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, SemaphoreHandle_used, ReleaseCount_used, PreviousCount_used); // NtReleaseSemaphore

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySemaphore(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SemaphoreHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass_used = (SEMAPHORE_INFORMATION_CLASS)(x32based_args[3]); // SEMAPHORE_INFORMATION_CLASS  IN 
	PVOID SemaphoreInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG SemaphoreInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SemaphoreHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SemaphoreHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, SemaphoreHandle_used, SemaphoreInformationClass_used, SemaphoreInformation_used, SemaphoreInformationLength_used, ReturnLength_used); // NtQuerySemaphore

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	TIMER_TYPE TimerType_used = (TIMER_TYPE)(x32based_args[5]); // TIMER_TYPE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TimerHandle_holder[sizeof(PVOID)];
	PHANDLE TimerHandle_used = (PHANDLE)&TimerHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_TimerHandle == NULL) {
		TimerHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, TimerHandle_used, DesiredAccess_used, ObjectAttributes_used, TimerType_used); // NtCreateTimer

	if (TimerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TimerHandle_used, x32based_TimerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TimerHandle_holder[sizeof(PVOID)];
	PHANDLE TimerHandle_used = (PHANDLE)&TimerHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_TimerHandle == NULL) {
		TimerHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, TimerHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenTimer

	if (TimerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TimerHandle_used, x32based_TimerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER DueTime_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 
	PTIMER_APC_ROUTINE TimerApcRoutine_used = (PTIMER_APC_ROUTINE)(x32based_args[4]); // PTIMER_APC_ROUTINE  IN 
	PVOID TimerContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	BOOLEAN ResumeTimer_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 
	LONG Period_used = (LONG)(x32based_args[7]); // LONG  IN 
	PBOOLEAN PreviousState_used = (PBOOLEAN)(x32based_args[8]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 7, TimerHandle_used, DueTime_used, TimerApcRoutine_used, TimerContext_used, ResumeTimer_used, Period_used, PreviousState_used); // NtSetTimer

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetTimerEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TIMER_SET_INFORMATION_CLASS TimerSetInformationClass_used = (TIMER_SET_INFORMATION_CLASS)(x32based_args[3]); // TIMER_SET_INFORMATION_CLASS  IN 
	PVOID TimerSetInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG TimerSetInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TimerHandle_used, TimerSetInformationClass_used, TimerSetInformation_used, TimerSetInformationLength_used); // NtSetTimerEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PBOOLEAN CurrentState_used = (PBOOLEAN)(x32based_args[3]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TimerHandle_used, CurrentState_used); // NtCancelTimer

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TIMER_INFORMATION_CLASS TimerInformationClass_used = (TIMER_INFORMATION_CLASS)(x32based_args[3]); // TIMER_INFORMATION_CLASS  IN 
	PVOID TimerInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG TimerInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, TimerHandle_used, TimerInformationClass_used, TimerInformation_used, TimerInformationLength_used, ReturnLength_used); // NtQueryTimer

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateIRTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TimerHandle_holder[sizeof(PVOID)];
	PHANDLE TimerHandle_used = (PHANDLE)&TimerHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TimerHandle == NULL) {
		TimerHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 2, TimerHandle_used, DesiredAccess_used); // NtCreateIRTimer

	if (TimerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TimerHandle_used, x32based_TimerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetIRTimer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER DueTime_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TimerHandle_used, DueTime_used); // NtSetIRTimer

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateTimer2(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	PVOID Reserved1_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Reserved2_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Attributes_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[6]); // ACCESS_MASK  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TimerHandle_holder[sizeof(PVOID)];
	PHANDLE TimerHandle_used = (PHANDLE)&TimerHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TimerHandle == NULL) {
		TimerHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, TimerHandle_used, Reserved1_used, Reserved2_used, Attributes_used, DesiredAccess_used); // NtCreateTimer2

	if (TimerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TimerHandle_used, x32based_TimerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetTimer2(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER DueTime_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER Period_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 
	PT2_SET_PARAMETERS Parameters_used = (PT2_SET_PARAMETERS)(x32based_args[5]); // PT2_SET_PARAMETERS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TimerHandle_used, DueTime_used, Period_used, Parameters_used); // NtSetTimer2

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelTimer2(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TimerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PT2_CANCEL_PARAMETERS Parameters_used = (PT2_CANCEL_PARAMETERS)(x32based_args[3]); // PT2_CANCEL_PARAMETERS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TimerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TimerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TimerHandle_used, Parameters_used); // NtCancelTimer2

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateProfile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProfileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_Process = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PVOID ProfileBase_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T ProfileSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	ULONG BucketSize_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG Buffer_used = (PULONG)(x32based_args[7]); // PULONG  IN 
	ULONG BufferSize_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	KPROFILE_SOURCE ProfileSource_used = (KPROFILE_SOURCE)(x32based_args[9]); // KPROFILE_SOURCE  IN 
	uint32_t x32based_Affinity = (uint32_t)(x32based_args[10]); // KAFFINITY  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProfileHandle_holder[sizeof(PVOID)];
	PHANDLE ProfileHandle_used = (PHANDLE)&ProfileHandle_holder;
	HANDLE Process_used = Handle32ToHandle((const void* __ptr32)x32based_Process);
	uint8_t Affinity_holder[sizeof(long long unsigned int)];
	KAFFINITY Affinity_used = (KAFFINITY)&Affinity_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProfileHandle == NULL) {
		ProfileHandle_used = 0;
	}
	if (x32based_Affinity != NULL) {
		*((SIZE_T*)Affinity_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_Affinity));
	}
	else {
		Affinity_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, ProfileHandle_used, Process_used, ProfileBase_used, ProfileSize_used, BucketSize_used, Buffer_used, BufferSize_used, ProfileSource_used, Affinity_used); // NtCreateProfile

	if (ProfileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProfileHandle_used, x32based_ProfileHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateProfileEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProfileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_Process = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PVOID ProfileBase_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T ProfileSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	ULONG BucketSize_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG Buffer_used = (PULONG)(x32based_args[7]); // PULONG  IN 
	ULONG BufferSize_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	KPROFILE_SOURCE ProfileSource_used = (KPROFILE_SOURCE)(x32based_args[9]); // KPROFILE_SOURCE  IN 
	USHORT GroupCount_used = (USHORT)(x32based_args[10]); // USHORT  IN 
	uint32_t x32based_GroupAffinity = (uint32_t)(x32based_args[11]); // PGROUP_AFFINITY  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProfileHandle_holder[sizeof(PVOID)];
	PHANDLE ProfileHandle_used = (PHANDLE)&ProfileHandle_holder;
	HANDLE Process_used = Handle32ToHandle((const void* __ptr32)x32based_Process);
	uint8_t GroupAffinity_holder[sizeof(_GROUP_AFFINITY)];
	PGROUP_AFFINITY GroupAffinity_used = (PGROUP_AFFINITY)&GroupAffinity_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProfileHandle == NULL) {
		ProfileHandle_used = 0;
	}
	if (x32based_GroupAffinity != NULL) {
		convert__GROUP_AFFINITY_32TO64(ctx, (_GROUP_AFFINITY**)&GroupAffinity_used, x32based_GroupAffinity);
	}
	else {
		GroupAffinity_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 10, ProfileHandle_used, Process_used, ProfileBase_used, ProfileSize_used, BucketSize_used, Buffer_used, BufferSize_used, ProfileSource_used, GroupCount_used, GroupAffinity_used); // NtCreateProfileEx

	if (ProfileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProfileHandle_used, x32based_ProfileHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtStartProfile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProfileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProfileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProfileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ProfileHandle_used); // NtStartProfile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtStopProfile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProfileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProfileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProfileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ProfileHandle_used); // NtStopProfile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryIntervalProfile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	KPROFILE_SOURCE ProfileSource_used = (KPROFILE_SOURCE)(x32based_args[2]); // KPROFILE_SOURCE  IN 
	PULONG Interval_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProfileSource_used, Interval_used); // NtQueryIntervalProfile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetIntervalProfile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Interval_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	KPROFILE_SOURCE Source_used = (KPROFILE_SOURCE)(x32based_args[3]); // KPROFILE_SOURCE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Interval_used, Source_used); // NtSetIntervalProfile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateKeyedEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyedEventHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyedEventHandle_holder[sizeof(PVOID)];
	PHANDLE KeyedEventHandle_used = (PHANDLE)&KeyedEventHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyedEventHandle == NULL) {
		KeyedEventHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, KeyedEventHandle_used, DesiredAccess_used, ObjectAttributes_used, Flags_used); // NtCreateKeyedEvent

	if (KeyedEventHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyedEventHandle_used, x32based_KeyedEventHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenKeyedEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyedEventHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyedEventHandle_holder[sizeof(PVOID)];
	PHANDLE KeyedEventHandle_used = (PHANDLE)&KeyedEventHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyedEventHandle == NULL) {
		KeyedEventHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, KeyedEventHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenKeyedEvent

	if (KeyedEventHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyedEventHandle_used, x32based_KeyedEventHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReleaseKeyedEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyedEventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID KeyValue_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyedEventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyedEventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, KeyedEventHandle_used, KeyValue_used, Alertable_used, Timeout_used); // NtReleaseKeyedEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForKeyedEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyedEventHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID KeyValue_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyedEventHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyedEventHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, KeyedEventHandle_used, KeyValue_used, Alertable_used, Timeout_used); // NtWaitForKeyedEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUmsThreadYield(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID SchedulerParam_used = (PVOID)(x32based_args[2]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, SchedulerParam_used); // NtUmsThreadYield

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateWnfStateName(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PWNF_STATE_NAME StateName_used = (PWNF_STATE_NAME)(x32based_args[2]); // PWNF_STATE_NAME  OUT 
	WNF_STATE_NAME_LIFETIME NameLifetime_used = (WNF_STATE_NAME_LIFETIME)(x32based_args[3]); // WNF_STATE_NAME_LIFETIME  IN 
	WNF_DATA_SCOPE DataScope_used = (WNF_DATA_SCOPE)(x32based_args[4]); // WNF_DATA_SCOPE  IN 
	BOOLEAN PersistData_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	PCWNF_TYPE_ID TypeId_used = (PCWNF_TYPE_ID)(x32based_args[6]); // PCWNF_TYPE_ID  IN 
	ULONG MaximumStateSize_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[8]); // PSECURITY_DESCRIPTOR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 7, StateName_used, NameLifetime_used, DataScope_used, PersistData_used, TypeId_used, MaximumStateSize_used, SecurityDescriptor_used); // NtCreateWnfStateName

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteWnfStateName(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, StateName_used); // NtDeleteWnfStateName

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUpdateWnfStateData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 
	void const* Buffer_used = (void const*)(x32based_args[3]); // void const *  IN 
	ULONG Length_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PCWNF_TYPE_ID TypeId_used = (PCWNF_TYPE_ID)(x32based_args[5]); // PCWNF_TYPE_ID  IN 
	void const* ExplicitScope_used = (void const*)(x32based_args[6]); // void const *  IN 
	WNF_CHANGE_STAMP MatchingChangeStamp_used = (WNF_CHANGE_STAMP)(x32based_args[7]); // WNF_CHANGE_STAMP  IN 
	LOGICAL CheckStamp_used = (LOGICAL)(x32based_args[8]); // LOGICAL  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 7, StateName_used, Buffer_used, Length_used, TypeId_used, ExplicitScope_used, MatchingChangeStamp_used, CheckStamp_used); // NtUpdateWnfStateData

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteWnfStateData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 
	void const* ExplicitScope_used = (void const*)(x32based_args[3]); // void const *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, StateName_used, ExplicitScope_used); // NtDeleteWnfStateData

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryWnfStateData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 
	PCWNF_TYPE_ID TypeId_used = (PCWNF_TYPE_ID)(x32based_args[3]); // PCWNF_TYPE_ID  IN 
	void const* ExplicitScope_used = (void const*)(x32based_args[4]); // void const *  IN 
	PWNF_CHANGE_STAMP ChangeStamp_used = (PWNF_CHANGE_STAMP)(x32based_args[5]); // PWNF_CHANGE_STAMP  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[6]); // PVOID  OUT 
	PULONG BufferSize_used = (PULONG)(x32based_args[7]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, StateName_used, TypeId_used, ExplicitScope_used, ChangeStamp_used, Buffer_used, BufferSize_used); // NtQueryWnfStateData

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryWnfStateNameInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 
	WNF_STATE_NAME_INFORMATION NameInfoClass_used = (WNF_STATE_NAME_INFORMATION)(x32based_args[3]); // WNF_STATE_NAME_INFORMATION  IN 
	void const* ExplicitScope_used = (void const*)(x32based_args[4]); // void const *  IN 
	PVOID InfoBuffer_used = (PVOID)(x32based_args[5]); // PVOID  IN  OUT 
	ULONG InfoBufferSize_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, StateName_used, NameInfoClass_used, ExplicitScope_used, InfoBuffer_used, InfoBufferSize_used); // NtQueryWnfStateNameInformation

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSubscribeWnfStateChange(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 
	WNF_CHANGE_STAMP ChangeStamp_used = (WNF_CHANGE_STAMP)(x32based_args[3]); // WNF_CHANGE_STAMP  IN 
	ULONG EventMask_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PULONG64 SubscriptionId_used = (PULONG64)(x32based_args[5]); // PULONG64  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, StateName_used, ChangeStamp_used, EventMask_used, SubscriptionId_used); // NtSubscribeWnfStateChange

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnsubscribeWnfStateChange(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCWNF_STATE_NAME StateName_used = (PCWNF_STATE_NAME)(x32based_args[2]); // PCWNF_STATE_NAME  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, StateName_used); // NtUnsubscribeWnfStateChange

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetCompleteWnfStateSubscription(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PWNF_STATE_NAME OldDescriptorStateName_used = (PWNF_STATE_NAME)(x32based_args[2]); // PWNF_STATE_NAME  IN 
	ULONG64* OldSubscriptionId_used = (ULONG64*)(x32based_args[3]); // ULONG64 *  IN 
	ULONG OldDescriptorEventMask_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG OldDescriptorStatus_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor_used = (PWNF_DELIVERY_DESCRIPTOR)(x32based_args[6]); // PWNF_DELIVERY_DESCRIPTOR  OUT 
	ULONG DescriptorSize_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, OldDescriptorStateName_used, OldSubscriptionId_used, OldDescriptorEventMask_used, OldDescriptorStatus_used, NewDeliveryDescriptor_used, DescriptorSize_used); // NtGetCompleteWnfStateSubscription

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetWnfProcessNotificationEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_NotificationEvent = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE NotificationEvent_used = Handle32ToHandle((const void* __ptr32)x32based_NotificationEvent);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, NotificationEvent_used); // NtSetWnfProcessNotificationEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateWorkerFactory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandleReturn = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_CompletionPortHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	uint32_t x32based_WorkerProcessHandle = (uint32_t)(x32based_args[6]); // HANDLE  IN 
	PVOID StartRoutine_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	PVOID StartParameter_used = (PVOID)(x32based_args[8]); // PVOID  IN 
	ULONG MaxThreadCount_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	SIZE_T StackReserve_used = (SIZE_T)(x32based_args[10]); // SIZE_T  IN 
	SIZE_T StackCommit_used = (SIZE_T)(x32based_args[11]); // SIZE_T  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t WorkerFactoryHandleReturn_holder[sizeof(PVOID)];
	PHANDLE WorkerFactoryHandleReturn_used = (PHANDLE)&WorkerFactoryHandleReturn_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE CompletionPortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_CompletionPortHandle);
	HANDLE WorkerProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerProcessHandle);

	// Convert parameters from x32 to x64
	if (x32based_WorkerFactoryHandleReturn == NULL) {
		WorkerFactoryHandleReturn_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 10, WorkerFactoryHandleReturn_used, DesiredAccess_used, ObjectAttributes_used, CompletionPortHandle_used, WorkerProcessHandle_used, StartRoutine_used, StartParameter_used, MaxThreadCount_used, StackReserve_used, StackCommit_used); // NtCreateWorkerFactory

	if (WorkerFactoryHandleReturn_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)WorkerFactoryHandleReturn_used, x32based_WorkerFactoryHandleReturn);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationWorkerFactory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	WORKERFACTORYINFOCLASS WorkerFactoryInformationClass_used = (WORKERFACTORYINFOCLASS)(x32based_args[3]); // WORKERFACTORYINFOCLASS  IN 
	PVOID WorkerFactoryInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG WorkerFactoryInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, WorkerFactoryHandle_used, WorkerFactoryInformationClass_used, WorkerFactoryInformation_used, WorkerFactoryInformationLength_used, ReturnLength_used); // NtQueryInformationWorkerFactory

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationWorkerFactory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	WORKERFACTORYINFOCLASS WorkerFactoryInformationClass_used = (WORKERFACTORYINFOCLASS)(x32based_args[3]); // WORKERFACTORYINFOCLASS  IN 
	PVOID WorkerFactoryInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG WorkerFactoryInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, WorkerFactoryHandle_used, WorkerFactoryInformationClass_used, WorkerFactoryInformation_used, WorkerFactoryInformationLength_used); // NtSetInformationWorkerFactory

	return ret_value;
}


NTSTATUS WINAPI _w32_NtShutdownWorkerFactory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	LONG volatile* PendingWorkerCount_used = (LONG volatile*)(x32based_args[3]); // LONG volatile *  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, WorkerFactoryHandle_used, PendingWorkerCount_used); // NtShutdownWorkerFactory

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReleaseWorkerFactoryWorker(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, WorkerFactoryHandle_used); // NtReleaseWorkerFactoryWorker

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWorkerFactoryWorkerReady(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, WorkerFactoryHandle_used); // NtWorkerFactoryWorkerReady

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForWorkViaWorkerFactory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WorkerFactoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_MiniPacket = (uint32_t)(x32based_args[3]); // _FILE_IO_COMPLETION_INFORMATION *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WorkerFactoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WorkerFactoryHandle);
	uint8_t MiniPacket_holder[sizeof(_FILE_IO_COMPLETION_INFORMATION)];
	_FILE_IO_COMPLETION_INFORMATION* MiniPacket_used = (_FILE_IO_COMPLETION_INFORMATION*)&MiniPacket_holder;

	// Convert parameters from x32 to x64
	if (x32based_MiniPacket == NULL) {
		MiniPacket_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 2, WorkerFactoryHandle_used, MiniPacket_used); // NtWaitForWorkViaWorkerFactory

	if (MiniPacket_used != NULL) {
		convert__FILE_IO_COMPLETION_INFORMATION_64TO32(ctx, (_FILE_IO_COMPLETION_INFORMATION*)MiniPacket_used, x32based_MiniPacket);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSystemTime(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PLARGE_INTEGER SystemTime_used = (PLARGE_INTEGER)(x32based_args[2]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER PreviousTime_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, SystemTime_used, PreviousTime_used); // NtSetSystemTime

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryTimerResolution(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULONG MaximumTime_used = (PULONG)(x32based_args[2]); // PULONG  OUT 
	PULONG MinimumTime_used = (PULONG)(x32based_args[3]); // PULONG  OUT 
	PULONG CurrentTime_used = (PULONG)(x32based_args[4]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, MaximumTime_used, MinimumTime_used, CurrentTime_used); // NtQueryTimerResolution

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetTimerResolution(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG DesiredTime_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	BOOLEAN SetResolution_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	PULONG ActualTime_used = (PULONG)(x32based_args[4]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, DesiredTime_used, SetResolution_used, ActualTime_used); // NtSetTimerResolution

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryPerformanceCounter(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PLARGE_INTEGER PerformanceCounter_used = (PLARGE_INTEGER)(x32based_args[2]); // PLARGE_INTEGER  OUT 
	PLARGE_INTEGER PerformanceFrequency_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, PerformanceCounter_used, PerformanceFrequency_used); // NtQueryPerformanceCounter

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAllocateLocallyUniqueId(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PLUID Luid_used = (PLUID)(x32based_args[2]); // PLUID  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Luid_used); // NtAllocateLocallyUniqueId

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetUuidSeed(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCHAR Seed_used = (PCHAR)(x32based_args[2]); // PCHAR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Seed_used); // NtSetUuidSeed

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAllocateUuids(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PULARGE_INTEGER Time_used = (PULARGE_INTEGER)(x32based_args[2]); // PULARGE_INTEGER  OUT 
	PULONG Range_used = (PULONG)(x32based_args[3]); // PULONG  OUT 
	PULONG Sequence_used = (PULONG)(x32based_args[4]); // PULONG  OUT 
	PCHAR Seed_used = (PCHAR)(x32based_args[5]); // PCHAR  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, Time_used, Range_used, Sequence_used, Seed_used); // NtAllocateUuids

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySystemInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	SYSTEM_INFORMATION_CLASS SystemInformationClass_used = (SYSTEM_INFORMATION_CLASS)(x32based_args[2]); // SYSTEM_INFORMATION_CLASS  IN 
	PVOID SystemInformation_used = (PVOID)(x32based_args[3]); // PVOID  IN  OUT 
	ULONG SystemInformationLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[5]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	switch (SystemInformationClass_used) {
	case SystemBasicInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemBasicInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_BASIC_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemProcessInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemProcessInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_PROCESS_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemPagedPoolInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemPagedPoolInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_POOL_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemNonPagedPoolInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemNonPagedPoolInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_POOL_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemPageFileInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemPageFileInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_PAGEFILE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemFileCacheInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemFileCacheInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemRegistryQuotaInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemRegistryQuotaInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_REGISTRY_QUOTA_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemLegacyDriverInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemLegacyDriverInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_LEGACY_DRIVER_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemVerifierInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemVerifierInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_VERIFIER_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSessionProcessInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSessionProcessInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_SESSION_PROCESS_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemExtendedProcessInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemExtendedProcessInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_PROCESS_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemEmulationBasicInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemEmulationBasicInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_BASIC_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemExtendedHandleInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemExtendedHandleInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_HANDLE_INFORMATION_EX*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSessionPoolTagInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSessionPoolTagInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_SESSION_POOLTAG_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSessionMappedViewInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSessionMappedViewInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_SESSION_MAPPED_VIEW_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemRegisterFirmwareTableInformationHandler: {
		ret_value = _w32_NtQuerySystemInformation_SystemRegisterFirmwareTableInformationHandler(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FIRMWARE_TABLE_HANDLER*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemModuleInformationEx: {
		ret_value = _w32_NtQuerySystemInformation_SystemModuleInformationEx(ctx, syscall_idx, SystemInformationClass_used, (RTL_PROCESS_MODULE_INFORMATION_EX*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSuperfetchInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSuperfetchInformation(ctx, syscall_idx, SystemInformationClass_used, (SUPERFETCH_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemMemoryListInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemMemoryListInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_MEMORY_LIST_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemFileCacheInformationEx: {
		ret_value = _w32_NtQuerySystemInformation_SystemFileCacheInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemRefTraceInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemRefTraceInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_REF_TRACE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemProcessIdInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemProcessIdInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_PROCESS_ID_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemVerifierInformationEx: {
		ret_value = _w32_NtQuerySystemInformation_SystemVerifierInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_VERIFIER_INFORMATION_EX*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSystemPartitionInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSystemPartitionInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_SYSTEM_PARTITION_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSystemDiskInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemSystemDiskInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_SYSTEM_DISK_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemPagedPoolInformationEx: {
		ret_value = _w32_NtQuerySystemInformation_SystemPagedPoolInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemSystemPtesInformationEx: {
		ret_value = _w32_NtQuerySystemInformation_SystemSystemPtesInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemBasicPerformanceInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemBasicPerformanceInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_BASIC_PERFORMANCE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemPolicyInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemPolicyInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_POLICY_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemManufacturingInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemManufacturingInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_MANUFACTURING_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemActivityModerationUserSettings: {
		ret_value = _w32_NtQuerySystemInformation_SystemActivityModerationUserSettings(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemHypervisorSharedPageInformation: {
		ret_value = _w32_NtQuerySystemInformation_SystemHypervisorSharedPageInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION*)SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 4, SystemInformationClass_used, SystemInformation_used, SystemInformationLength_used, ReturnLength_used); // NtQuerySystemInformation
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySystemInformationEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	SYSTEM_INFORMATION_CLASS SystemInformationClass_used = (SYSTEM_INFORMATION_CLASS)(x32based_args[2]); // SYSTEM_INFORMATION_CLASS  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID SystemInformation_used = (PVOID)(x32based_args[5]); // PVOID  IN  OUT 
	ULONG SystemInformationLength_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	switch (SystemInformationClass_used) {
	case SystemLogicalProcessorInformation: {
		ret_value = _w32_NtQuerySystemInformationEx_SystemLogicalProcessorInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)InputBuffer_used, InputBufferLength_used, SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemLogicalProcessorAndGroupInformation: {
		ret_value = _w32_NtQuerySystemInformationEx_SystemLogicalProcessorAndGroupInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)InputBuffer_used, InputBufferLength_used, SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	case SystemFeatureConfigurationInformation: {
		ret_value = _w32_NtQuerySystemInformationEx_SystemFeatureConfigurationInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FEATURE_CONFIGURATION_INFORMATION*)InputBuffer_used, InputBufferLength_used, SystemInformation_used, SystemInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 6, SystemInformationClass_used, InputBuffer_used, InputBufferLength_used, SystemInformation_used, SystemInformationLength_used, ReturnLength_used); // NtQuerySystemInformationEx
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSystemInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	SYSTEM_INFORMATION_CLASS SystemInformationClass_used = (SYSTEM_INFORMATION_CLASS)(x32based_args[2]); // SYSTEM_INFORMATION_CLASS  IN 
	PVOID SystemInformation_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG SystemInformationLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	switch (SystemInformationClass_used) {
	case SystemPagedPoolInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemPagedPoolInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_POOL_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemRegistryQuotaInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemRegistryQuotaInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_REGISTRY_QUOTA_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemExtendServiceTableInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemExtendServiceTableInformation(ctx, syscall_idx, SystemInformationClass_used, (UNICODE_STRING*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemVerifierInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemVerifierInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_VERIFIER_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemThreadPriorityClientIdInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemThreadPriorityClientIdInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_THREAD_CID_PRIORITY_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemRefTraceInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemRefTraceInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_REF_TRACE_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemVerifierInformationEx: {
		ret_value = _w32_NtSetSystemInformation_SystemVerifierInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_VERIFIER_INFORMATION_EX*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemVerifierFaultsInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemVerifierFaultsInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_VERIFIER_FAULTS_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemRegistryAppendString: {
		ret_value = _w32_NtSetSystemInformation_SystemRegistryAppendString(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemPagedPoolInformationEx: {
		ret_value = _w32_NtSetSystemInformation_SystemPagedPoolInformationEx(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FILECACHE_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemPolicyInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemPolicyInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_POLICY_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemElamCertificateInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemElamCertificateInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_ELAM_CERTIFICATE_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemActivityModerationExeState: {
		ret_value = _w32_NtSetSystemInformation_SystemActivityModerationExeState(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_ACTIVITY_MODERATION_EXE_STATE*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	case SystemFeatureConfigurationInformation: {
		ret_value = _w32_NtSetSystemInformation_SystemFeatureConfigurationInformation(ctx, syscall_idx, SystemInformationClass_used, (SYSTEM_FEATURE_CONFIGURATION_INFORMATION*)SystemInformation_used, SystemInformationLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 3, SystemInformationClass_used, SystemInformation_used, SystemInformationLength_used); // NtSetSystemInformation
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSystemDebugControl(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	SYSDBG_COMMAND Command_used = (SYSDBG_COMMAND)(x32based_args[2]); // SYSDBG_COMMAND  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[3]); // PVOID  IN  OUT 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID OutputBuffer_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG OutputBufferLength_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, Command_used, InputBuffer_used, InputBufferLength_used, OutputBuffer_used, OutputBufferLength_used, ReturnLength_used); // NtSystemDebugControl

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRaiseHardError(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ErrorStatus_used = (NTSTATUS)(x32based_args[2]); // NTSTATUS  IN 
	ULONG NumberOfParameters_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	ULONG UnicodeStringParameterMask_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	uint32_t x32based_Parameters = (uint32_t)(x32based_args[5]); // PULONG_PTR  IN 
	ULONG ValidResponseOptions_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG Response_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t Parameters_holder[sizeof(long long unsigned int)];
	PULONG_PTR Parameters_used = (PULONG_PTR)&Parameters_holder;

	// Convert parameters from x32 to x64
	if (x32based_Parameters != NULL) {
		*((SIZE_T*)Parameters_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_Parameters));
	}
	else {
		Parameters_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ErrorStatus_used, NumberOfParameters_used, UnicodeStringParameterMask_used, Parameters_used, ValidResponseOptions_used, Response_used); // NtRaiseHardError

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDefaultLocale(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	BOOLEAN UserProfile_used = (BOOLEAN)(x32based_args[2]); // BOOLEAN  IN 
	PLCID DefaultLocaleId_used = (PLCID)(x32based_args[3]); // PLCID  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, UserProfile_used, DefaultLocaleId_used); // NtQueryDefaultLocale

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetDefaultLocale(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	BOOLEAN UserProfile_used = (BOOLEAN)(x32based_args[2]); // BOOLEAN  IN 
	LCID DefaultLocaleId_used = (LCID)(x32based_args[3]); // LCID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, UserProfile_used, DefaultLocaleId_used); // NtSetDefaultLocale

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInstallUILanguage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	LANGID* InstallUILanguageId_used = (LANGID*)(x32based_args[2]); // LANGID *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, InstallUILanguageId_used); // NtQueryInstallUILanguage

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushInstallUILanguage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	LANGID InstallUILanguage_used = (LANGID)(x32based_args[2]); // LANGID  IN 
	ULONG SetComittedFlag_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, InstallUILanguage_used, SetComittedFlag_used); // NtFlushInstallUILanguage

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDefaultUILanguage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	LANGID* DefaultUILanguageId_used = (LANGID*)(x32based_args[2]); // LANGID *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, DefaultUILanguageId_used); // NtQueryDefaultUILanguage

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetDefaultUILanguage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	LANGID DefaultUILanguageId_used = (LANGID)(x32based_args[2]); // LANGID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, DefaultUILanguageId_used); // NtSetDefaultUILanguage

	return ret_value;
}


NTSTATUS WINAPI _w32_NtIsUILanguageComitted(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtIsUILanguageComitted

	return ret_value;
}


NTSTATUS WINAPI _w32_NtInitializeNlsFiles(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[2]); // PVOID *  OUT 
	PLCID DefaultLocaleId_used = (PLCID)(x32based_args[3]); // PLCID  OUT 
	PLARGE_INTEGER DefaultCasingTableSize_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress == NULL) {
		BaseAddress_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 3, BaseAddress_used, DefaultLocaleId_used, DefaultCasingTableSize_used); // NtInitializeNlsFiles

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetNlsSectionPtr(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG SectionType_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	ULONG SectionData_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PVOID ContextData_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	uint32_t x32based_SectionPointer = (uint32_t)(x32based_args[5]); // PVOID *  OUT 
	PULONG SectionSize_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionPointer_holder[sizeof(PVOID)];
	PVOID* SectionPointer_used = (PVOID*)&SectionPointer_holder;

	// Convert parameters from x32 to x64
	if (x32based_SectionPointer == NULL) {
		SectionPointer_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, SectionType_used, SectionData_used, ContextData_used, SectionPointer_used, SectionSize_used); // NtGetNlsSectionPtr

	if (x32based_SectionPointer != NULL) {
		*((X32_SIZE_T*)x32based_SectionPointer) = (X32_SIZE_T)(*(SIZE_T*)SectionPointer_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMapCMFModule(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG What_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	ULONG Index_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PULONG CacheIndexOut_used = (PULONG)(x32based_args[4]); // PULONG  OUT 
	PULONG CacheFlagsOut_used = (PULONG)(x32based_args[5]); // PULONG  OUT 
	PULONG ViewSizeOut_used = (PULONG)(x32based_args[6]); // PULONG  OUT 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[7]); // PVOID *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress == NULL) {
		BaseAddress_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, What_used, Index_used, CacheIndexOut_used, CacheFlagsOut_used, ViewSizeOut_used, BaseAddress_used); // NtMapCMFModule

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetMUIRegistryInfo(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Flags_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	PULONG DataSize_used = (PULONG)(x32based_args[3]); // PULONG  IN  OUT 
	PVOID Data_used = (PVOID)(x32based_args[4]); // PVOID  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, Flags_used, DataSize_used, Data_used); // NtGetMUIRegistryInfo

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAddAtom(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PWSTR AtomName_used = (PWSTR)(x32based_args[2]); // PWSTR  IN 
	ULONG Length_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PRTL_ATOM Atom_used = (PRTL_ATOM)(x32based_args[4]); // PRTL_ATOM  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, AtomName_used, Length_used, Atom_used); // NtAddAtom

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAddAtomEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PWSTR AtomName_used = (PWSTR)(x32based_args[2]); // PWSTR  IN 
	ULONG Length_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PRTL_ATOM Atom_used = (PRTL_ATOM)(x32based_args[4]); // PRTL_ATOM  OUT 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, AtomName_used, Length_used, Atom_used, Flags_used); // NtAddAtomEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFindAtom(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PWSTR AtomName_used = (PWSTR)(x32based_args[2]); // PWSTR  IN 
	ULONG Length_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PRTL_ATOM Atom_used = (PRTL_ATOM)(x32based_args[4]); // PRTL_ATOM  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, AtomName_used, Length_used, Atom_used); // NtFindAtom

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteAtom(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	RTL_ATOM Atom_used = (RTL_ATOM)(x32based_args[2]); // RTL_ATOM  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Atom_used); // NtDeleteAtom

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationAtom(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	RTL_ATOM Atom_used = (RTL_ATOM)(x32based_args[2]); // RTL_ATOM  IN 
	ATOM_INFORMATION_CLASS AtomInformationClass_used = (ATOM_INFORMATION_CLASS)(x32based_args[3]); // ATOM_INFORMATION_CLASS  IN 
	PVOID AtomInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG AtomInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, Atom_used, AtomInformationClass_used, AtomInformation_used, AtomInformationLength_used, ReturnLength_used); // NtQueryInformationAtom

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryLicenseValue(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ValueName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PULONG Type_used = (PULONG)(x32based_args[3]); // PULONG  OUT 
	PVOID Data_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG DataSize_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ResultDataSize_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ValueName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ValueName_used = (PUNICODE_STRING)&ValueName_holder;

	// Convert parameters from x32 to x64
	if (x32based_ValueName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ValueName_used, x32based_ValueName);
	}
	else {
		ValueName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, ValueName_used, Type_used, Data_used, DataSize_used, ResultDataSize_used); // NtQueryLicenseValue

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetDefaultHardErrorPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DefaultHardErrorPort = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE DefaultHardErrorPort_used = Handle32ToHandle((const void* __ptr32)x32based_DefaultHardErrorPort);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, DefaultHardErrorPort_used); // NtSetDefaultHardErrorPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtShutdownSystem(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	SHUTDOWN_ACTION Action_used = (SHUTDOWN_ACTION)(x32based_args[2]); // SHUTDOWN_ACTION  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Action_used); // NtShutdownSystem

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDisplayString(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_String = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t String_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING String_used = (PUNICODE_STRING)&String_holder;

	// Convert parameters from x32 to x64
	if (x32based_String != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&String_used, x32based_String);
	}
	else {
		String_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, String_used); // NtDisplayString

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDrawText(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Text = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t Text_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Text_used = (PUNICODE_STRING)&Text_holder;

	// Convert parameters from x32 to x64
	if (x32based_Text != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Text_used, x32based_Text);
	}
	else {
		Text_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, Text_used); // NtDrawText

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAllocateVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	ULONG_PTR ZeroBits_used = (ULONG_PTR)(x32based_args[4]); // ULONG_PTR  IN 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[5]); // PSIZE_T  IN  OUT 
	ULONG AllocationType_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG Protect_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, BaseAddress_used, ZeroBits_used, RegionSize_used, AllocationType_used, Protect_used); // NtAllocateVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFreeVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG FreeType_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, BaseAddress_used, RegionSize_used, FreeType_used); // NtFreeVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReadVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint32_t x32based_NumberOfBytesRead = (uint32_t)(x32based_args[6]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NumberOfBytesRead_holder[sizeof(long long unsigned int)];
	PSIZE_T NumberOfBytesRead_used = (PSIZE_T)&NumberOfBytesRead_holder;

	// Convert parameters from x32 to x64
	if (x32based_NumberOfBytesRead == NULL) {
		NumberOfBytesRead_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, Buffer_used, BufferSize_used, NumberOfBytesRead_used); // NtReadVirtualMemory

	if (x32based_NumberOfBytesRead != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfBytesRead) = (X32_SIZE_T)(*(SIZE_T*)NumberOfBytesRead_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWriteVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint32_t x32based_NumberOfBytesWritten = (uint32_t)(x32based_args[6]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NumberOfBytesWritten_holder[sizeof(long long unsigned int)];
	PSIZE_T NumberOfBytesWritten_used = (PSIZE_T)&NumberOfBytesWritten_holder;

	// Convert parameters from x32 to x64
	if (x32based_NumberOfBytesWritten == NULL) {
		NumberOfBytesWritten_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, Buffer_used, BufferSize_used, NumberOfBytesWritten_used); // NtWriteVirtualMemory

	if (x32based_NumberOfBytesWritten != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfBytesWritten) = (X32_SIZE_T)(*(SIZE_T*)NumberOfBytesWritten_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtProtectVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG NewProtect_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG OldProtect_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, RegionSize_used, NewProtect_used, OldProtect_used); // NtProtectVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	MEMORY_INFORMATION_CLASS MemoryInformationClass_used = (MEMORY_INFORMATION_CLASS)(x32based_args[4]); // MEMORY_INFORMATION_CLASS  IN 
	PVOID MemoryInformation_used = (PVOID)(x32based_args[5]); // PVOID  IN  OUT 
	SIZE_T MemoryInformationLength_used = (SIZE_T)(x32based_args[6]); // SIZE_T  IN 
	uint32_t x32based_ReturnLength = (uint32_t)(x32based_args[7]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t ReturnLength_holder[sizeof(long long unsigned int)];
	PSIZE_T ReturnLength_used = (PSIZE_T)&ReturnLength_holder;

	// Convert parameters from x32 to x64
	if (x32based_ReturnLength == NULL) {
		ReturnLength_used = 0;
	}
	switch (MemoryInformationClass_used) {
	case MemoryBasicInformation: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryBasicInformation(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (MEMORY_BASIC_INFORMATION*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	case MemoryWorkingSetInformation: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryWorkingSetInformation(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (MEMORY_WORKING_SET_INFORMATION*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	case MemoryMappedFilenameInformation: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryMappedFilenameInformation(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (UNICODE_STRING*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	case MemoryRegionInformation: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryRegionInformation(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (MEMORY_REGION_INFORMATION*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	case MemoryWorkingSetExInformation: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryWorkingSetExInformation(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (MEMORY_WORKING_SET_EX_INFORMATION*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	case MemoryRegionInformationEx: {
		ret_value = _w32_NtQueryVirtualMemory_MemoryRegionInformationEx(ctx, syscall_idx, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, (MEMORY_REGION_INFORMATION*)MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, BaseAddress_used, MemoryInformationClass_used, MemoryInformation_used, MemoryInformationLength_used, ReturnLength_used); // NtQueryVirtualMemory
		break;
	}
	}

	if (x32based_ReturnLength != NULL) {
		*((X32_SIZE_T*)x32based_ReturnLength) = (X32_SIZE_T)(*(SIZE_T*)ReturnLength_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass_used = (VIRTUAL_MEMORY_INFORMATION_CLASS)(x32based_args[3]); // VIRTUAL_MEMORY_INFORMATION_CLASS  IN 
	ULONG_PTR NumberOfEntries_used = (ULONG_PTR)(x32based_args[4]); // ULONG_PTR  IN 
	uint32_t x32based_VirtualAddresses = (uint32_t)(x32based_args[5]); // PMEMORY_RANGE_ENTRY  IN 
	PVOID VmInformation_used = (PVOID)(x32based_args[6]); // PVOID  IN 
	ULONG VmInformationLength_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t VirtualAddresses_holder[sizeof(_MEMORY_RANGE_ENTRY)];
	PMEMORY_RANGE_ENTRY VirtualAddresses_used = (PMEMORY_RANGE_ENTRY)&VirtualAddresses_holder;

	// Convert parameters from x32 to x64
	if (x32based_VirtualAddresses != NULL) {
		convert__MEMORY_RANGE_ENTRY_32TO64(ctx, (_MEMORY_RANGE_ENTRY**)&VirtualAddresses_used, x32based_VirtualAddresses);
	}
	else {
		VirtualAddresses_used = 0;
	}

	switch (VmInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, VmInformationClass_used, NumberOfEntries_used, VirtualAddresses_used, VmInformation_used, VmInformationLength_used); // NtSetInformationVirtualMemory
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLockVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG MapType_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, BaseAddress_used, RegionSize_used, MapType_used); // NtLockVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnlockVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG MapType_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, BaseAddress_used, RegionSize_used, MapType_used); // NtUnlockVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	PLARGE_INTEGER MaximumSize_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 
	ULONG SectionPageProtection_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG AllocationAttributes_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[8]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionHandle_holder[sizeof(PVOID)];
	PHANDLE SectionHandle_used = (PHANDLE)&SectionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);

	// Convert parameters from x32 to x64
	if (x32based_SectionHandle == NULL) {
		SectionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 7, SectionHandle_used, DesiredAccess_used, ObjectAttributes_used, MaximumSize_used, SectionPageProtection_used, AllocationAttributes_used, FileHandle_used); // NtCreateSection

	if (SectionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SectionHandle_used, x32based_SectionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateSectionEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	PLARGE_INTEGER MaximumSize_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 
	ULONG SectionPageProtection_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG AllocationAttributes_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[8]); // HANDLE  IN 
	uint32_t x32based_ExtendedParameters = (uint32_t)(x32based_args[9]); // PMEM_EXTENDED_PARAMETER  IN  OUT 
	ULONG ExtendedParameterCount_used = (ULONG)(x32based_args[10]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionHandle_holder[sizeof(PVOID)];
	PHANDLE SectionHandle_used = (PHANDLE)&SectionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t ExtendedParameters_holder[sizeof(MEM_EXTENDED_PARAMETER)];
	PMEM_EXTENDED_PARAMETER ExtendedParameters_used = (PMEM_EXTENDED_PARAMETER)&ExtendedParameters_holder;

	// Convert parameters from x32 to x64
	if (x32based_SectionHandle == NULL) {
		SectionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_ExtendedParameters != NULL) {
		convert_MEM_EXTENDED_PARAMETER_32TO64(ctx, (MEM_EXTENDED_PARAMETER**)&ExtendedParameters_used, x32based_ExtendedParameters);
	}
	else {
		ExtendedParameters_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, SectionHandle_used, DesiredAccess_used, ObjectAttributes_used, MaximumSize_used, SectionPageProtection_used, AllocationAttributes_used, FileHandle_used, ExtendedParameters_used, ExtendedParameterCount_used); // NtCreateSectionEx

	if (SectionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SectionHandle_used, x32based_SectionHandle);
	}
	if (ExtendedParameters_used != NULL) {
		convert_MEM_EXTENDED_PARAMETER_64TO32(ctx, (MEM_EXTENDED_PARAMETER*)ExtendedParameters_used, x32based_ExtendedParameters);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SectionHandle_holder[sizeof(PVOID)];
	PHANDLE SectionHandle_used = (PHANDLE)&SectionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_SectionHandle == NULL) {
		SectionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SectionHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenSection

	if (SectionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SectionHandle_used, x32based_SectionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMapViewOfSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[4]); // PVOID *  IN  OUT 
	ULONG_PTR ZeroBits_used = (ULONG_PTR)(x32based_args[5]); // ULONG_PTR  IN 
	SIZE_T CommitSize_used = (SIZE_T)(x32based_args[6]); // SIZE_T  IN 
	PLARGE_INTEGER SectionOffset_used = (PLARGE_INTEGER)(x32based_args[7]); // PLARGE_INTEGER  IN  OUT 
	uint32_t x32based_ViewSize = (uint32_t)(x32based_args[8]); // PSIZE_T  IN  OUT 
	SECTION_INHERIT InheritDisposition_used = (SECTION_INHERIT)(x32based_args[9]); // SECTION_INHERIT  IN 
	ULONG AllocationType_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	ULONG Win32Protect_used = (ULONG)(x32based_args[11]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t ViewSize_holder[sizeof(long long unsigned int)];
	PSIZE_T ViewSize_used = (PSIZE_T)&ViewSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_ViewSize != NULL) {
		*((SIZE_T*)ViewSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_ViewSize));
	}
	else {
		ViewSize_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 10, SectionHandle_used, ProcessHandle_used, BaseAddress_used, ZeroBits_used, CommitSize_used, SectionOffset_used, ViewSize_used, InheritDisposition_used, AllocationType_used, Win32Protect_used); // NtMapViewOfSection

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_ViewSize != NULL) {
		*((X32_SIZE_T*)x32based_ViewSize) = (X32_SIZE_T)(*(SIZE_T*)ViewSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnmapViewOfSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProcessHandle_used, BaseAddress_used); // NtUnmapViewOfSection

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnmapViewOfSectionEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, BaseAddress_used, Flags_used); // NtUnmapViewOfSectionEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtExtendSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER NewSectionSize_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, SectionHandle_used, NewSectionSize_used); // NtExtendSection

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	SECTION_INFORMATION_CLASS SectionInformationClass_used = (SECTION_INFORMATION_CLASS)(x32based_args[3]); // SECTION_INFORMATION_CLASS  IN 
	PVOID SectionInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	SIZE_T SectionInformationLength_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint32_t x32based_ReturnLength = (uint32_t)(x32based_args[6]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	uint8_t ReturnLength_holder[sizeof(long long unsigned int)];
	PSIZE_T ReturnLength_used = (PSIZE_T)&ReturnLength_holder;

	// Convert parameters from x32 to x64
	if (x32based_ReturnLength == NULL) {
		ReturnLength_used = 0;
	}
	switch (SectionInformationClass_used) {
	case SectionBasicInformation: {
		ret_value = _w32_NtQuerySection_SectionBasicInformation(ctx, syscall_idx, SectionHandle_used, SectionInformationClass_used, (SECTION_BASIC_INFORMATION*)SectionInformation_used, SectionInformationLength_used, ReturnLength_used);
		break;
	}
	case SectionImageInformation: {
		ret_value = _w32_NtQuerySection_SectionImageInformation(ctx, syscall_idx, SectionHandle_used, SectionInformationClass_used, (SECTION_IMAGE_INFORMATION*)SectionInformation_used, SectionInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, SectionHandle_used, SectionInformationClass_used, SectionInformation_used, SectionInformationLength_used, ReturnLength_used); // NtQuerySection
		break;
	}
	}

	if (x32based_ReturnLength != NULL) {
		*((X32_SIZE_T*)x32based_ReturnLength) = (X32_SIZE_T)(*(SIZE_T*)ReturnLength_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAreMappedFilesTheSame(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID File1MappedAsAnImage_used = (PVOID)(x32based_args[2]); // PVOID  IN 
	PVOID File2MappedAsFile_used = (PVOID)(x32based_args[3]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, File1MappedAsAnImage_used, File2MappedAsFile_used); // NtAreMappedFilesTheSame

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreatePartition(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PartitionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG PreferredNode_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PartitionHandle_holder[sizeof(PVOID)];
	PHANDLE PartitionHandle_used = (PHANDLE)&PartitionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_PartitionHandle == NULL) {
		PartitionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PartitionHandle_used, DesiredAccess_used, ObjectAttributes_used, PreferredNode_used); // NtCreatePartition

	if (PartitionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PartitionHandle_used, x32based_PartitionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenPartition(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PartitionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PartitionHandle_holder[sizeof(PVOID)];
	PHANDLE PartitionHandle_used = (PHANDLE)&PartitionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_PartitionHandle == NULL) {
		PartitionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PartitionHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenPartition

	if (PartitionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PartitionHandle_used, x32based_PartitionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtManagePartition(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass_used = (MEMORY_PARTITION_INFORMATION_CLASS)(x32based_args[2]); // MEMORY_PARTITION_INFORMATION_CLASS  IN 
	PVOID PartitionInformation_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG PartitionInformationLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	switch (PartitionInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 3, PartitionInformationClass_used, PartitionInformation_used, PartitionInformationLength_used); // NtManagePartition
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMapUserPhysicalPages(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID VirtualAddress_used = (PVOID)(x32based_args[2]); // PVOID  IN 
	ULONG_PTR NumberOfPages_used = (ULONG_PTR)(x32based_args[3]); // ULONG_PTR  IN 
	uint32_t x32based_UserPfnArray = (uint32_t)(x32based_args[4]); // PULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t UserPfnArray_holder[sizeof(long long unsigned int)];
	PULONG_PTR UserPfnArray_used = (PULONG_PTR)&UserPfnArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_UserPfnArray != NULL) {
		*((SIZE_T*)UserPfnArray_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_UserPfnArray));
	}
	else {
		UserPfnArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, VirtualAddress_used, NumberOfPages_used, UserPfnArray_used); // NtMapUserPhysicalPages

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMapUserPhysicalPagesScatter(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_VirtualAddresses = (uint32_t)(x32based_args[2]); // PVOID *  IN 
	ULONG_PTR NumberOfPages_used = (ULONG_PTR)(x32based_args[3]); // ULONG_PTR  IN 
	uint32_t x32based_UserPfnArray = (uint32_t)(x32based_args[4]); // PULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t VirtualAddresses_holder[sizeof(PVOID)];
	PVOID* VirtualAddresses_used = (PVOID*)&VirtualAddresses_holder;
	uint8_t UserPfnArray_holder[sizeof(long long unsigned int)];
	PULONG_PTR UserPfnArray_used = (PULONG_PTR)&UserPfnArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_VirtualAddresses != NULL) {
		*((SIZE_T*)VirtualAddresses_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_VirtualAddresses));
	}
	else {
		VirtualAddresses_used = 0;
	}
	if (x32based_UserPfnArray != NULL) {
		*((SIZE_T*)UserPfnArray_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_UserPfnArray));
	}
	else {
		UserPfnArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, VirtualAddresses_used, NumberOfPages_used, UserPfnArray_used); // NtMapUserPhysicalPagesScatter

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAllocateUserPhysicalPages(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_NumberOfPages = (uint32_t)(x32based_args[3]); // PULONG_PTR  IN  OUT 
	uint32_t x32based_UserPfnArray = (uint32_t)(x32based_args[4]); // PULONG_PTR  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NumberOfPages_holder[sizeof(long long unsigned int)];
	PULONG_PTR NumberOfPages_used = (PULONG_PTR)&NumberOfPages_holder;
	uint8_t UserPfnArray_holder[sizeof(long long unsigned int)];
	PULONG_PTR UserPfnArray_used = (PULONG_PTR)&UserPfnArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_NumberOfPages != NULL) {
		*((SIZE_T*)NumberOfPages_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_NumberOfPages));
	}
	else {
		NumberOfPages_used = 0;
	}
	if (x32based_UserPfnArray == NULL) {
		UserPfnArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, NumberOfPages_used, UserPfnArray_used); // NtAllocateUserPhysicalPages

	if (x32based_NumberOfPages != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfPages) = (X32_SIZE_T)(*(SIZE_T*)NumberOfPages_used);
	}
	if (x32based_UserPfnArray != NULL) {
		*((X32_SIZE_T*)x32based_UserPfnArray) = (X32_SIZE_T)(*(SIZE_T*)UserPfnArray_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFreeUserPhysicalPages(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_NumberOfPages = (uint32_t)(x32based_args[3]); // PULONG_PTR  IN  OUT 
	uint32_t x32based_UserPfnArray = (uint32_t)(x32based_args[4]); // PULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NumberOfPages_holder[sizeof(long long unsigned int)];
	PULONG_PTR NumberOfPages_used = (PULONG_PTR)&NumberOfPages_holder;
	uint8_t UserPfnArray_holder[sizeof(long long unsigned int)];
	PULONG_PTR UserPfnArray_used = (PULONG_PTR)&UserPfnArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_NumberOfPages != NULL) {
		*((SIZE_T*)NumberOfPages_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_NumberOfPages));
	}
	else {
		NumberOfPages_used = 0;
	}
	if (x32based_UserPfnArray != NULL) {
		*((SIZE_T*)UserPfnArray_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_UserPfnArray));
	}
	else {
		UserPfnArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, NumberOfPages_used, UserPfnArray_used); // NtFreeUserPhysicalPages

	if (x32based_NumberOfPages != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfPages) = (X32_SIZE_T)(*(SIZE_T*)NumberOfPages_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetWriteWatch(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T RegionSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint32_t x32based_UserAddressArray = (uint32_t)(x32based_args[6]); // PVOID *  IN  OUT 
	uint32_t x32based_EntriesInUserAddressArray = (uint32_t)(x32based_args[7]); // PULONG_PTR  IN  OUT 
	PULONG Granularity_used = (PULONG)(x32based_args[8]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t UserAddressArray_holder[sizeof(PVOID)];
	PVOID* UserAddressArray_used = (PVOID*)&UserAddressArray_holder;
	uint8_t EntriesInUserAddressArray_holder[sizeof(long long unsigned int)];
	PULONG_PTR EntriesInUserAddressArray_used = (PULONG_PTR)&EntriesInUserAddressArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_UserAddressArray != NULL) {
		*((SIZE_T*)UserAddressArray_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_UserAddressArray));
	}
	else {
		UserAddressArray_used = 0;
	}
	if (x32based_EntriesInUserAddressArray != NULL) {
		*((SIZE_T*)EntriesInUserAddressArray_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_EntriesInUserAddressArray));
	}
	else {
		EntriesInUserAddressArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 7, ProcessHandle_used, Flags_used, BaseAddress_used, RegionSize_used, UserAddressArray_used, EntriesInUserAddressArray_used, Granularity_used); // NtGetWriteWatch

	if (x32based_UserAddressArray != NULL) {
		*((X32_SIZE_T*)x32based_UserAddressArray) = (X32_SIZE_T)(*(SIZE_T*)UserAddressArray_used);
	}
	if (x32based_EntriesInUserAddressArray != NULL) {
		*((X32_SIZE_T*)x32based_EntriesInUserAddressArray) = (X32_SIZE_T)(*(SIZE_T*)EntriesInUserAddressArray_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtResetWriteWatch(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	SIZE_T RegionSize_used = (SIZE_T)(x32based_args[4]); // SIZE_T  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, BaseAddress_used, RegionSize_used); // NtResetWriteWatch

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreatePagingFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PageFileName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PLARGE_INTEGER MinimumSize_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER MaximumSize_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 
	ULONG Priority_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PageFileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING PageFileName_used = (PUNICODE_STRING)&PageFileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_PageFileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&PageFileName_used, x32based_PageFileName);
	}
	else {
		PageFileName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PageFileName_used, MinimumSize_used, MaximumSize_used, Priority_used); // NtCreatePagingFile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushInstructionCache(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	SIZE_T Length_used = (SIZE_T)(x32based_args[4]); // SIZE_T  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, BaseAddress_used, Length_used); // NtFlushInstructionCache

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushWriteBuffer(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtFlushWriteBuffer

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateEnclave(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	ULONG_PTR ZeroBits_used = (ULONG_PTR)(x32based_args[4]); // ULONG_PTR  IN 
	SIZE_T Size_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	SIZE_T InitialCommitment_used = (SIZE_T)(x32based_args[6]); // SIZE_T  IN 
	ULONG EnclaveType_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PVOID EnclaveInformation_used = (PVOID)(x32based_args[8]); // PVOID  IN 
	ULONG EnclaveInformationLength_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	PULONG EnclaveError_used = (PULONG)(x32based_args[10]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, ProcessHandle_used, BaseAddress_used, ZeroBits_used, Size_used, InitialCommitment_used, EnclaveType_used, EnclaveInformation_used, EnclaveInformationLength_used, EnclaveError_used); // NtCreateEnclave

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLoadEnclaveData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	ULONG Protect_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PVOID PageInformation_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	ULONG PageInformationLength_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	uint32_t x32based_NumberOfBytesWritten = (uint32_t)(x32based_args[9]); // PSIZE_T  OUT 
	PULONG EnclaveError_used = (PULONG)(x32based_args[10]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NumberOfBytesWritten_holder[sizeof(long long unsigned int)];
	PSIZE_T NumberOfBytesWritten_used = (PSIZE_T)&NumberOfBytesWritten_holder;

	// Convert parameters from x32 to x64
	if (x32based_NumberOfBytesWritten == NULL) {
		NumberOfBytesWritten_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 9, ProcessHandle_used, BaseAddress_used, Buffer_used, BufferSize_used, Protect_used, PageInformation_used, PageInformationLength_used, NumberOfBytesWritten_used, EnclaveError_used); // NtLoadEnclaveData

	if (x32based_NumberOfBytesWritten != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfBytesWritten) = (X32_SIZE_T)(*(SIZE_T*)NumberOfBytesWritten_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtInitializeEnclave(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID EnclaveInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG EnclaveInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG EnclaveError_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, EnclaveInformation_used, EnclaveInformationLength_used, EnclaveError_used); // NtInitializeEnclave

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTerminateEnclave(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID BaseAddress_used = (PVOID)(x32based_args[2]); // PVOID  IN 
	BOOLEAN WaitForThread_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, BaseAddress_used, WaitForThread_used); // NtTerminateEnclave

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCallEnclave(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PENCLAVE_ROUTINE Routine_used = (PENCLAVE_ROUTINE)(x32based_args[2]); // PENCLAVE_ROUTINE  IN 
	PVOID Parameter_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	BOOLEAN WaitForThread_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	uint32_t x32based_ReturnValue = (uint32_t)(x32based_args[5]); // PVOID *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ReturnValue_holder[sizeof(PVOID)];
	PVOID* ReturnValue_used = (PVOID*)&ReturnValue_holder;

	// Convert parameters from x32 to x64
	if (x32based_ReturnValue == NULL) {
		ReturnValue_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, Routine_used, Parameter_used, WaitForThread_used, ReturnValue_used); // NtCallEnclave

	if (x32based_ReturnValue != NULL) {
		*((X32_SIZE_T*)x32based_ReturnValue) = (X32_SIZE_T)(*(SIZE_T*)ReturnValue_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	OBJECT_INFORMATION_CLASS ObjectInformationClass_used = (OBJECT_INFORMATION_CLASS)(x32based_args[3]); // OBJECT_INFORMATION_CLASS  IN 
	PVOID ObjectInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG ObjectInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	switch (ObjectInformationClass_used) {
	case ObjectNameInformation: {
		ret_value = _w32_NtQueryObject_ObjectNameInformation(ctx, syscall_idx, Handle_used, ObjectInformationClass_used, (OBJECT_NAME_INFORMATION*)ObjectInformation_used, ObjectInformationLength_used, ReturnLength_used);
		break;
	}
	case ObjectTypeInformation: {
		ret_value = _w32_NtQueryObject_ObjectTypeInformation(ctx, syscall_idx, Handle_used, ObjectInformationClass_used, (OBJECT_TYPE_INFORMATION*)ObjectInformation_used, ObjectInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, Handle_used, ObjectInformationClass_used, ObjectInformation_used, ObjectInformationLength_used, ReturnLength_used); // NtQueryObject
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	OBJECT_INFORMATION_CLASS ObjectInformationClass_used = (OBJECT_INFORMATION_CLASS)(x32based_args[3]); // OBJECT_INFORMATION_CLASS  IN 
	PVOID ObjectInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ObjectInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	switch (ObjectInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 4, Handle_used, ObjectInformationClass_used, ObjectInformation_used, ObjectInformationLength_used); // NtSetInformationObject
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDuplicateObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SourceProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_SourceHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_TargetProcessHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	uint32_t x32based_TargetHandle = (uint32_t)(x32based_args[5]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[6]); // ACCESS_MASK  IN 
	ULONG HandleAttributes_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG Options_used = (ULONG)(x32based_args[8]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SourceProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SourceProcessHandle);
	HANDLE SourceHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SourceHandle);
	HANDLE TargetProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TargetProcessHandle);
	uint8_t TargetHandle_holder[sizeof(PVOID)];
	PHANDLE TargetHandle_used = (PHANDLE)&TargetHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetHandle == NULL) {
		TargetHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 7, SourceProcessHandle_used, SourceHandle_used, TargetProcessHandle_used, TargetHandle_used, DesiredAccess_used, HandleAttributes_used, Options_used); // NtDuplicateObject

	if (TargetHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TargetHandle_used, x32based_TargetHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMakeTemporaryObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Handle_used); // NtMakeTemporaryObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtMakePermanentObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Handle_used); // NtMakePermanentObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSignalAndWaitForSingleObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SignalHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_WaitHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SignalHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SignalHandle);
	HANDLE WaitHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WaitHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, SignalHandle_used, WaitHandle_used, Alertable_used, Timeout_used); // NtSignalAndWaitForSingleObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForSingleObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, Handle_used, Alertable_used, Timeout_used); // NtWaitForSingleObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForMultipleObjects(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Count_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	uint32_t x32based_Handles = (uint32_t)(x32based_args[3]); // HANDLE *  IN 
	WAIT_TYPE WaitType_used = (WAIT_TYPE)(x32based_args[4]); // WAIT_TYPE  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t Handles_holder[sizeof(PVOID)];
	HANDLE* Handles_used = (HANDLE*)&Handles_holder;

	// Convert parameters from x32 to x64
	if (x32based_Handles != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&Handles_used, x32based_Handles);
	}
	else {
		Handles_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, Count_used, Handles_used, WaitType_used, Alertable_used, Timeout_used); // NtWaitForMultipleObjects

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForMultipleObjects32(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Count_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	LONG* Handles_used = (LONG*)(x32based_args[3]); // LONG *  IN 
	WAIT_TYPE WaitType_used = (WAIT_TYPE)(x32based_args[4]); // WAIT_TYPE  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, Count_used, Handles_used, WaitType_used, Alertable_used, Timeout_used); // NtWaitForMultipleObjects32

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSecurityObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	SECURITY_INFORMATION SecurityInformation_used = (SECURITY_INFORMATION)(x32based_args[3]); // SECURITY_INFORMATION  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[4]); // PSECURITY_DESCRIPTOR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, Handle_used, SecurityInformation_used, SecurityDescriptor_used); // NtSetSecurityObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySecurityObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	SECURITY_INFORMATION SecurityInformation_used = (SECURITY_INFORMATION)(x32based_args[3]); // SECURITY_INFORMATION  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[4]); // PSECURITY_DESCRIPTOR  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG LengthNeeded_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor == NULL) {
		SecurityDescriptor_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, Handle_used, SecurityInformation_used, SecurityDescriptor_used, Length_used, LengthNeeded_used); // NtQuerySecurityObject

	if (SecurityDescriptor_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SecurityDescriptor_used, x32based_SecurityDescriptor);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtClose(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Handle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Handle_used = Handle32ToHandle((const void* __ptr32)x32based_Handle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Handle_used); // NtClose

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCompareObjects(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FirstObjectHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_SecondObjectHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FirstObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FirstObjectHandle);
	HANDLE SecondObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SecondObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, FirstObjectHandle_used, SecondObjectHandle_used); // NtCompareObjects

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateDirectoryObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DirectoryHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DirectoryHandle_holder[sizeof(PVOID)];
	PHANDLE DirectoryHandle_used = (PHANDLE)&DirectoryHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_DirectoryHandle == NULL) {
		DirectoryHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, DirectoryHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtCreateDirectoryObject

	if (DirectoryHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)DirectoryHandle_used, x32based_DirectoryHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateDirectoryObjectEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DirectoryHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ShadowDirectoryHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DirectoryHandle_holder[sizeof(PVOID)];
	PHANDLE DirectoryHandle_used = (PHANDLE)&DirectoryHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE ShadowDirectoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ShadowDirectoryHandle);

	// Convert parameters from x32 to x64
	if (x32based_DirectoryHandle == NULL) {
		DirectoryHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, DirectoryHandle_used, DesiredAccess_used, ObjectAttributes_used, ShadowDirectoryHandle_used, Flags_used); // NtCreateDirectoryObjectEx

	if (DirectoryHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)DirectoryHandle_used, x32based_DirectoryHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenDirectoryObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DirectoryHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DirectoryHandle_holder[sizeof(PVOID)];
	PHANDLE DirectoryHandle_used = (PHANDLE)&DirectoryHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_DirectoryHandle == NULL) {
		DirectoryHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, DirectoryHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenDirectoryObject

	if (DirectoryHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)DirectoryHandle_used, x32based_DirectoryHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDirectoryObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DirectoryHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[3]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	BOOLEAN ReturnSingleEntry_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	BOOLEAN RestartScan_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 
	PULONG Context_used = (PULONG)(x32based_args[7]); // PULONG  IN  OUT 
	PULONG ReturnLength_used = (PULONG)(x32based_args[8]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE DirectoryHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DirectoryHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 7, DirectoryHandle_used, Buffer_used, Length_used, ReturnSingleEntry_used, RestartScan_used, Context_used, ReturnLength_used); // NtQueryDirectoryObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreatePrivateNamespace(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_NamespaceHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	PVOID BoundaryDescriptor_used = (PVOID)(x32based_args[5]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t NamespaceHandle_holder[sizeof(PVOID)];
	PHANDLE NamespaceHandle_used = (PHANDLE)&NamespaceHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_NamespaceHandle == NULL) {
		NamespaceHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, NamespaceHandle_used, DesiredAccess_used, ObjectAttributes_used, BoundaryDescriptor_used); // NtCreatePrivateNamespace

	if (NamespaceHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NamespaceHandle_used, x32based_NamespaceHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenPrivateNamespace(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_NamespaceHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	PVOID BoundaryDescriptor_used = (PVOID)(x32based_args[5]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t NamespaceHandle_holder[sizeof(PVOID)];
	PHANDLE NamespaceHandle_used = (PHANDLE)&NamespaceHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_NamespaceHandle == NULL) {
		NamespaceHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, NamespaceHandle_used, DesiredAccess_used, ObjectAttributes_used, BoundaryDescriptor_used); // NtOpenPrivateNamespace

	if (NamespaceHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NamespaceHandle_used, x32based_NamespaceHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeletePrivateNamespace(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_NamespaceHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE NamespaceHandle_used = Handle32ToHandle((const void* __ptr32)x32based_NamespaceHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, NamespaceHandle_used); // NtDeletePrivateNamespace

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateSymbolicLinkObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_LinkHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_LinkTarget = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t LinkHandle_holder[sizeof(PVOID)];
	PHANDLE LinkHandle_used = (PHANDLE)&LinkHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t LinkTarget_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING LinkTarget_used = (PUNICODE_STRING)&LinkTarget_holder;

	// Convert parameters from x32 to x64
	if (x32based_LinkHandle == NULL) {
		LinkHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_LinkTarget != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&LinkTarget_used, x32based_LinkTarget);
	}
	else {
		LinkTarget_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, LinkHandle_used, DesiredAccess_used, ObjectAttributes_used, LinkTarget_used); // NtCreateSymbolicLinkObject

	if (LinkHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)LinkHandle_used, x32based_LinkHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenSymbolicLinkObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_LinkHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t LinkHandle_holder[sizeof(PVOID)];
	PHANDLE LinkHandle_used = (PHANDLE)&LinkHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_LinkHandle == NULL) {
		LinkHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, LinkHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenSymbolicLinkObject

	if (LinkHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)LinkHandle_used, x32based_LinkHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySymbolicLinkObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_LinkHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_LinkTarget = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN  OUT 
	PULONG ReturnedLength_used = (PULONG)(x32based_args[4]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE LinkHandle_used = Handle32ToHandle((const void* __ptr32)x32based_LinkHandle);
	uint8_t LinkTarget_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING LinkTarget_used = (PUNICODE_STRING)&LinkTarget_holder;

	// Convert parameters from x32 to x64
	if (x32based_LinkTarget != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&LinkTarget_used, x32based_LinkTarget);
	}
	else {
		LinkTarget_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, LinkHandle_used, LinkTarget_used, ReturnedLength_used); // NtQuerySymbolicLinkObject

	if (LinkTarget_used != NULL) {
		convert__UNICODE_STRING_64TO32(ctx, (_UNICODE_STRING*)LinkTarget_used, x32based_LinkTarget);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ParentProcess = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	BOOLEAN InheritObjectTable_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[7]); // HANDLE  IN 
	uint32_t x32based_DebugPort = (uint32_t)(x32based_args[8]); // HANDLE  IN 
	uint32_t x32based_ExceptionPort = (uint32_t)(x32based_args[9]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessHandle_holder[sizeof(PVOID)];
	PHANDLE ProcessHandle_used = (PHANDLE)&ProcessHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE ParentProcess_used = Handle32ToHandle((const void* __ptr32)x32based_ParentProcess);
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	HANDLE DebugPort_used = Handle32ToHandle((const void* __ptr32)x32based_DebugPort);
	HANDLE ExceptionPort_used = Handle32ToHandle((const void* __ptr32)x32based_ExceptionPort);

	// Convert parameters from x32 to x64
	if (x32based_ProcessHandle == NULL) {
		ProcessHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, ProcessHandle_used, DesiredAccess_used, ObjectAttributes_used, ParentProcess_used, InheritObjectTable_used, SectionHandle_used, DebugPort_used, ExceptionPort_used); // NtCreateProcess

	if (ProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProcessHandle_used, x32based_ProcessHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateProcessEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ParentProcess = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[7]); // HANDLE  IN 
	uint32_t x32based_DebugPort = (uint32_t)(x32based_args[8]); // HANDLE  IN 
	uint32_t x32based_ExceptionPort = (uint32_t)(x32based_args[9]); // HANDLE  IN 
	ULONG JobMemberLevel_used = (ULONG)(x32based_args[10]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessHandle_holder[sizeof(PVOID)];
	PHANDLE ProcessHandle_used = (PHANDLE)&ProcessHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE ParentProcess_used = Handle32ToHandle((const void* __ptr32)x32based_ParentProcess);
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	HANDLE DebugPort_used = Handle32ToHandle((const void* __ptr32)x32based_DebugPort);
	HANDLE ExceptionPort_used = Handle32ToHandle((const void* __ptr32)x32based_ExceptionPort);

	// Convert parameters from x32 to x64
	if (x32based_ProcessHandle == NULL) {
		ProcessHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, ProcessHandle_used, DesiredAccess_used, ObjectAttributes_used, ParentProcess_used, Flags_used, SectionHandle_used, DebugPort_used, ExceptionPort_used, JobMemberLevel_used); // NtCreateProcessEx

	if (ProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProcessHandle_used, x32based_ProcessHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ClientId = (uint32_t)(x32based_args[5]); // PCLIENT_ID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessHandle_holder[sizeof(PVOID)];
	PHANDLE ProcessHandle_used = (PHANDLE)&ProcessHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t ClientId_holder[sizeof(_CLIENT_ID)];
	PCLIENT_ID ClientId_used = (PCLIENT_ID)&ClientId_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessHandle == NULL) {
		ProcessHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_ClientId != NULL) {
		convert__CLIENT_ID_32TO64(ctx, (_CLIENT_ID**)&ClientId_used, x32based_ClientId);
	}
	else {
		ClientId_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, DesiredAccess_used, ObjectAttributes_used, ClientId_used); // NtOpenProcess

	if (ProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProcessHandle_used, x32based_ProcessHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTerminateProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	NTSTATUS ExitStatus_used = (NTSTATUS)(x32based_args[3]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProcessHandle_used, ExitStatus_used); // NtTerminateProcess

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSuspendProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ProcessHandle_used); // NtSuspendProcess

	return ret_value;
}


NTSTATUS WINAPI _w32_NtResumeProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ProcessHandle_used); // NtResumeProcess

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PROCESSINFOCLASS ProcessInformationClass_used = (PROCESSINFOCLASS)(x32based_args[3]); // PROCESSINFOCLASS  IN 
	PVOID ProcessInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG ProcessInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	switch (ProcessInformationClass_used) {
	case ProcessBasicInformation: {
		ret_value = _w32_NtQueryInformationProcess_ProcessBasicInformation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_BASIC_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessQuotaLimits: {
		ret_value = _w32_NtQueryInformationProcess_ProcessQuotaLimits(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (QUOTA_LIMITS*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessVmCounters: {
		ret_value = _w32_NtQueryInformationProcess_ProcessVmCounters(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (VM_COUNTERS*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessPooledUsageAndLimits: {
		ret_value = _w32_NtQueryInformationProcess_ProcessPooledUsageAndLimits(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (POOLED_USAGE_AND_LIMITS*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessWorkingSetWatch: {
		ret_value = _w32_NtQueryInformationProcess_ProcessWorkingSetWatch(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_WS_WATCH_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessDeviceMap: {
		ret_value = _w32_NtQueryInformationProcess_ProcessDeviceMap(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_DEVICEMAP_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessImageFileName: {
		ret_value = _w32_NtQueryInformationProcess_ProcessImageFileName(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (UNICODE_STRING*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessHandleTracing: {
		ret_value = _w32_NtQueryInformationProcess_ProcessHandleTracing(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_HANDLE_TRACING_QUERY*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessImageInformation: {
		ret_value = _w32_NtQueryInformationProcess_ProcessImageInformation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (SECTION_IMAGE_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessWorkingSetWatchEx: {
		ret_value = _w32_NtQueryInformationProcess_ProcessWorkingSetWatchEx(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_WS_WATCH_INFORMATION_EX*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessImageFileNameWin32: {
		ret_value = _w32_NtQueryInformationProcess_ProcessImageFileNameWin32(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (UNICODE_STRING*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessHandleInformation: {
		ret_value = _w32_NtQueryInformationProcess_ProcessHandleInformation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	case ProcessCommandLineInformation: {
		ret_value = _w32_NtQueryInformationProcess_ProcessCommandLineInformation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (UNICODE_STRING*)ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, ProcessInformationClass_used, ProcessInformation_used, ProcessInformationLength_used, ReturnLength_used); // NtQueryInformationProcess
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetNextProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	ULONG HandleAttributes_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_NewProcessHandle = (uint32_t)(x32based_args[6]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t NewProcessHandle_holder[sizeof(PVOID)];
	PHANDLE NewProcessHandle_used = (PHANDLE)&NewProcessHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewProcessHandle == NULL) {
		NewProcessHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, DesiredAccess_used, HandleAttributes_used, Flags_used, NewProcessHandle_used); // NtGetNextProcess

	if (NewProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NewProcessHandle_used, x32based_NewProcessHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetNextThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[4]); // ACCESS_MASK  IN 
	ULONG HandleAttributes_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ULONG Flags_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	uint32_t x32based_NewThreadHandle = (uint32_t)(x32based_args[7]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);
	uint8_t NewThreadHandle_holder[sizeof(PVOID)];
	PHANDLE NewThreadHandle_used = (PHANDLE)&NewThreadHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewThreadHandle == NULL) {
		NewThreadHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, ThreadHandle_used, DesiredAccess_used, HandleAttributes_used, Flags_used, NewThreadHandle_used); // NtGetNextThread

	if (NewThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NewThreadHandle_used, x32based_NewThreadHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PROCESSINFOCLASS ProcessInformationClass_used = (PROCESSINFOCLASS)(x32based_args[3]); // PROCESSINFOCLASS  IN 
	PVOID ProcessInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ProcessInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	switch (ProcessInformationClass_used) {
	case ProcessQuotaLimits: {
		ret_value = _w32_NtSetInformationProcess_ProcessQuotaLimits(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (QUOTA_LIMITS*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessExceptionPort: {
		ret_value = _w32_NtSetInformationProcess_ProcessExceptionPort(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_EXCEPTION_PORT*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessAccessToken: {
		ret_value = _w32_NtSetInformationProcess_ProcessAccessToken(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_ACCESS_TOKEN*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessAffinityMask: {
		ret_value = _w32_NtSetInformationProcess_ProcessAffinityMask(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (KAFFINITY*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessInstrumentationCallback: {
		ret_value = _w32_NtSetInformationProcess_ProcessInstrumentationCallback(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessThreadStackAllocation: {
		ret_value = _w32_NtSetInformationProcess_ProcessThreadStackAllocation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_STACK_ALLOCATION_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessMemoryExhaustion: {
		ret_value = _w32_NtSetInformationProcess_ProcessMemoryExhaustion(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_MEMORY_EXHAUSTION_INFO*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	case ProcessCombineSecurityDomainsInformation: {
		ret_value = _w32_NtSetInformationProcess_ProcessCombineSecurityDomainsInformation(ctx, syscall_idx, ProcessHandle_used, ProcessInformationClass_used, (PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION*)ProcessInformation_used, ProcessInformationLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, ProcessInformationClass_used, ProcessInformation_used, ProcessInformationLength_used); // NtSetInformationProcess
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryPortInformationProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtQueryPortInformationProcess

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	uint32_t x32based_ClientId = (uint32_t)(x32based_args[6]); // PCLIENT_ID  OUT 
	PCONTEXT ThreadContext_used = (PCONTEXT)(x32based_args[7]); // PCONTEXT  IN 
	uint32_t x32based_InitialTeb = (uint32_t)(x32based_args[8]); // PINITIAL_TEB  IN 
	BOOLEAN CreateSuspended_used = (BOOLEAN)(x32based_args[9]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadHandle_holder[sizeof(PVOID)];
	PHANDLE ThreadHandle_used = (PHANDLE)&ThreadHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t ClientId_holder[sizeof(_CLIENT_ID)];
	PCLIENT_ID ClientId_used = (PCLIENT_ID)&ClientId_holder;
	uint8_t InitialTeb_holder[sizeof(_INITIAL_TEB)];
	PINITIAL_TEB InitialTeb_used = (PINITIAL_TEB)&InitialTeb_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadHandle == NULL) {
		ThreadHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_ClientId == NULL) {
		ClientId_used = 0;
	}
	if (x32based_InitialTeb != NULL) {
		convert__INITIAL_TEB_32TO64(ctx, (_INITIAL_TEB**)&InitialTeb_used, x32based_InitialTeb);
	}
	else {
		InitialTeb_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, ThreadHandle_used, DesiredAccess_used, ObjectAttributes_used, ProcessHandle_used, ClientId_used, ThreadContext_used, InitialTeb_used, CreateSuspended_used); // NtCreateThread

	if (ThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ThreadHandle_used, x32based_ThreadHandle);
	}
	if (ClientId_used != NULL) {
		convert__CLIENT_ID_64TO32(ctx, (_CLIENT_ID*)ClientId_used, x32based_ClientId);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ClientId = (uint32_t)(x32based_args[5]); // PCLIENT_ID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadHandle_holder[sizeof(PVOID)];
	PHANDLE ThreadHandle_used = (PHANDLE)&ThreadHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t ClientId_holder[sizeof(_CLIENT_ID)];
	PCLIENT_ID ClientId_used = (PCLIENT_ID)&ClientId_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadHandle == NULL) {
		ThreadHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_ClientId != NULL) {
		convert__CLIENT_ID_32TO64(ctx, (_CLIENT_ID**)&ClientId_used, x32based_ClientId);
	}
	else {
		ClientId_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ThreadHandle_used, DesiredAccess_used, ObjectAttributes_used, ClientId_used); // NtOpenThread

	if (ThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ThreadHandle_used, x32based_ThreadHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTerminateThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	NTSTATUS ExitStatus_used = (NTSTATUS)(x32based_args[3]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, ExitStatus_used); // NtTerminateThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSuspendThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PULONG PreviousSuspendCount_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, PreviousSuspendCount_used); // NtSuspendThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtResumeThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PULONG PreviousSuspendCount_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, PreviousSuspendCount_used); // NtResumeThread

	return ret_value;
}


ULONG WINAPI _w32_NtGetCurrentProcessorNumber(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	// Declare space used in parameters
	// Convert parameters from x32 to x64
	return (ULONG)__syscall64(syscall_idx, 0); // NtGetCurrentProcessorNumber
}


NTSTATUS WINAPI _w32_NtGetContextThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PCONTEXT ThreadContext_used = (PCONTEXT)(x32based_args[3]); // PCONTEXT  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, ThreadContext_used); // NtGetContextThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetContextThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PCONTEXT ThreadContext_used = (PCONTEXT)(x32based_args[3]); // PCONTEXT  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, ThreadContext_used); // NtSetContextThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	THREADINFOCLASS ThreadInformationClass_used = (THREADINFOCLASS)(x32based_args[3]); // THREADINFOCLASS  IN 
	PVOID ThreadInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG ThreadInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	switch (ThreadInformationClass_used) {
	case ThreadBasicInformation: {
		ret_value = _w32_NtQueryInformationThread_ThreadBasicInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_BASIC_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}
	case ThreadLastSystemCall: {
		ret_value = _w32_NtQueryInformationThread_ThreadLastSystemCall(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_LAST_SYSCALL_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}
	case ThreadTebInformation: {
		ret_value = _w32_NtQueryInformationThread_ThreadTebInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_TEB_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}
	case ThreadGroupInformation: {
		ret_value = _w32_NtQueryInformationThread_ThreadGroupInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (GROUP_AFFINITY*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}
	case ThreadCounterProfiling: {
		ret_value = _w32_NtQueryInformationThread_ThreadCounterProfiling(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_PROFILING_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}

	case ThreadNameInformation: {
		ret_value = _w32_NtQueryInformationThread_ThreadNameInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_NAME_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, ThreadHandle_used, ThreadInformationClass_used, ThreadInformation_used, ThreadInformationLength_used, ReturnLength_used); // NtQueryInformationThread
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	THREADINFOCLASS ThreadInformationClass_used = (THREADINFOCLASS)(x32based_args[3]); // THREADINFOCLASS  IN 
	PVOID ThreadInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ThreadInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	switch (ThreadInformationClass_used) {
	case ThreadAffinityMask: {
		ret_value = _w32_NtSetInformationThread_ThreadAffinityMask(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (KAFFINITY*)ThreadInformation_used, ThreadInformationLength_used);
		break;
	}
	case ThreadGroupInformation: {
		ret_value = _w32_NtSetInformationThread_ThreadGroupInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (GROUP_AFFINITY*)ThreadInformation_used, ThreadInformationLength_used);
		break;
	}
	case ThreadCounterProfiling: {
		ret_value = _w32_NtSetInformationThread_ThreadCounterProfiling(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_PROFILING_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used);
		break;
	}

	case ThreadNameInformation: {
		ret_value = _w32_NtSetInformationThread_ThreadNameInformation(ctx, syscall_idx, ThreadHandle_used, ThreadInformationClass_used, (THREAD_NAME_INFORMATION*)ThreadInformation_used, ThreadInformationLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 4, ThreadHandle_used, ThreadInformationClass_used, ThreadInformation_used, ThreadInformationLength_used); // NtSetInformationThread
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlertThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ThreadHandle_used); // NtAlertThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlertResumeThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PULONG PreviousSuspendCount_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ThreadHandle_used, PreviousSuspendCount_used); // NtAlertResumeThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTestAlert(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtTestAlert

	return ret_value;
}


NTSTATUS WINAPI _w32_NtImpersonateThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ServerThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ClientThreadHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PSECURITY_QUALITY_OF_SERVICE SecurityQos_used = (PSECURITY_QUALITY_OF_SERVICE)(x32based_args[4]); // PSECURITY_QUALITY_OF_SERVICE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ServerThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ServerThreadHandle);
	HANDLE ClientThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ClientThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ServerThreadHandle_used, ClientThreadHandle_used, SecurityQos_used); // NtImpersonateThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRegisterThreadTerminatePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, PortHandle_used); // NtRegisterThreadTerminatePort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetLdtEntries(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Selector0_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	ULONG Entry0Low_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	ULONG Entry0Hi_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG Selector1_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ULONG Entry1Low_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG Entry1Hi_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, Selector0_used, Entry0Low_used, Entry0Hi_used, Selector1_used, Entry1Low_used, Entry1Hi_used); // NtSetLdtEntries

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueueApcThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PPS_APC_ROUTINE ApcRoutine_used = (PPS_APC_ROUTINE)(x32based_args[3]); // PPS_APC_ROUTINE  IN 
	PVOID ApcArgument1_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	PVOID ApcArgument2_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	PVOID ApcArgument3_used = (PVOID)(x32based_args[6]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle_used, ApcRoutine_used, ApcArgument1_used, ApcArgument2_used, ApcArgument3_used); // NtQueueApcThread

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueueApcThreadEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_UserApcReserveHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PPS_APC_ROUTINE ApcRoutine_used = (PPS_APC_ROUTINE)(x32based_args[4]); // PPS_APC_ROUTINE  IN 
	PVOID ApcArgument1_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	PVOID ApcArgument2_used = (PVOID)(x32based_args[6]); // PVOID  IN 
	PVOID ApcArgument3_used = (PVOID)(x32based_args[7]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);
	HANDLE UserApcReserveHandle_used = Handle32ToHandle((const void* __ptr32)x32based_UserApcReserveHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, ThreadHandle_used, UserApcReserveHandle_used, ApcRoutine_used, ApcArgument1_used, ApcArgument2_used, ApcArgument3_used); // NtQueueApcThreadEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlertThreadByThreadId(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadId = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadId_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadId);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ThreadId_used); // NtAlertThreadByThreadId

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForAlertByThreadId(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PVOID Address_used = (PVOID)(x32based_args[2]); // PVOID  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Address_used, Timeout_used); // NtWaitForAlertByThreadId

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateUserProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[3]); // PHANDLE  OUT 
	ACCESS_MASK ProcessDesiredAccess_used = (ACCESS_MASK)(x32based_args[4]); // ACCESS_MASK  IN 
	ACCESS_MASK ThreadDesiredAccess_used = (ACCESS_MASK)(x32based_args[5]); // ACCESS_MASK  IN 
	uint32_t x32based_ProcessObjectAttributes = (uint32_t)(x32based_args[6]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ThreadObjectAttributes = (uint32_t)(x32based_args[7]); // POBJECT_ATTRIBUTES  IN 
	ULONG ProcessFlags_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG ThreadFlags_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	PVOID ProcessParameters_used = (PVOID)(x32based_args[10]); // PVOID  IN 
	uint32_t x32based_CreateInfo = (uint32_t)(x32based_args[11]); // PPS_CREATE_INFO  IN  OUT 
	uint32_t x32based_AttributeList = (uint32_t)(x32based_args[12]); // PPS_ATTRIBUTE_LIST  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessHandle_holder[sizeof(PVOID)];
	PHANDLE ProcessHandle_used = (PHANDLE)&ProcessHandle_holder;
	uint8_t ThreadHandle_holder[sizeof(PVOID)];
	PHANDLE ThreadHandle_used = (PHANDLE)&ThreadHandle_holder;
	uint8_t ProcessObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ProcessObjectAttributes_used = (POBJECT_ATTRIBUTES)&ProcessObjectAttributes_holder;
	uint8_t ThreadObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ThreadObjectAttributes_used = (POBJECT_ATTRIBUTES)&ThreadObjectAttributes_holder;
	uint8_t CreateInfo_holder[sizeof(_PS_CREATE_INFO)];
	PPS_CREATE_INFO CreateInfo_used = (PPS_CREATE_INFO)&CreateInfo_holder;
	uint8_t AttributeList_holder[sizeof(_PS_ATTRIBUTE_LIST)];
	PPS_ATTRIBUTE_LIST AttributeList_used = (PPS_ATTRIBUTE_LIST)&AttributeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessHandle == NULL) {
		ProcessHandle_used = 0;
	}
	if (x32based_ThreadHandle == NULL) {
		ThreadHandle_used = 0;
	}
	if (x32based_ProcessObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ProcessObjectAttributes_used, x32based_ProcessObjectAttributes);
	}
	else {
		ProcessObjectAttributes_used = 0;
	}
	if (x32based_ThreadObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ThreadObjectAttributes_used, x32based_ThreadObjectAttributes);
	}
	else {
		ThreadObjectAttributes_used = 0;
	}
	if (x32based_CreateInfo != NULL) {
		convert__PS_CREATE_INFO_32TO64(ctx, (_PS_CREATE_INFO**)&CreateInfo_used, x32based_CreateInfo);
	}
	else {
		CreateInfo_used = 0;
	}
	if (x32based_AttributeList != NULL) {
		convert__PS_ATTRIBUTE_LIST_32TO64(ctx, (_PS_ATTRIBUTE_LIST**)&AttributeList_used, x32based_AttributeList);
	}
	else {
		AttributeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, ProcessHandle_used, ThreadHandle_used, ProcessDesiredAccess_used, ThreadDesiredAccess_used, ProcessObjectAttributes_used, ThreadObjectAttributes_used, ProcessFlags_used, ThreadFlags_used, ProcessParameters_used, CreateInfo_used, AttributeList_used); // NtCreateUserProcess

	if (ProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProcessHandle_used, x32based_ProcessHandle);
	}
	if (ThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ThreadHandle_used, x32based_ThreadHandle);
	}
	if (CreateInfo_used != NULL) {
		convert__PS_CREATE_INFO_64TO32(ctx, (_PS_CREATE_INFO*)CreateInfo_used, x32based_CreateInfo);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateThreadEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	PVOID StartRoutine_used = (PVOID)(x32based_args[6]); // PVOID  IN 
	PVOID Argument_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	ULONG CreateFlags_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	SIZE_T ZeroBits_used = (SIZE_T)(x32based_args[9]); // SIZE_T  IN 
	SIZE_T StackSize_used = (SIZE_T)(x32based_args[10]); // SIZE_T  IN 
	SIZE_T MaximumStackSize_used = (SIZE_T)(x32based_args[11]); // SIZE_T  IN 
	uint32_t x32based_AttributeList = (uint32_t)(x32based_args[12]); // PPS_ATTRIBUTE_LIST  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadHandle_holder[sizeof(PVOID)];
	PHANDLE ThreadHandle_used = (PHANDLE)&ThreadHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t AttributeList_holder[sizeof(_PS_ATTRIBUTE_LIST)];
	PPS_ATTRIBUTE_LIST AttributeList_used = (PPS_ATTRIBUTE_LIST)&AttributeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadHandle == NULL) {
		ThreadHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_AttributeList != NULL) {
		convert__PS_ATTRIBUTE_LIST_32TO64(ctx, (_PS_ATTRIBUTE_LIST**)&AttributeList_used, x32based_AttributeList);
	}
	else {
		AttributeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, ThreadHandle_used, DesiredAccess_used, ObjectAttributes_used, ProcessHandle_used, StartRoutine_used, Argument_used, CreateFlags_used, ZeroBits_used, StackSize_used, MaximumStackSize_used, AttributeList_used); // NtCreateThreadEx

	if (ThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ThreadHandle_used, x32based_ThreadHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t JobHandle_holder[sizeof(PVOID)];
	PHANDLE JobHandle_used = (PHANDLE)&JobHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_JobHandle == NULL) {
		JobHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, JobHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtCreateJobObject

	if (JobHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)JobHandle_used, x32based_JobHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t JobHandle_holder[sizeof(PVOID)];
	PHANDLE JobHandle_used = (PHANDLE)&JobHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_JobHandle == NULL) {
		JobHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, JobHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenJobObject

	if (JobHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)JobHandle_used, x32based_JobHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAssignProcessToJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE JobHandle_used = Handle32ToHandle((const void* __ptr32)x32based_JobHandle);
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, JobHandle_used, ProcessHandle_used); // NtAssignProcessToJobObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTerminateJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	NTSTATUS ExitStatus_used = (NTSTATUS)(x32based_args[3]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE JobHandle_used = Handle32ToHandle((const void* __ptr32)x32based_JobHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, JobHandle_used, ExitStatus_used); // NtTerminateJobObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtIsProcessInJob(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	HANDLE JobHandle_used = Handle32ToHandle((const void* __ptr32)x32based_JobHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProcessHandle_used, JobHandle_used); // NtIsProcessInJob

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	JOBOBJECTINFOCLASS JobObjectInformationClass_used = (JOBOBJECTINFOCLASS)(x32based_args[3]); // JOBOBJECTINFOCLASS  IN 
	PVOID JobObjectInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG JobObjectInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE JobHandle_used = Handle32ToHandle((const void* __ptr32)x32based_JobHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, JobHandle_used, JobObjectInformationClass_used, JobObjectInformation_used, JobObjectInformationLength_used, ReturnLength_used); // NtQueryInformationJobObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationJobObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_JobHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	JOBOBJECTINFOCLASS JobObjectInformationClass_used = (JOBOBJECTINFOCLASS)(x32based_args[3]); // JOBOBJECTINFOCLASS  IN 
	PVOID JobObjectInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG JobObjectInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE JobHandle_used = Handle32ToHandle((const void* __ptr32)x32based_JobHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, JobHandle_used, JobObjectInformationClass_used, JobObjectInformation_used, JobObjectInformationLength_used); // NtSetInformationJobObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateJobSet(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG NumJob_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	uint32_t x32based_UserJobSet = (uint32_t)(x32based_args[3]); // PJOB_SET_ARRAY  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t UserJobSet_holder[sizeof(_JOB_SET_ARRAY)];
	PJOB_SET_ARRAY UserJobSet_used = (PJOB_SET_ARRAY)&UserJobSet_holder;

	// Convert parameters from x32 to x64
	if (x32based_UserJobSet != NULL) {
		convert__JOB_SET_ARRAY_32TO64(ctx, (_JOB_SET_ARRAY**)&UserJobSet_used, x32based_UserJobSet);
	}
	else {
		UserJobSet_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, NumJob_used, UserJobSet_used, Flags_used); // NtCreateJobSet

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRevertContainerImpersonation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtRevertContainerImpersonation

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAllocateReserveObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MemoryReserveHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	MEMORY_RESERVE_TYPE Type_used = (MEMORY_RESERVE_TYPE)(x32based_args[4]); // MEMORY_RESERVE_TYPE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t MemoryReserveHandle_holder[sizeof(PVOID)];
	PHANDLE MemoryReserveHandle_used = (PHANDLE)&MemoryReserveHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_MemoryReserveHandle == NULL) {
		MemoryReserveHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, MemoryReserveHandle_used, ObjectAttributes_used, Type_used); // NtAllocateReserveObject

	if (MemoryReserveHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)MemoryReserveHandle_used, x32based_MemoryReserveHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateDebugObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DebugObjectHandle_holder[sizeof(PVOID)];
	PHANDLE DebugObjectHandle_used = (PHANDLE)&DebugObjectHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_DebugObjectHandle == NULL) {
		DebugObjectHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, DebugObjectHandle_used, DesiredAccess_used, ObjectAttributes_used, Flags_used); // NtCreateDebugObject

	if (DebugObjectHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)DebugObjectHandle_used, x32based_DebugObjectHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDebugActiveProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	HANDLE DebugObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DebugObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProcessHandle_used, DebugObjectHandle_used); // NtDebugActiveProcess

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDebugContinue(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ClientId = (uint32_t)(x32based_args[3]); // PCLIENT_ID  IN 
	NTSTATUS ContinueStatus_used = (NTSTATUS)(x32based_args[4]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE DebugObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DebugObjectHandle);
	uint8_t ClientId_holder[sizeof(_CLIENT_ID)];
	PCLIENT_ID ClientId_used = (PCLIENT_ID)&ClientId_holder;

	// Convert parameters from x32 to x64
	if (x32based_ClientId != NULL) {
		convert__CLIENT_ID_32TO64(ctx, (_CLIENT_ID**)&ClientId_used, x32based_ClientId);
	}
	else {
		ClientId_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, DebugObjectHandle_used, ClientId_used, ContinueStatus_used); // NtDebugContinue

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRemoveProcessDebug(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	HANDLE DebugObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DebugObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ProcessHandle_used, DebugObjectHandle_used); // NtRemoveProcessDebug

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationDebugObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	DEBUGOBJECTINFOCLASS DebugObjectInformationClass_used = (DEBUGOBJECTINFOCLASS)(x32based_args[3]); // DEBUGOBJECTINFOCLASS  IN 
	PVOID DebugInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG DebugInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE DebugObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DebugObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, DebugObjectHandle_used, DebugObjectInformationClass_used, DebugInformation_used, DebugInformationLength_used, ReturnLength_used); // NtSetInformationDebugObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWaitForDebugEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DebugObjectHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 
	uint32_t x32based_WaitStateChange = (uint32_t)(x32based_args[5]); // PDBGUI_WAIT_STATE_CHANGE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE DebugObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_DebugObjectHandle);
	uint8_t WaitStateChange_holder[sizeof(_DBGUI_WAIT_STATE_CHANGE)];
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange_used = (PDBGUI_WAIT_STATE_CHANGE)&WaitStateChange_holder;

	// Convert parameters from x32 to x64
	if (x32based_WaitStateChange == NULL) {
		WaitStateChange_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, DebugObjectHandle_used, Alertable_used, Timeout_used, WaitStateChange_used); // NtWaitForDebugEvent

	if (WaitStateChange_used != NULL) {
		convert__DBGUI_WAIT_STATE_CHANGE_64TO32(ctx, (_DBGUI_WAIT_STATE_CHANGE*)WaitStateChange_used, x32based_WaitStateChange);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 
	PLARGE_INTEGER AllocationSize_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 
	ULONG FileAttributes_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG ShareAccess_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG CreateDisposition_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	PVOID EaBuffer_used = (PVOID)(x32based_args[11]); // PVOID  IN 
	ULONG EaLength_used = (ULONG)(x32based_args[12]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileHandle_holder[sizeof(PVOID)];
	PHANDLE FileHandle_used = (PHANDLE)&FileHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileHandle == NULL) {
		FileHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, FileHandle_used, DesiredAccess_used, ObjectAttributes_used, IoStatusBlock_used, AllocationSize_used, FileAttributes_used, ShareAccess_used, CreateDisposition_used, CreateOptions_used, EaBuffer_used, EaLength_used); // NtCreateFile

	if (FileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)FileHandle_used, x32based_FileHandle);
	}
	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateNamedPipeFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ULONG DesiredAccess_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 
	ULONG ShareAccess_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG CreateDisposition_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG NamedPipeType_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	ULONG ReadMode_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	ULONG CompletionMode_used = (ULONG)(x32based_args[11]); // ULONG  IN 
	ULONG MaximumInstances_used = (ULONG)(x32based_args[12]); // ULONG  IN 
	ULONG InboundQuota_used = (ULONG)(x32based_args[13]); // ULONG  IN 
	ULONG OutboundQuota_used = (ULONG)(x32based_args[14]); // ULONG  IN 
	PLARGE_INTEGER DefaultTimeout_used = (PLARGE_INTEGER)(x32based_args[15]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileHandle_holder[sizeof(PVOID)];
	PHANDLE FileHandle_used = (PHANDLE)&FileHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileHandle == NULL) {
		FileHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 14, FileHandle_used, DesiredAccess_used, ObjectAttributes_used, IoStatusBlock_used, ShareAccess_used, CreateDisposition_used, CreateOptions_used, NamedPipeType_used, ReadMode_used, CompletionMode_used, MaximumInstances_used, InboundQuota_used, OutboundQuota_used, DefaultTimeout_used); // NtCreateNamedPipeFile

	if (FileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)FileHandle_used, x32based_FileHandle);
	}
	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateMailslotFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ULONG DesiredAccess_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 
	ULONG CreateOptions_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG MailslotQuota_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG MaximumMessageSize_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PLARGE_INTEGER ReadTimeout_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileHandle_holder[sizeof(PVOID)];
	PHANDLE FileHandle_used = (PHANDLE)&FileHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileHandle == NULL) {
		FileHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, FileHandle_used, DesiredAccess_used, ObjectAttributes_used, IoStatusBlock_used, CreateOptions_used, MailslotQuota_used, MaximumMessageSize_used, ReadTimeout_used); // NtCreateMailslotFile

	if (FileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)FileHandle_used, x32based_FileHandle);
	}
	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 
	ULONG ShareAccess_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG OpenOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t FileHandle_holder[sizeof(PVOID)];
	PHANDLE FileHandle_used = (PHANDLE)&FileHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_FileHandle == NULL) {
		FileHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, FileHandle_used, DesiredAccess_used, ObjectAttributes_used, IoStatusBlock_used, ShareAccess_used, OpenOptions_used); // NtOpenFile

	if (FileHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)FileHandle_used, x32based_FileHandle);
	}
	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, ObjectAttributes_used); // NtDeleteFile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushBuffersFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 2, FileHandle_used, IoStatusBlock_used); // NtFlushBuffersFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushBuffersFileEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PVOID Parameters_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ParametersSize_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, FileHandle_used, Flags_used, Parameters_used, ParametersSize_used, IoStatusBlock_used); // NtFlushBuffersFileEx

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID FileInformation_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	FILE_INFORMATION_CLASS FileInformationClass_used = (FILE_INFORMATION_CLASS)(x32based_args[6]); // FILE_INFORMATION_CLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	switch (FileInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, FileHandle_used, IoStatusBlock_used, FileInformation_used, Length_used, FileInformationClass_used); // NtQueryInformationFile
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationByName(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID FileInformation_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	FILE_INFORMATION_CLASS FileInformationClass_used = (FILE_INFORMATION_CLASS)(x32based_args[6]); // FILE_INFORMATION_CLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	switch (FileInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, ObjectAttributes_used, IoStatusBlock_used, FileInformation_used, Length_used, FileInformationClass_used); // NtQueryInformationByName
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID FileInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	FILE_INFORMATION_CLASS FileInformationClass_used = (FILE_INFORMATION_CLASS)(x32based_args[6]); // FILE_INFORMATION_CLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	switch (FileInformationClass_used) {
	case FileRenameInformation: {
		ret_value = _w32_NtSetInformationFile_FileRenameInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_RENAME_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileLinkInformation: {
		ret_value = _w32_NtSetInformationFile_FileLinkInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_LINK_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileMailslotSetInformation: {
		ret_value = _w32_NtSetInformationFile_FileMailslotSetInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_MAILSLOT_SET_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileCompletionInformation: {
		ret_value = _w32_NtSetInformationFile_FileCompletionInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_COMPLETION_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileMoveClusterInformation: {
		ret_value = _w32_NtSetInformationFile_FileMoveClusterInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_MOVE_CLUSTER_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileTrackingInformation: {
		ret_value = _w32_NtSetInformationFile_FileTrackingInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_TRACKING_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileIoStatusBlockRangeInformation: {
		ret_value = _w32_NtSetInformationFile_FileIoStatusBlockRangeInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_IOSTATUSBLOCK_RANGE_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileReplaceCompletionInformation: {
		ret_value = _w32_NtSetInformationFile_FileReplaceCompletionInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_COMPLETION_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileRenameInformationEx: {
		ret_value = _w32_NtSetInformationFile_FileRenameInformationEx(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_RENAME_INFORMATION_EX*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileMemoryPartitionInformation: {
		ret_value = _w32_NtSetInformationFile_FileMemoryPartitionInformation(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_MEMORY_PARTITION_INFORMATION*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	case FileLinkInformationEx: {
		ret_value = _w32_NtSetInformationFile_FileLinkInformationEx(ctx, syscall_idx, FileHandle_used, IoStatusBlock_used, (FILE_LINK_INFORMATION_EX*)FileInformation_used, Length_used, FileInformationClass_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, FileHandle_used, IoStatusBlock_used, FileInformation_used, Length_used, FileInformationClass_used); // NtSetInformationFile
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDirectoryFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID FileInformation_used = (PVOID)(x32based_args[7]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	FILE_INFORMATION_CLASS FileInformationClass_used = (FILE_INFORMATION_CLASS)(x32based_args[9]); // FILE_INFORMATION_CLASS  IN 
	BOOLEAN ReturnSingleEntry_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 
	uint32_t x32based_FileName = (uint32_t)(x32based_args[11]); // PUNICODE_STRING  IN 
	BOOLEAN RestartScan_used = (BOOLEAN)(x32based_args[12]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;
	uint8_t FileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING FileName_used = (PUNICODE_STRING)&FileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	if (x32based_FileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&FileName_used, x32based_FileName);
	}
	else {
		FileName_used = 0;
	}

	switch (FileInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 11, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, FileInformation_used, Length_used, FileInformationClass_used, ReturnSingleEntry_used, FileName_used, RestartScan_used); // NtQueryDirectoryFile
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryDirectoryFileEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID FileInformation_used = (PVOID)(x32based_args[7]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	FILE_INFORMATION_CLASS FileInformationClass_used = (FILE_INFORMATION_CLASS)(x32based_args[9]); // FILE_INFORMATION_CLASS  IN 
	ULONG QueryFlags_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	uint32_t x32based_FileName = (uint32_t)(x32based_args[11]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;
	uint8_t FileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING FileName_used = (PUNICODE_STRING)&FileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	if (x32based_FileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&FileName_used, x32based_FileName);
	}
	else {
		FileName_used = 0;
	}

	switch (FileInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 10, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, FileInformation_used, Length_used, FileInformationClass_used, QueryFlags_used, FileName_used); // NtQueryDirectoryFileEx
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryEaFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	BOOLEAN ReturnSingleEntry_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 
	PVOID EaList_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	ULONG EaListLength_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PULONG EaIndex_used = (PULONG)(x32based_args[9]); // PULONG  IN 
	BOOLEAN RestartScan_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, IoStatusBlock_used, Buffer_used, Length_used, ReturnSingleEntry_used, EaList_used, EaListLength_used, EaIndex_used, RestartScan_used); // NtQueryEaFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetEaFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, FileHandle_used, IoStatusBlock_used, Buffer_used, Length_used); // NtSetEaFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryQuotaInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	BOOLEAN ReturnSingleEntry_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 
	PVOID SidList_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	ULONG SidListLength_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	uint32_t x32based_StartSid = (uint32_t)(x32based_args[9]); // PSID  IN 
	BOOLEAN RestartScan_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;
	uint8_t StartSid_holder[sizeof(PVOID)];
	PSID StartSid_used = (PSID)&StartSid_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	if (x32based_StartSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&StartSid_used, x32based_StartSid);
	}
	else {
		StartSid_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, IoStatusBlock_used, Buffer_used, Length_used, ReturnSingleEntry_used, SidList_used, SidListLength_used, StartSid_used, RestartScan_used); // NtQueryQuotaInformationFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetQuotaInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, FileHandle_used, IoStatusBlock_used, Buffer_used, Length_used); // NtSetQuotaInformationFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryVolumeInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID FsInformation_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	FSINFOCLASS FsInformationClass_used = (FSINFOCLASS)(x32based_args[6]); // FSINFOCLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	switch (FsInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, FileHandle_used, IoStatusBlock_used, FsInformation_used, Length_used, FsInformationClass_used); // NtQueryVolumeInformationFile
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetVolumeInformationFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PVOID FsInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	FSINFOCLASS FsInformationClass_used = (FSINFOCLASS)(x32based_args[6]); // FSINFOCLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	switch (FsInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, FileHandle_used, IoStatusBlock_used, FsInformation_used, Length_used, FsInformationClass_used); // NtSetVolumeInformationFile
		break;
	}
	}

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelIoFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 2, FileHandle_used, IoStatusBlock_used); // NtCancelIoFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelIoFileEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoRequestToCancel = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[4]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoRequestToCancel_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoRequestToCancel_used = (PIO_STATUS_BLOCK)&IoRequestToCancel_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoRequestToCancel != NULL) {
		convert__IO_STATUS_BLOCK_32TO64(ctx, (_IO_STATUS_BLOCK**)&IoRequestToCancel_used, x32based_IoRequestToCancel);
	}
	else {
		IoRequestToCancel_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, FileHandle_used, IoRequestToCancel_used, IoStatusBlock_used); // NtCancelIoFileEx

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelSynchronousIoFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoRequestToCancel = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[4]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);
	uint8_t IoRequestToCancel_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoRequestToCancel_used = (PIO_STATUS_BLOCK)&IoRequestToCancel_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoRequestToCancel != NULL) {
		convert__IO_STATUS_BLOCK_32TO64(ctx, (_IO_STATUS_BLOCK**)&IoRequestToCancel_used, x32based_IoRequestToCancel);
	}
	else {
		IoRequestToCancel_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, ThreadHandle_used, IoRequestToCancel_used, IoStatusBlock_used); // NtCancelSynchronousIoFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeviceIoControlFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	ULONG IoControlCode_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[8]); // PVOID  IN 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	PVOID OutputBuffer_used = (PVOID)(x32based_args[10]); // PVOID  OUT 
	ULONG OutputBufferLength_used = (ULONG)(x32based_args[11]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 10, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, IoControlCode_used, InputBuffer_used, InputBufferLength_used, OutputBuffer_used, OutputBufferLength_used); // NtDeviceIoControlFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFsControlFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	ULONG FsControlCode_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[8]); // PVOID  IN 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	PVOID OutputBuffer_used = (PVOID)(x32based_args[10]); // PVOID  OUT 
	ULONG OutputBufferLength_used = (ULONG)(x32based_args[11]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 10, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, FsControlCode_used, InputBuffer_used, InputBufferLength_used, OutputBuffer_used, OutputBufferLength_used); // NtFsControlFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReadFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[7]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 
	PULONG Key_used = (PULONG)(x32based_args[10]); // PULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, Buffer_used, Length_used, ByteOffset_used, Key_used); // NtReadFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWriteFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 
	PULONG Key_used = (PULONG)(x32based_args[10]); // PULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, Buffer_used, Length_used, ByteOffset_used, Key_used); // NtWriteFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReadFileScatter(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	uint32_t x32based_SegmentArray = (uint32_t)(x32based_args[7]); // PFILE_SEGMENT_ELEMENT  IN 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 
	PULONG Key_used = (PULONG)(x32based_args[10]); // PULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;
	uint8_t SegmentArray_holder[sizeof(_FILE_SEGMENT_ELEMENT)];
	PFILE_SEGMENT_ELEMENT SegmentArray_used = (PFILE_SEGMENT_ELEMENT)&SegmentArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	if (x32based_SegmentArray != NULL) {
		convert__FILE_SEGMENT_ELEMENT_32TO64(ctx, (_FILE_SEGMENT_ELEMENT**)&SegmentArray_used, x32based_SegmentArray);
	}
	else {
		SegmentArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, SegmentArray_used, Length_used, ByteOffset_used, Key_used); // NtReadFileScatter

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWriteFileGather(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	uint32_t x32based_SegmentArray = (uint32_t)(x32based_args[7]); // PFILE_SEGMENT_ELEMENT  IN 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 
	PULONG Key_used = (PULONG)(x32based_args[10]); // PULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;
	uint8_t SegmentArray_holder[sizeof(_FILE_SEGMENT_ELEMENT)];
	PFILE_SEGMENT_ELEMENT SegmentArray_used = (PFILE_SEGMENT_ELEMENT)&SegmentArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	if (x32based_SegmentArray != NULL) {
		convert__FILE_SEGMENT_ELEMENT_32TO64(ctx, (_FILE_SEGMENT_ELEMENT**)&SegmentArray_used, x32based_SegmentArray);
	}
	else {
		SegmentArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, SegmentArray_used, Length_used, ByteOffset_used, Key_used); // NtWriteFileGather

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLockFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[7]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER Length_used = (PLARGE_INTEGER)(x32based_args[8]); // PLARGE_INTEGER  IN 
	ULONG Key_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	BOOLEAN FailImmediately_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 
	BOOLEAN ExclusiveLock_used = (BOOLEAN)(x32based_args[11]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 10, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, ByteOffset_used, Length_used, Key_used, FailImmediately_used, ExclusiveLock_used); // NtLockFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnlockFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[3]); // PIO_STATUS_BLOCK  OUT 
	PLARGE_INTEGER ByteOffset_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER Length_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 
	ULONG Key_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, FileHandle_used, IoStatusBlock_used, ByteOffset_used, Length_used, Key_used); // NtUnlockFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryAttributesFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	PFILE_BASIC_INFORMATION FileInformation_used = (PFILE_BASIC_INFORMATION)(x32based_args[3]); // PFILE_BASIC_INFORMATION  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, ObjectAttributes_used, FileInformation_used); // NtQueryAttributesFile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryFullAttributesFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	PFILE_NETWORK_OPEN_INFORMATION FileInformation_used = (PFILE_NETWORK_OPEN_INFORMATION)(x32based_args[3]); // PFILE_NETWORK_OPEN_INFORMATION  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, ObjectAttributes_used, FileInformation_used); // NtQueryFullAttributesFile

	return ret_value;
}


NTSTATUS WINAPI _w32_NtNotifyChangeDirectoryFile(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[7]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG CompletionFilter_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	BOOLEAN WatchTree_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 9, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, Buffer_used, Length_used, CompletionFilter_used, WatchTree_used); // NtNotifyChangeDirectoryFile

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtNotifyChangeDirectoryFileEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	PVOID Buffer_used = (PVOID)(x32based_args[7]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG CompletionFilter_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	BOOLEAN WatchTree_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 
	DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass_used = (DIRECTORY_NOTIFY_INFORMATION_CLASS)(x32based_args[11]); // DIRECTORY_NOTIFY_INFORMATION_CLASS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 10, FileHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, Buffer_used, Length_used, CompletionFilter_used, WatchTree_used, DirectoryNotifyInformationClass_used); // NtNotifyChangeDirectoryFileEx

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLoadDriver(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DriverServiceName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DriverServiceName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING DriverServiceName_used = (PUNICODE_STRING)&DriverServiceName_holder;

	// Convert parameters from x32 to x64
	if (x32based_DriverServiceName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&DriverServiceName_used, x32based_DriverServiceName);
	}
	else {
		DriverServiceName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, DriverServiceName_used); // NtLoadDriver

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnloadDriver(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_DriverServiceName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t DriverServiceName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING DriverServiceName_used = (PUNICODE_STRING)&DriverServiceName_holder;

	// Convert parameters from x32 to x64
	if (x32based_DriverServiceName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&DriverServiceName_used, x32based_DriverServiceName);
	}
	else {
		DriverServiceName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, DriverServiceName_used); // NtUnloadDriver

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateIoCompletion(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG Count_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t IoCompletionHandle_holder[sizeof(PVOID)];
	PHANDLE IoCompletionHandle_used = (PHANDLE)&IoCompletionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoCompletionHandle == NULL) {
		IoCompletionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, IoCompletionHandle_used, DesiredAccess_used, ObjectAttributes_used, Count_used); // NtCreateIoCompletion

	if (IoCompletionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)IoCompletionHandle_used, x32based_IoCompletionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenIoCompletion(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t IoCompletionHandle_holder[sizeof(PVOID)];
	PHANDLE IoCompletionHandle_used = (PHANDLE)&IoCompletionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoCompletionHandle == NULL) {
		IoCompletionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, IoCompletionHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenIoCompletion

	if (IoCompletionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)IoCompletionHandle_used, x32based_IoCompletionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryIoCompletion(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass_used = (IO_COMPLETION_INFORMATION_CLASS)(x32based_args[3]); // IO_COMPLETION_INFORMATION_CLASS  IN 
	PVOID IoCompletionInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG IoCompletionInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, IoCompletionHandle_used, IoCompletionInformationClass_used, IoCompletionInformation_used, IoCompletionInformationLength_used, ReturnLength_used); // NtQueryIoCompletion

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetIoCompletion(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID KeyContext_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	NTSTATUS IoStatus_used = (NTSTATUS)(x32based_args[5]); // NTSTATUS  IN 
	ULONG_PTR IoStatusInformation_used = (ULONG_PTR)(x32based_args[6]); // ULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, IoCompletionHandle_used, KeyContext_used, ApcContext_used, IoStatus_used, IoStatusInformation_used); // NtSetIoCompletion

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetIoCompletionEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoCompletionPacketHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PVOID KeyContext_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	NTSTATUS IoStatus_used = (NTSTATUS)(x32based_args[6]); // NTSTATUS  IN 
	ULONG_PTR IoStatusInformation_used = (ULONG_PTR)(x32based_args[7]); // ULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);
	HANDLE IoCompletionPacketHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionPacketHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, IoCompletionHandle_used, IoCompletionPacketHandle_used, KeyContext_used, ApcContext_used, IoStatus_used, IoStatusInformation_used); // NtSetIoCompletionEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRemoveIoCompletion(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_KeyContext = (uint32_t)(x32based_args[3]); // PVOID *  OUT 
	uint32_t x32based_ApcContext = (uint32_t)(x32based_args[4]); // PVOID *  OUT 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);
	uint8_t KeyContext_holder[sizeof(PVOID)];
	PVOID* KeyContext_used = (PVOID*)&KeyContext_holder;
	uint8_t ApcContext_holder[sizeof(PVOID)];
	PVOID* ApcContext_used = (PVOID*)&ApcContext_holder;
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyContext == NULL) {
		KeyContext_used = 0;
	}
	if (x32based_ApcContext == NULL) {
		ApcContext_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, IoCompletionHandle_used, KeyContext_used, ApcContext_used, IoStatusBlock_used, Timeout_used); // NtRemoveIoCompletion

	if (x32based_KeyContext != NULL) {
		*((X32_SIZE_T*)x32based_KeyContext) = (X32_SIZE_T)(*(SIZE_T*)KeyContext_used);
	}
	if (x32based_ApcContext != NULL) {
		*((X32_SIZE_T*)x32based_ApcContext) = (X32_SIZE_T)(*(SIZE_T*)ApcContext_used);
	}
	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRemoveIoCompletionEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoCompletionInformation = (uint32_t)(x32based_args[3]); // PFILE_IO_COMPLETION_INFORMATION  OUT 
	ULONG Count_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PULONG NumEntriesRemoved_used = (PULONG)(x32based_args[5]); // PULONG  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 
	BOOLEAN Alertable_used = (BOOLEAN)(x32based_args[7]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);
	uint8_t IoCompletionInformation_holder[sizeof(_FILE_IO_COMPLETION_INFORMATION)];
	PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation_used = (PFILE_IO_COMPLETION_INFORMATION)&IoCompletionInformation_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoCompletionInformation == NULL) {
		IoCompletionInformation_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, IoCompletionHandle_used, IoCompletionInformation_used, Count_used, NumEntriesRemoved_used, Timeout_used, Alertable_used); // NtRemoveIoCompletionEx

	if (IoCompletionInformation_used != NULL) {
		convert__FILE_IO_COMPLETION_INFORMATION_64TO32(ctx, (_FILE_IO_COMPLETION_INFORMATION*)IoCompletionInformation_used, x32based_IoCompletionInformation);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateWaitCompletionPacket(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WaitCompletionPacketHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t WaitCompletionPacketHandle_holder[sizeof(PVOID)];
	PHANDLE WaitCompletionPacketHandle_used = (PHANDLE)&WaitCompletionPacketHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_WaitCompletionPacketHandle == NULL) {
		WaitCompletionPacketHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, WaitCompletionPacketHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtCreateWaitCompletionPacket

	if (WaitCompletionPacketHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)WaitCompletionPacketHandle_used, x32based_WaitCompletionPacketHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAssociateWaitCompletionPacket(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WaitCompletionPacketHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_IoCompletionHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_TargetObjectHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	PVOID KeyContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[6]); // PVOID  IN 
	NTSTATUS IoStatus_used = (NTSTATUS)(x32based_args[7]); // NTSTATUS  IN 
	ULONG_PTR IoStatusInformation_used = (ULONG_PTR)(x32based_args[8]); // ULONG_PTR  IN 
	PBOOLEAN AlreadySignaled_used = (PBOOLEAN)(x32based_args[9]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WaitCompletionPacketHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WaitCompletionPacketHandle);
	HANDLE IoCompletionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_IoCompletionHandle);
	HANDLE TargetObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TargetObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 8, WaitCompletionPacketHandle_used, IoCompletionHandle_used, TargetObjectHandle_used, KeyContext_used, ApcContext_used, IoStatus_used, IoStatusInformation_used, AlreadySignaled_used); // NtAssociateWaitCompletionPacket

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCancelWaitCompletionPacket(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_WaitCompletionPacketHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN RemoveSignaledPacket_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE WaitCompletionPacketHandle_used = Handle32ToHandle((const void* __ptr32)x32based_WaitCompletionPacketHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, WaitCompletionPacketHandle_used, RemoveSignaledPacket_used); // NtCancelWaitCompletionPacket

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenSession(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SessionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SessionHandle_holder[sizeof(PVOID)];
	PHANDLE SessionHandle_used = (PHANDLE)&SessionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_SessionHandle == NULL) {
		SessionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SessionHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenSession

	if (SessionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)SessionHandle_used, x32based_SessionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtNotifyChangeSession(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SessionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG ChangeSequenceNumber_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PLARGE_INTEGER ChangeTimeStamp_used = (PLARGE_INTEGER)(x32based_args[4]); // PLARGE_INTEGER  IN 
	IO_SESSION_EVENT Event_used = (IO_SESSION_EVENT)(x32based_args[5]); // IO_SESSION_EVENT  IN 
	IO_SESSION_STATE NewState_used = (IO_SESSION_STATE)(x32based_args[6]); // IO_SESSION_STATE  IN 
	IO_SESSION_STATE PreviousState_used = (IO_SESSION_STATE)(x32based_args[7]); // IO_SESSION_STATE  IN 
	PVOID Payload_used = (PVOID)(x32based_args[8]); // PVOID  IN 
	ULONG PayloadSize_used = (ULONG)(x32based_args[9]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE SessionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SessionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 8, SessionHandle_used, ChangeSequenceNumber_used, ChangeTimeStamp_used, Event_used, NewState_used, PreviousState_used, Payload_used, PayloadSize_used); // NtNotifyChangeSession

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreatePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	ULONG MaxConnectionInfoLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG MaxMessageLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ULONG MaxPoolUsage_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, PortHandle_used, ObjectAttributes_used, MaxConnectionInfoLength_used, MaxMessageLength_used, MaxPoolUsage_used); // NtCreatePort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateWaitablePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	ULONG MaxConnectionInfoLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG MaxMessageLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ULONG MaxPoolUsage_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, PortHandle_used, ObjectAttributes_used, MaxConnectionInfoLength_used, MaxMessageLength_used, MaxPoolUsage_used); // NtCreateWaitablePort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_PortName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	PSECURITY_QUALITY_OF_SERVICE SecurityQos_used = (PSECURITY_QUALITY_OF_SERVICE)(x32based_args[4]); // PSECURITY_QUALITY_OF_SERVICE  IN 
	uint32_t x32based_ClientView = (uint32_t)(x32based_args[5]); // PPORT_VIEW  IN  OUT 
	uint32_t x32based_ServerView = (uint32_t)(x32based_args[6]); // PREMOTE_PORT_VIEW  IN  OUT 
	PULONG MaxMessageLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 
	PVOID ConnectionInformation_used = (PVOID)(x32based_args[8]); // PVOID  IN  OUT 
	PULONG ConnectionInformationLength_used = (PULONG)(x32based_args[9]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t PortName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING PortName_used = (PUNICODE_STRING)&PortName_holder;
	uint8_t ClientView_holder[sizeof(_PORT_VIEW)];
	PPORT_VIEW ClientView_used = (PPORT_VIEW)&ClientView_holder;
	uint8_t ServerView_holder[sizeof(_REMOTE_PORT_VIEW)];
	PREMOTE_PORT_VIEW ServerView_used = (PREMOTE_PORT_VIEW)&ServerView_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_PortName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&PortName_used, x32based_PortName);
	}
	else {
		PortName_used = 0;
	}
	if (x32based_ClientView != NULL) {
		convert__PORT_VIEW_32TO64(ctx, (_PORT_VIEW**)&ClientView_used, x32based_ClientView);
	}
	else {
		ClientView_used = 0;
	}
	if (x32based_ServerView != NULL) {
		convert__REMOTE_PORT_VIEW_32TO64(ctx, (_REMOTE_PORT_VIEW**)&ServerView_used, x32based_ServerView);
	}
	else {
		ServerView_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, PortHandle_used, PortName_used, SecurityQos_used, ClientView_used, ServerView_used, MaxMessageLength_used, ConnectionInformation_used, ConnectionInformationLength_used); // NtConnectPort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}
	if (ClientView_used != NULL) {
		convert__PORT_VIEW_64TO32(ctx, (_PORT_VIEW*)ClientView_used, x32based_ClientView);
	}
	if (ServerView_used != NULL) {
		convert__REMOTE_PORT_VIEW_64TO32(ctx, (_REMOTE_PORT_VIEW*)ServerView_used, x32based_ServerView);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSecureConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_PortName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	PSECURITY_QUALITY_OF_SERVICE SecurityQos_used = (PSECURITY_QUALITY_OF_SERVICE)(x32based_args[4]); // PSECURITY_QUALITY_OF_SERVICE  IN 
	uint32_t x32based_ClientView = (uint32_t)(x32based_args[5]); // PPORT_VIEW  IN  OUT 
	uint32_t x32based_RequiredServerSid = (uint32_t)(x32based_args[6]); // PSID  IN 
	uint32_t x32based_ServerView = (uint32_t)(x32based_args[7]); // PREMOTE_PORT_VIEW  IN  OUT 
	PULONG MaxMessageLength_used = (PULONG)(x32based_args[8]); // PULONG  OUT 
	PVOID ConnectionInformation_used = (PVOID)(x32based_args[9]); // PVOID  IN  OUT 
	PULONG ConnectionInformationLength_used = (PULONG)(x32based_args[10]); // PULONG  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t PortName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING PortName_used = (PUNICODE_STRING)&PortName_holder;
	uint8_t ClientView_holder[sizeof(_PORT_VIEW)];
	PPORT_VIEW ClientView_used = (PPORT_VIEW)&ClientView_holder;
	uint8_t RequiredServerSid_holder[sizeof(PVOID)];
	PSID RequiredServerSid_used = (PSID)&RequiredServerSid_holder;
	uint8_t ServerView_holder[sizeof(_REMOTE_PORT_VIEW)];
	PREMOTE_PORT_VIEW ServerView_used = (PREMOTE_PORT_VIEW)&ServerView_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_PortName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&PortName_used, x32based_PortName);
	}
	else {
		PortName_used = 0;
	}
	if (x32based_ClientView != NULL) {
		convert__PORT_VIEW_32TO64(ctx, (_PORT_VIEW**)&ClientView_used, x32based_ClientView);
	}
	else {
		ClientView_used = 0;
	}
	if (x32based_RequiredServerSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&RequiredServerSid_used, x32based_RequiredServerSid);
	}
	else {
		RequiredServerSid_used = 0;
	}
	if (x32based_ServerView != NULL) {
		convert__REMOTE_PORT_VIEW_32TO64(ctx, (_REMOTE_PORT_VIEW**)&ServerView_used, x32based_ServerView);
	}
	else {
		ServerView_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, PortHandle_used, PortName_used, SecurityQos_used, ClientView_used, RequiredServerSid_used, ServerView_used, MaxMessageLength_used, ConnectionInformation_used, ConnectionInformationLength_used); // NtSecureConnectPort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}
	if (ClientView_used != NULL) {
		convert__PORT_VIEW_64TO32(ctx, (_PORT_VIEW*)ClientView_used, x32based_ClientView);
	}
	if (ServerView_used != NULL) {
		convert__REMOTE_PORT_VIEW_64TO32(ctx, (_REMOTE_PORT_VIEW*)ServerView_used, x32based_ServerView);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtListenPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ConnectionRequest = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t ConnectionRequest_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ConnectionRequest_used = (PPORT_MESSAGE)&ConnectionRequest_holder;

	// Convert parameters from x32 to x64
	if (x32based_ConnectionRequest == NULL) {
		ConnectionRequest_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, ConnectionRequest_used); // NtListenPort

	if (ConnectionRequest_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ConnectionRequest_used, x32based_ConnectionRequest);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAcceptConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	PVOID PortContext_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ConnectionRequest = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	BOOLEAN AcceptConnection_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	uint32_t x32based_ServerView = (uint32_t)(x32based_args[6]); // PPORT_VIEW  IN  OUT 
	uint32_t x32based_ClientView = (uint32_t)(x32based_args[7]); // PREMOTE_PORT_VIEW  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t ConnectionRequest_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ConnectionRequest_used = (PPORT_MESSAGE)&ConnectionRequest_holder;
	uint8_t ServerView_holder[sizeof(_PORT_VIEW)];
	PPORT_VIEW ServerView_used = (PPORT_VIEW)&ServerView_holder;
	uint8_t ClientView_holder[sizeof(_REMOTE_PORT_VIEW)];
	PREMOTE_PORT_VIEW ClientView_used = (PREMOTE_PORT_VIEW)&ClientView_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ConnectionRequest != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ConnectionRequest_used, x32based_ConnectionRequest);
	}
	else {
		ConnectionRequest_used = 0;
	}
	if (x32based_ServerView != NULL) {
		convert__PORT_VIEW_32TO64(ctx, (_PORT_VIEW**)&ServerView_used, x32based_ServerView);
	}
	else {
		ServerView_used = 0;
	}
	if (x32based_ClientView == NULL) {
		ClientView_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, PortHandle_used, PortContext_used, ConnectionRequest_used, AcceptConnection_used, ServerView_used, ClientView_used); // NtAcceptConnectPort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}
	if (ServerView_used != NULL) {
		convert__PORT_VIEW_64TO32(ctx, (_PORT_VIEW*)ServerView_used, x32based_ServerView);
	}
	if (ClientView_used != NULL) {
		convert__REMOTE_PORT_VIEW_64TO32(ctx, (_REMOTE_PORT_VIEW*)ClientView_used, x32based_ClientView);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCompleteConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, PortHandle_used); // NtCompleteConnectPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRequestPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_RequestMessage = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t RequestMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE RequestMessage_used = (PPORT_MESSAGE)&RequestMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_RequestMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&RequestMessage_used, x32based_RequestMessage);
	}
	else {
		RequestMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, RequestMessage_used); // NtRequestPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRequestWaitReplyPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_RequestMessage = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	uint32_t x32based_ReplyMessage = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t RequestMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE RequestMessage_used = (PPORT_MESSAGE)&RequestMessage_holder;
	uint8_t ReplyMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReplyMessage_used = (PPORT_MESSAGE)&ReplyMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_RequestMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&RequestMessage_used, x32based_RequestMessage);
	}
	else {
		RequestMessage_used = 0;
	}
	if (x32based_ReplyMessage == NULL) {
		ReplyMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, RequestMessage_used, ReplyMessage_used); // NtRequestWaitReplyPort

	if (ReplyMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ReplyMessage_used, x32based_ReplyMessage);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplyPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ReplyMessage = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t ReplyMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReplyMessage_used = (PPORT_MESSAGE)&ReplyMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_ReplyMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ReplyMessage_used, x32based_ReplyMessage);
	}
	else {
		ReplyMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, ReplyMessage_used); // NtReplyPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplyWaitReplyPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ReplyMessage = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t ReplyMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReplyMessage_used = (PPORT_MESSAGE)&ReplyMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_ReplyMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ReplyMessage_used, x32based_ReplyMessage);
	}
	else {
		ReplyMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, ReplyMessage_used); // NtReplyWaitReplyPort

	if (ReplyMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ReplyMessage_used, x32based_ReplyMessage);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplyWaitReceivePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_PortContext = (uint32_t)(x32based_args[3]); // PVOID *  OUT 
	uint32_t x32based_ReplyMessage = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	uint32_t x32based_ReceiveMessage = (uint32_t)(x32based_args[5]); // PPORT_MESSAGE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t PortContext_holder[sizeof(PVOID)];
	PVOID* PortContext_used = (PVOID*)&PortContext_holder;
	uint8_t ReplyMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReplyMessage_used = (PPORT_MESSAGE)&ReplyMessage_holder;
	uint8_t ReceiveMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReceiveMessage_used = (PPORT_MESSAGE)&ReceiveMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortContext == NULL) {
		PortContext_used = 0;
	}
	if (x32based_ReplyMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ReplyMessage_used, x32based_ReplyMessage);
	}
	else {
		ReplyMessage_used = 0;
	}
	if (x32based_ReceiveMessage == NULL) {
		ReceiveMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, PortHandle_used, PortContext_used, ReplyMessage_used, ReceiveMessage_used); // NtReplyWaitReceivePort

	if (x32based_PortContext != NULL) {
		*((X32_SIZE_T*)x32based_PortContext) = (X32_SIZE_T)(*(SIZE_T*)PortContext_used);
	}
	if (ReceiveMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ReceiveMessage_used, x32based_ReceiveMessage);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplyWaitReceivePortEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_PortContext = (uint32_t)(x32based_args[3]); // PVOID *  OUT 
	uint32_t x32based_ReplyMessage = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	uint32_t x32based_ReceiveMessage = (uint32_t)(x32based_args[5]); // PPORT_MESSAGE  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[6]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t PortContext_holder[sizeof(PVOID)];
	PVOID* PortContext_used = (PVOID*)&PortContext_holder;
	uint8_t ReplyMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReplyMessage_used = (PPORT_MESSAGE)&ReplyMessage_holder;
	uint8_t ReceiveMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReceiveMessage_used = (PPORT_MESSAGE)&ReceiveMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortContext == NULL) {
		PortContext_used = 0;
	}
	if (x32based_ReplyMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ReplyMessage_used, x32based_ReplyMessage);
	}
	else {
		ReplyMessage_used = 0;
	}
	if (x32based_ReceiveMessage == NULL) {
		ReceiveMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, PortHandle_used, PortContext_used, ReplyMessage_used, ReceiveMessage_used, Timeout_used); // NtReplyWaitReceivePortEx

	if (x32based_PortContext != NULL) {
		*((X32_SIZE_T*)x32based_PortContext) = (X32_SIZE_T)(*(SIZE_T*)PortContext_used);
	}
	if (ReceiveMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ReceiveMessage_used, x32based_ReceiveMessage);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtImpersonateClientOfPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Message = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t Message_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE Message_used = (PPORT_MESSAGE)&Message_holder;

	// Convert parameters from x32 to x64
	if (x32based_Message != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&Message_used, x32based_Message);
	}
	else {
		Message_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, Message_used); // NtImpersonateClientOfPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReadRequestData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Message = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	ULONG DataEntryIndex_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[6]); // SIZE_T  IN 
	uint32_t x32based_NumberOfBytesRead = (uint32_t)(x32based_args[7]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t Message_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE Message_used = (PPORT_MESSAGE)&Message_holder;
	uint8_t NumberOfBytesRead_holder[sizeof(long long unsigned int)];
	PSIZE_T NumberOfBytesRead_used = (PSIZE_T)&NumberOfBytesRead_holder;

	// Convert parameters from x32 to x64
	if (x32based_Message != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&Message_used, x32based_Message);
	}
	else {
		Message_used = 0;
	}
	if (x32based_NumberOfBytesRead == NULL) {
		NumberOfBytesRead_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, PortHandle_used, Message_used, DataEntryIndex_used, Buffer_used, BufferSize_used, NumberOfBytesRead_used); // NtReadRequestData

	if (x32based_NumberOfBytesRead != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfBytesRead) = (X32_SIZE_T)(*(SIZE_T*)NumberOfBytesRead_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtWriteRequestData(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Message = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	ULONG DataEntryIndex_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[6]); // SIZE_T  IN 
	uint32_t x32based_NumberOfBytesWritten = (uint32_t)(x32based_args[7]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t Message_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE Message_used = (PPORT_MESSAGE)&Message_holder;
	uint8_t NumberOfBytesWritten_holder[sizeof(long long unsigned int)];
	PSIZE_T NumberOfBytesWritten_used = (PSIZE_T)&NumberOfBytesWritten_holder;

	// Convert parameters from x32 to x64
	if (x32based_Message != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&Message_used, x32based_Message);
	}
	else {
		Message_used = 0;
	}
	if (x32based_NumberOfBytesWritten == NULL) {
		NumberOfBytesWritten_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, PortHandle_used, Message_used, DataEntryIndex_used, Buffer_used, BufferSize_used, NumberOfBytesWritten_used); // NtWriteRequestData

	if (x32based_NumberOfBytesWritten != NULL) {
		*((X32_SIZE_T*)x32based_NumberOfBytesWritten) = (X32_SIZE_T)(*(SIZE_T*)NumberOfBytesWritten_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PORT_INFORMATION_CLASS PortInformationClass_used = (PORT_INFORMATION_CLASS)(x32based_args[3]); // PORT_INFORMATION_CLASS  IN 
	PVOID PortInformation_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	switch (PortInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, PortHandle_used, PortInformationClass_used, PortInformation_used, Length_used, ReturnLength_used); // NtQueryInformationPort
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCreatePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_PortAttributes = (uint32_t)(x32based_args[4]); // PALPC_PORT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t PortAttributes_holder[sizeof(_ALPC_PORT_ATTRIBUTES)];
	PALPC_PORT_ATTRIBUTES PortAttributes_used = (PALPC_PORT_ATTRIBUTES)&PortAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_PortAttributes != NULL) {
		convert__ALPC_PORT_ATTRIBUTES_32TO64(ctx, (_ALPC_PORT_ATTRIBUTES**)&PortAttributes_used, x32based_PortAttributes);
	}
	else {
		PortAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, ObjectAttributes_used, PortAttributes_used); // NtAlpcCreatePort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcDisconnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, PortHandle_used, Flags_used); // NtAlpcDisconnectPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcQueryInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ALPC_PORT_INFORMATION_CLASS PortInformationClass_used = (ALPC_PORT_INFORMATION_CLASS)(x32based_args[3]); // ALPC_PORT_INFORMATION_CLASS  IN 
	PVOID PortInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	switch (PortInformationClass_used) {
	case AlpcBasicInformation: {
		ret_value = _w32_NtAlpcQueryInformation_AlpcBasicInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_BASIC_INFORMATION*)PortInformation_used, Length_used, ReturnLength_used);
		break;
	}
	case AlpcServerInformation: {
		ret_value = _w32_NtAlpcQueryInformation_AlpcServerInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_SERVER_INFORMATION*)PortInformation_used, Length_used, ReturnLength_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 5, PortHandle_used, PortInformationClass_used, PortInformation_used, Length_used, ReturnLength_used); // NtAlpcQueryInformation
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcSetInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ALPC_PORT_INFORMATION_CLASS PortInformationClass_used = (ALPC_PORT_INFORMATION_CLASS)(x32based_args[3]); // ALPC_PORT_INFORMATION_CLASS  IN 
	PVOID PortInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	switch (PortInformationClass_used) {
	case AlpcBasicInformation: {
		ret_value = _w32_NtAlpcSetInformation_AlpcBasicInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_BASIC_INFORMATION*)PortInformation_used, Length_used);
		break;
	}
	case AlpcPortInformation: {
		ret_value = _w32_NtAlpcSetInformation_AlpcPortInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_PORT_ATTRIBUTES*)PortInformation_used, Length_used);
		break;
	}
	case AlpcAssociateCompletionPortInformation: {
		ret_value = _w32_NtAlpcSetInformation_AlpcAssociateCompletionPortInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_PORT_ASSOCIATE_COMPLETION_PORT*)PortInformation_used, Length_used);
		break;
	}
	case AlpcMessageZoneInformation: {
		ret_value = _w32_NtAlpcSetInformation_AlpcMessageZoneInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_PORT_MESSAGE_ZONE_INFORMATION*)PortInformation_used, Length_used);
		break;
	}
	case AlpcRegisterCompletionListInformation: {
		ret_value = _w32_NtAlpcSetInformation_AlpcRegisterCompletionListInformation(ctx, syscall_idx, PortHandle_used, PortInformationClass_used, (ALPC_PORT_COMPLETION_LIST_INFORMATION*)PortInformation_used, Length_used);
		break;
	}
	default: {
		ret_value = __syscall64(syscall_idx, 4, PortHandle_used, PortInformationClass_used, PortInformation_used, Length_used); // NtAlpcSetInformation
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCreatePortSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_SectionHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	SIZE_T SectionSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint32_t x32based_AlpcSectionHandle = (uint32_t)(x32based_args[6]); // PALPC_HANDLE  OUT 
	uint32_t x32based_ActualSectionSize = (uint32_t)(x32based_args[7]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	HANDLE SectionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SectionHandle);
	uint8_t AlpcSectionHandle_holder[sizeof(PVOID)];
	PALPC_HANDLE AlpcSectionHandle_used = (PALPC_HANDLE)&AlpcSectionHandle_holder;
	uint8_t ActualSectionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T ActualSectionSize_used = (PSIZE_T)&ActualSectionSize_holder;

	// Convert parameters from x32 to x64
	if (x32based_AlpcSectionHandle == NULL) {
		AlpcSectionHandle_used = 0;
	}
	if (x32based_ActualSectionSize == NULL) {
		ActualSectionSize_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 6, PortHandle_used, Flags_used, SectionHandle_used, SectionSize_used, AlpcSectionHandle_used, ActualSectionSize_used); // NtAlpcCreatePortSection

	if (AlpcSectionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)AlpcSectionHandle_used, x32based_AlpcSectionHandle);
	}
	if (x32based_ActualSectionSize != NULL) {
		*((X32_SIZE_T*)x32based_ActualSectionSize) = (X32_SIZE_T)(*(SIZE_T*)ActualSectionSize_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcDeletePortSection(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	ALPC_HANDLE SectionHandle_used = (ALPC_HANDLE)(x32based_args[4]); // ALPC_HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, SectionHandle_used); // NtAlpcDeletePortSection

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCreateResourceReserve(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	SIZE_T MessageSize_used = (SIZE_T)(x32based_args[4]); // SIZE_T  IN 
	uint32_t x32based_ResourceId = (uint32_t)(x32based_args[5]); // PALPC_HANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t ResourceId_holder[sizeof(PVOID)];
	PALPC_HANDLE ResourceId_used = (PALPC_HANDLE)&ResourceId_holder;

	// Convert parameters from x32 to x64
	if (x32based_ResourceId == NULL) {
		ResourceId_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, PortHandle_used, Flags_used, MessageSize_used, ResourceId_used); // NtAlpcCreateResourceReserve

	if (ResourceId_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ResourceId_used, x32based_ResourceId);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcDeleteResourceReserve(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	ALPC_HANDLE ResourceId_used = (ALPC_HANDLE)(x32based_args[4]); // ALPC_HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, ResourceId_used); // NtAlpcDeleteResourceReserve

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCreateSectionView(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	uint32_t x32based_ViewAttributes = (uint32_t)(x32based_args[4]); // PALPC_DATA_VIEW_ATTR  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t ViewAttributes_holder[sizeof(_ALPC_DATA_VIEW_ATTR)];
	PALPC_DATA_VIEW_ATTR ViewAttributes_used = (PALPC_DATA_VIEW_ATTR)&ViewAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ViewAttributes != NULL) {
		convert__ALPC_DATA_VIEW_ATTR_32TO64(ctx, (_ALPC_DATA_VIEW_ATTR**)&ViewAttributes_used, x32based_ViewAttributes);
	}
	else {
		ViewAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, ViewAttributes_used); // NtAlpcCreateSectionView

	if (ViewAttributes_used != NULL) {
		convert__ALPC_DATA_VIEW_ATTR_64TO32(ctx, (_ALPC_DATA_VIEW_ATTR*)ViewAttributes_used, x32based_ViewAttributes);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcDeleteSectionView(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	PVOID ViewBase_used = (PVOID)(x32based_args[4]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, ViewBase_used); // NtAlpcDeleteSectionView

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCreateSecurityContext(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	uint32_t x32based_SecurityAttribute = (uint32_t)(x32based_args[4]); // PALPC_SECURITY_ATTR  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t SecurityAttribute_holder[sizeof(_ALPC_SECURITY_ATTR)];
	PALPC_SECURITY_ATTR SecurityAttribute_used = (PALPC_SECURITY_ATTR)&SecurityAttribute_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityAttribute != NULL) {
		convert__ALPC_SECURITY_ATTR_32TO64(ctx, (_ALPC_SECURITY_ATTR**)&SecurityAttribute_used, x32based_SecurityAttribute);
	}
	else {
		SecurityAttribute_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, SecurityAttribute_used); // NtAlpcCreateSecurityContext

	if (SecurityAttribute_used != NULL) {
		convert__ALPC_SECURITY_ATTR_64TO32(ctx, (_ALPC_SECURITY_ATTR*)SecurityAttribute_used, x32based_SecurityAttribute);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcDeleteSecurityContext(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	ALPC_HANDLE ContextHandle_used = (ALPC_HANDLE)(x32based_args[4]); // ALPC_HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, ContextHandle_used); // NtAlpcDeleteSecurityContext

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcRevokeSecurityContext(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG 
	ALPC_HANDLE ContextHandle_used = (ALPC_HANDLE)(x32based_args[4]); // ALPC_HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, ContextHandle_used); // NtAlpcRevokeSecurityContext

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcQueryInformationMessage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_PortMessage = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass_used = (ALPC_MESSAGE_INFORMATION_CLASS)(x32based_args[4]); // ALPC_MESSAGE_INFORMATION_CLASS  IN 
	PVOID MessageInformation_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t PortMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE PortMessage_used = (PPORT_MESSAGE)&PortMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&PortMessage_used, x32based_PortMessage);
	}
	else {
		PortMessage_used = 0;
	}

	switch (MessageInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 6, PortHandle_used, PortMessage_used, MessageInformationClass_used, MessageInformation_used, Length_used, ReturnLength_used); // NtAlpcQueryInformationMessage
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_PortName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_PortAttributes = (uint32_t)(x32based_args[5]); // PALPC_PORT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	uint32_t x32based_RequiredServerSid = (uint32_t)(x32based_args[7]); // PSID  IN 
	uint32_t x32based_ConnectionMessage = (uint32_t)(x32based_args[8]); // PPORT_MESSAGE  IN  OUT 
	PULONG BufferLength_used = (PULONG)(x32based_args[9]); // PULONG  IN  OUT 
	PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[10]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	PALPC_MESSAGE_ATTRIBUTES InMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[11]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[12]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t PortName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING PortName_used = (PUNICODE_STRING)&PortName_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t PortAttributes_holder[sizeof(_ALPC_PORT_ATTRIBUTES)];
	PALPC_PORT_ATTRIBUTES PortAttributes_used = (PALPC_PORT_ATTRIBUTES)&PortAttributes_holder;
	uint8_t RequiredServerSid_holder[sizeof(PVOID)];
	PSID RequiredServerSid_used = (PSID)&RequiredServerSid_holder;
	uint8_t ConnectionMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ConnectionMessage_used = (PPORT_MESSAGE)&ConnectionMessage_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_PortName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&PortName_used, x32based_PortName);
	}
	else {
		PortName_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_PortAttributes != NULL) {
		convert__ALPC_PORT_ATTRIBUTES_32TO64(ctx, (_ALPC_PORT_ATTRIBUTES**)&PortAttributes_used, x32based_PortAttributes);
	}
	else {
		PortAttributes_used = 0;
	}
	if (x32based_RequiredServerSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&RequiredServerSid_used, x32based_RequiredServerSid);
	}
	else {
		RequiredServerSid_used = 0;
	}
	if (x32based_ConnectionMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ConnectionMessage_used, x32based_ConnectionMessage);
	}
	else {
		ConnectionMessage_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, PortHandle_used, PortName_used, ObjectAttributes_used, PortAttributes_used, Flags_used, RequiredServerSid_used, ConnectionMessage_used, BufferLength_used, OutMessageAttributes_used, InMessageAttributes_used, Timeout_used); // NtAlpcConnectPort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}
	if (ConnectionMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ConnectionMessage_used, x32based_ConnectionMessage);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcConnectPortEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ConnectionPortObjectAttributes = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_ClientPortObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_PortAttributes = (uint32_t)(x32based_args[5]); // PALPC_PORT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	uint32_t x32based_ServerSecurityRequirements = (uint32_t)(x32based_args[7]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_ConnectionMessage = (uint32_t)(x32based_args[8]); // PPORT_MESSAGE  IN  OUT 
	uint32_t x32based_BufferLength = (uint32_t)(x32based_args[9]); // PSIZE_T  IN  OUT 
	PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[10]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	PALPC_MESSAGE_ATTRIBUTES InMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[11]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[12]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	uint8_t ConnectionPortObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ConnectionPortObjectAttributes_used = (POBJECT_ATTRIBUTES)&ConnectionPortObjectAttributes_holder;
	uint8_t ClientPortObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ClientPortObjectAttributes_used = (POBJECT_ATTRIBUTES)&ClientPortObjectAttributes_holder;
	uint8_t PortAttributes_holder[sizeof(_ALPC_PORT_ATTRIBUTES)];
	PALPC_PORT_ATTRIBUTES PortAttributes_used = (PALPC_PORT_ATTRIBUTES)&PortAttributes_holder;
	uint8_t ServerSecurityRequirements_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR ServerSecurityRequirements_used = (PSECURITY_DESCRIPTOR)&ServerSecurityRequirements_holder;
	uint8_t ConnectionMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ConnectionMessage_used = (PPORT_MESSAGE)&ConnectionMessage_holder;
	uint8_t BufferLength_holder[sizeof(long long unsigned int)];
	PSIZE_T BufferLength_used = (PSIZE_T)&BufferLength_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ConnectionPortObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ConnectionPortObjectAttributes_used, x32based_ConnectionPortObjectAttributes);
	}
	else {
		ConnectionPortObjectAttributes_used = 0;
	}
	if (x32based_ClientPortObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ClientPortObjectAttributes_used, x32based_ClientPortObjectAttributes);
	}
	else {
		ClientPortObjectAttributes_used = 0;
	}
	if (x32based_PortAttributes != NULL) {
		convert__ALPC_PORT_ATTRIBUTES_32TO64(ctx, (_ALPC_PORT_ATTRIBUTES**)&PortAttributes_used, x32based_PortAttributes);
	}
	else {
		PortAttributes_used = 0;
	}
	if (x32based_ServerSecurityRequirements != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&ServerSecurityRequirements_used, x32based_ServerSecurityRequirements);
	}
	else {
		ServerSecurityRequirements_used = 0;
	}
	if (x32based_ConnectionMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ConnectionMessage_used, x32based_ConnectionMessage);
	}
	else {
		ConnectionMessage_used = 0;
	}
	if (x32based_BufferLength != NULL) {
		*((SIZE_T*)BufferLength_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BufferLength));
	}
	else {
		BufferLength_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, PortHandle_used, ConnectionPortObjectAttributes_used, ClientPortObjectAttributes_used, PortAttributes_used, Flags_used, ServerSecurityRequirements_used, ConnectionMessage_used, BufferLength_used, OutMessageAttributes_used, InMessageAttributes_used, Timeout_used); // NtAlpcConnectPortEx

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}
	if (ConnectionMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ConnectionMessage_used, x32based_ConnectionMessage);
	}
	if (x32based_BufferLength != NULL) {
		*((X32_SIZE_T*)x32based_BufferLength) = (X32_SIZE_T)(*(SIZE_T*)BufferLength_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcAcceptConnectPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ConnectionPortHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[5]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_PortAttributes = (uint32_t)(x32based_args[6]); // PALPC_PORT_ATTRIBUTES  IN 
	PVOID PortContext_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	uint32_t x32based_ConnectionRequest = (uint32_t)(x32based_args[8]); // PPORT_MESSAGE  IN 
	PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[9]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	BOOLEAN AcceptConnection_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t PortHandle_holder[sizeof(PVOID)];
	PHANDLE PortHandle_used = (PHANDLE)&PortHandle_holder;
	HANDLE ConnectionPortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ConnectionPortHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t PortAttributes_holder[sizeof(_ALPC_PORT_ATTRIBUTES)];
	PALPC_PORT_ATTRIBUTES PortAttributes_used = (PALPC_PORT_ATTRIBUTES)&PortAttributes_holder;
	uint8_t ConnectionRequest_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ConnectionRequest_used = (PPORT_MESSAGE)&ConnectionRequest_holder;

	// Convert parameters from x32 to x64
	if (x32based_PortHandle == NULL) {
		PortHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_PortAttributes != NULL) {
		convert__ALPC_PORT_ATTRIBUTES_32TO64(ctx, (_ALPC_PORT_ATTRIBUTES**)&PortAttributes_used, x32based_PortAttributes);
	}
	else {
		PortAttributes_used = 0;
	}
	if (x32based_ConnectionRequest != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&ConnectionRequest_used, x32based_ConnectionRequest);
	}
	else {
		ConnectionRequest_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, PortHandle_used, ConnectionPortHandle_used, Flags_used, ObjectAttributes_used, PortAttributes_used, PortContext_used, ConnectionRequest_used, ConnectionMessageAttributes_used, AcceptConnection_used); // NtAlpcAcceptConnectPort

	if (PortHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)PortHandle_used, x32based_PortHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcSendWaitReceivePort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_SendMessageA = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[5]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	uint32_t x32based_ReceiveMessage = (uint32_t)(x32based_args[6]); // PPORT_MESSAGE  OUT 
	uint32_t x32based_BufferLength = (uint32_t)(x32based_args[7]); // PSIZE_T  IN  OUT 
	PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes_used = (PALPC_MESSAGE_ATTRIBUTES)(x32based_args[8]); // PALPC_MESSAGE_ATTRIBUTES  IN  OUT 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[9]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t SendMessageA_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE SendMessageA_used = (PPORT_MESSAGE)&SendMessageA_holder;
	uint8_t ReceiveMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE ReceiveMessage_used = (PPORT_MESSAGE)&ReceiveMessage_holder;
	uint8_t BufferLength_holder[sizeof(long long unsigned int)];
	PSIZE_T BufferLength_used = (PSIZE_T)&BufferLength_holder;

	// Convert parameters from x32 to x64
	if (x32based_SendMessageA != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&SendMessageA_used, x32based_SendMessageA);
	}
	else {
		SendMessageA_used = 0;
	}
	if (x32based_ReceiveMessage == NULL) {
		ReceiveMessage_used = 0;
	}
	if (x32based_BufferLength != NULL) {
		*((SIZE_T*)BufferLength_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BufferLength));
	}
	else {
		BufferLength_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, PortHandle_used, Flags_used, SendMessageA_used, SendMessageAttributes_used, ReceiveMessage_used, BufferLength_used, ReceiveMessageAttributes_used, Timeout_used); // NtAlpcSendWaitReceivePort

	if (ReceiveMessage_used != NULL) {
		convert__PORT_MESSAGE_64TO32(ctx, (_PORT_MESSAGE*)ReceiveMessage_used, x32based_ReceiveMessage);
	}
	if (x32based_BufferLength != NULL) {
		*((X32_SIZE_T*)x32based_BufferLength) = (X32_SIZE_T)(*(SIZE_T*)BufferLength_used);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcCancelMessage(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_MessageContext = (uint32_t)(x32based_args[4]); // PALPC_CONTEXT_ATTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t MessageContext_holder[sizeof(_ALPC_CONTEXT_ATTR)];
	PALPC_CONTEXT_ATTR MessageContext_used = (PALPC_CONTEXT_ATTR)&MessageContext_holder;

	// Convert parameters from x32 to x64
	if (x32based_MessageContext != NULL) {
		convert__ALPC_CONTEXT_ATTR_32TO64(ctx, (_ALPC_CONTEXT_ATTR**)&MessageContext_used, x32based_MessageContext);
	}
	else {
		MessageContext_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Flags_used, MessageContext_used); // NtAlpcCancelMessage

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcImpersonateClientOfPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Message = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	PVOID Flags_used = (PVOID)(x32based_args[4]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t Message_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE Message_used = (PPORT_MESSAGE)&Message_holder;

	// Convert parameters from x32 to x64
	if (x32based_Message != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&Message_used, x32based_Message);
	}
	else {
		Message_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Message_used, Flags_used); // NtAlpcImpersonateClientOfPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcImpersonateClientContainerOfPort(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Message = (uint32_t)(x32based_args[3]); // PPORT_MESSAGE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t Message_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE Message_used = (PPORT_MESSAGE)&Message_holder;

	// Convert parameters from x32 to x64
	if (x32based_Message != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&Message_used, x32based_Message);
	}
	else {
		Message_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, PortHandle_used, Message_used, Flags_used); // NtAlpcImpersonateClientContainerOfPort

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcOpenSenderProcess(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_PortMessage = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[6]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[7]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ProcessHandle_holder[sizeof(PVOID)];
	PHANDLE ProcessHandle_used = (PHANDLE)&ProcessHandle_holder;
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t PortMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE PortMessage_used = (PPORT_MESSAGE)&PortMessage_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ProcessHandle == NULL) {
		ProcessHandle_used = 0;
	}
	if (x32based_PortMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&PortMessage_used, x32based_PortMessage);
	}
	else {
		PortMessage_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, PortHandle_used, PortMessage_used, Flags_used, DesiredAccess_used, ObjectAttributes_used); // NtAlpcOpenSenderProcess

	if (ProcessHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ProcessHandle_used, x32based_ProcessHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAlpcOpenSenderThread(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_PortHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_PortMessage = (uint32_t)(x32based_args[4]); // PPORT_MESSAGE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[6]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[7]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ThreadHandle_holder[sizeof(PVOID)];
	PHANDLE ThreadHandle_used = (PHANDLE)&ThreadHandle_holder;
	HANDLE PortHandle_used = Handle32ToHandle((const void* __ptr32)x32based_PortHandle);
	uint8_t PortMessage_holder[sizeof(_PORT_MESSAGE)];
	PPORT_MESSAGE PortMessage_used = (PPORT_MESSAGE)&PortMessage_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ThreadHandle == NULL) {
		ThreadHandle_used = 0;
	}
	if (x32based_PortMessage != NULL) {
		convert__PORT_MESSAGE_32TO64(ctx, (_PORT_MESSAGE**)&PortMessage_used, x32based_PortMessage);
	}
	else {
		PortMessage_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ThreadHandle_used, PortHandle_used, PortMessage_used, Flags_used, DesiredAccess_used, ObjectAttributes_used); // NtAlpcOpenSenderThread

	if (ThreadHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ThreadHandle_used, x32based_ThreadHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPlugPlayControl(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PLUGPLAY_CONTROL_CLASS PnPControlClass_used = (PLUGPLAY_CONTROL_CLASS)(x32based_args[2]); // PLUGPLAY_CONTROL_CLASS  IN 
	PVOID PnPControlData_used = (PVOID)(x32based_args[3]); // PVOID  IN  OUT 
	ULONG PnPControlDataLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, PnPControlClass_used, PnPControlData_used, PnPControlDataLength_used); // NtPlugPlayControl

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSerializeBoot(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtSerializeBoot

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnableLastKnownGood(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtEnableLastKnownGood

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDisableLastKnownGood(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtDisableLastKnownGood

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplacePartitionUnit(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetInstancePath = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	uint32_t x32based_SpareInstancePath = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetInstancePath_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING TargetInstancePath_used = (PUNICODE_STRING)&TargetInstancePath_holder;
	uint8_t SpareInstancePath_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SpareInstancePath_used = (PUNICODE_STRING)&SpareInstancePath_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetInstancePath != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&TargetInstancePath_used, x32based_TargetInstancePath);
	}
	else {
		TargetInstancePath_used = 0;
	}
	if (x32based_SpareInstancePath != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SpareInstancePath_used, x32based_SpareInstancePath);
	}
	else {
		SpareInstancePath_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, TargetInstancePath_used, SpareInstancePath_used, Flags_used); // NtReplacePartitionUnit

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPowerInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	POWER_INFORMATION_LEVEL InformationLevel_used = (POWER_INFORMATION_LEVEL)(x32based_args[2]); // POWER_INFORMATION_LEVEL  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID OutputBuffer_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG OutputBufferLength_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, InformationLevel_used, InputBuffer_used, InputBufferLength_used, OutputBuffer_used, OutputBufferLength_used); // NtPowerInformation

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetThreadExecutionState(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	EXECUTION_STATE NewFlags_used = (EXECUTION_STATE)(x32based_args[2]); // EXECUTION_STATE  IN 
	EXECUTION_STATE* PreviousFlags_used = (EXECUTION_STATE*)(x32based_args[3]); // EXECUTION_STATE *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, NewFlags_used, PreviousFlags_used); // NtSetThreadExecutionState

	return ret_value;
}


NTSTATUS WINAPI _w32_NtInitiatePowerAction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	POWER_ACTION SystemAction_used = (POWER_ACTION)(x32based_args[2]); // POWER_ACTION  IN 
	SYSTEM_POWER_STATE LightestSystemState_used = (SYSTEM_POWER_STATE)(x32based_args[3]); // SYSTEM_POWER_STATE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	BOOLEAN Asynchronous_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, SystemAction_used, LightestSystemState_used, Flags_used, Asynchronous_used); // NtInitiatePowerAction

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetSystemPowerState(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	POWER_ACTION SystemAction_used = (POWER_ACTION)(x32based_args[2]); // POWER_ACTION  IN 
	SYSTEM_POWER_STATE LightestSystemState_used = (SYSTEM_POWER_STATE)(x32based_args[3]); // SYSTEM_POWER_STATE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, SystemAction_used, LightestSystemState_used, Flags_used); // NtSetSystemPowerState

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetDevicePowerState(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Device = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PDEVICE_POWER_STATE State_used = (PDEVICE_POWER_STATE)(x32based_args[3]); // PDEVICE_POWER_STATE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Device_used = Handle32ToHandle((const void* __ptr32)x32based_Device);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Device_used, State_used); // NtGetDevicePowerState

	return ret_value;
}


BOOLEAN WINAPI _w32_NtIsSystemResumeAutomatic(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	// Declare space used in parameters
	// Convert parameters from x32 to x64
	return (BOOLEAN)__syscall64(syscall_idx, 0); // NtIsSystemResumeAutomatic
}


NTSTATUS WINAPI _w32_NtCreateKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG TitleIndex_used = (ULONG)(x32based_args[5]); // ULONG 
	uint32_t x32based_Class = (uint32_t)(x32based_args[6]); // PUNICODE_STRING  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PULONG Disposition_used = (PULONG)(x32based_args[8]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t Class_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Class_used = (PUNICODE_STRING)&Class_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_Class != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Class_used, x32based_Class);
	}
	else {
		Class_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 7, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used, TitleIndex_used, Class_used, CreateOptions_used, Disposition_used); // NtCreateKey

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateKeyTransacted(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG TitleIndex_used = (ULONG)(x32based_args[5]); // ULONG 
	uint32_t x32based_Class = (uint32_t)(x32based_args[6]); // PUNICODE_STRING  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[8]); // HANDLE  IN 
	PULONG Disposition_used = (PULONG)(x32based_args[9]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t Class_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Class_used = (PUNICODE_STRING)&Class_holder;
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_Class != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Class_used, x32based_Class);
	}
	else {
		Class_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used, TitleIndex_used, Class_used, CreateOptions_used, TransactionHandle_used, Disposition_used); // NtCreateKeyTransacted

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used); // NtOpenKey

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenKeyTransacted(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used, TransactionHandle_used); // NtOpenKeyTransacted

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenKeyEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG OpenOptions_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used, OpenOptions_used); // NtOpenKeyEx

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenKeyTransactedEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	ULONG OpenOptions_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[6]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyHandle_holder[sizeof(PVOID)];
	PHANDLE KeyHandle_used = (PHANDLE)&KeyHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	if (x32based_KeyHandle == NULL) {
		KeyHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, KeyHandle_used, DesiredAccess_used, ObjectAttributes_used, OpenOptions_used, TransactionHandle_used); // NtOpenKeyTransactedEx

	if (KeyHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)KeyHandle_used, x32based_KeyHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, KeyHandle_used); // NtDeleteKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRenameKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_NewName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	uint8_t NewName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING NewName_used = (PUNICODE_STRING)&NewName_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&NewName_used, x32based_NewName);
	}
	else {
		NewName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, KeyHandle_used, NewName_used); // NtRenameKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteValueKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ValueName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	uint8_t ValueName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ValueName_used = (PUNICODE_STRING)&ValueName_holder;

	// Convert parameters from x32 to x64
	if (x32based_ValueName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ValueName_used, x32based_ValueName);
	}
	else {
		ValueName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, KeyHandle_used, ValueName_used); // NtDeleteValueKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	KEY_INFORMATION_CLASS KeyInformationClass_used = (KEY_INFORMATION_CLASS)(x32based_args[3]); // KEY_INFORMATION_CLASS  IN 
	PVOID KeyInformation_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ResultLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	switch (KeyInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 5, KeyHandle_used, KeyInformationClass_used, KeyInformation_used, Length_used, ResultLength_used); // NtQueryKey
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	KEY_SET_INFORMATION_CLASS KeySetInformationClass_used = (KEY_SET_INFORMATION_CLASS)(x32based_args[3]); // KEY_SET_INFORMATION_CLASS  IN 
	PVOID KeySetInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG KeySetInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	switch (KeySetInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 4, KeyHandle_used, KeySetInformationClass_used, KeySetInformation_used, KeySetInformationLength_used); // NtSetInformationKey
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryValueKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ValueName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass_used = (KEY_VALUE_INFORMATION_CLASS)(x32based_args[4]); // KEY_VALUE_INFORMATION_CLASS  IN 
	PVOID KeyValueInformation_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ResultLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	uint8_t ValueName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ValueName_used = (PUNICODE_STRING)&ValueName_holder;

	// Convert parameters from x32 to x64
	if (x32based_ValueName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ValueName_used, x32based_ValueName);
	}
	else {
		ValueName_used = 0;
	}

	switch (KeyValueInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 6, KeyHandle_used, ValueName_used, KeyValueInformationClass_used, KeyValueInformation_used, Length_used, ResultLength_used); // NtQueryValueKey
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetValueKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ValueName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	ULONG TitleIndex_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	ULONG Type_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PVOID Data_used = (PVOID)(x32based_args[6]); // PVOID  IN 
	ULONG DataSize_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	uint8_t ValueName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ValueName_used = (PUNICODE_STRING)&ValueName_holder;

	// Convert parameters from x32 to x64
	if (x32based_ValueName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ValueName_used, x32based_ValueName);
	}
	else {
		ValueName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, KeyHandle_used, ValueName_used, TitleIndex_used, Type_used, Data_used, DataSize_used); // NtSetValueKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryMultipleValueKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_ValueEntries = (uint32_t)(x32based_args[3]); // PKEY_VALUE_ENTRY  IN  OUT 
	ULONG EntryCount_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID ValueBuffer_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	PULONG BufferLength_used = (PULONG)(x32based_args[6]); // PULONG  IN  OUT 
	PULONG RequiredBufferLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	uint8_t ValueEntries_holder[sizeof(_KEY_VALUE_ENTRY)];
	PKEY_VALUE_ENTRY ValueEntries_used = (PKEY_VALUE_ENTRY)&ValueEntries_holder;

	// Convert parameters from x32 to x64
	if (x32based_ValueEntries != NULL) {
		convert__KEY_VALUE_ENTRY_32TO64(ctx, (_KEY_VALUE_ENTRY**)&ValueEntries_used, x32based_ValueEntries);
	}
	else {
		ValueEntries_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, KeyHandle_used, ValueEntries_used, EntryCount_used, ValueBuffer_used, BufferLength_used, RequiredBufferLength_used); // NtQueryMultipleValueKey

	if (ValueEntries_used != NULL) {
		convert__KEY_VALUE_ENTRY_64TO32(ctx, (_KEY_VALUE_ENTRY*)ValueEntries_used, x32based_ValueEntries);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Index_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	KEY_INFORMATION_CLASS KeyInformationClass_used = (KEY_INFORMATION_CLASS)(x32based_args[4]); // KEY_INFORMATION_CLASS  IN 
	PVOID KeyInformation_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ResultLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	switch (KeyInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 6, KeyHandle_used, Index_used, KeyInformationClass_used, KeyInformation_used, Length_used, ResultLength_used); // NtEnumerateKey
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateValueKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Index_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass_used = (KEY_VALUE_INFORMATION_CLASS)(x32based_args[4]); // KEY_VALUE_INFORMATION_CLASS  IN 
	PVOID KeyValueInformation_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ResultLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	switch (KeyValueInformationClass_used) {
	default: {
		ret_value = __syscall64(syscall_idx, 6, KeyHandle_used, Index_used, KeyValueInformationClass_used, KeyValueInformation_used, Length_used, ResultLength_used); // NtEnumerateValueKey
		break;
	}
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, KeyHandle_used); // NtFlushKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCompactKeys(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Count_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	uint32_t x32based_KeyArray = (uint32_t)(x32based_args[3]); // HANDLE *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t KeyArray_holder[sizeof(PVOID)];
	HANDLE* KeyArray_used = (HANDLE*)&KeyArray_holder;

	// Convert parameters from x32 to x64
	if (x32based_KeyArray != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&KeyArray_used, x32based_KeyArray);
	}
	else {
		KeyArray_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, Count_used, KeyArray_used); // NtCompactKeys

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCompressKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_Key = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE Key_used = Handle32ToHandle((const void* __ptr32)x32based_Key);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, Key_used); // NtCompressKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLoadKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_SourceFile = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;
	uint8_t SourceFile_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES SourceFile_used = (POBJECT_ATTRIBUTES)&SourceFile_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}
	if (x32based_SourceFile != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&SourceFile_used, x32based_SourceFile);
	}
	else {
		SourceFile_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, TargetKey_used, SourceFile_used); // NtLoadKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLoadKey2(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_SourceFile = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;
	uint8_t SourceFile_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES SourceFile_used = (POBJECT_ATTRIBUTES)&SourceFile_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}
	if (x32based_SourceFile != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&SourceFile_used, x32based_SourceFile);
	}
	else {
		SourceFile_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, TargetKey_used, SourceFile_used, Flags_used); // NtLoadKey2

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLoadKeyEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_SourceFile = (uint32_t)(x32based_args[3]); // POBJECT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	uint32_t x32based_TrustClassKey = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[6]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[7]); // ACCESS_MASK  IN 
	uint32_t x32based_RootHandle = (uint32_t)(x32based_args[8]); // PHANDLE  OUT 
	uint32_t x32based_IoStatus = (uint32_t)(x32based_args[9]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;
	uint8_t SourceFile_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES SourceFile_used = (POBJECT_ATTRIBUTES)&SourceFile_holder;
	HANDLE TrustClassKey_used = Handle32ToHandle((const void* __ptr32)x32based_TrustClassKey);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t RootHandle_holder[sizeof(PVOID)];
	PHANDLE RootHandle_used = (PHANDLE)&RootHandle_holder;
	uint8_t IoStatus_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatus_used = (PIO_STATUS_BLOCK)&IoStatus_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}
	if (x32based_SourceFile != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&SourceFile_used, x32based_SourceFile);
	}
	else {
		SourceFile_used = 0;
	}
	if (x32based_RootHandle == NULL) {
		RootHandle_used = 0;
	}
	if (x32based_IoStatus == NULL) {
		IoStatus_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, TargetKey_used, SourceFile_used, Flags_used, TrustClassKey_used, Event_used, DesiredAccess_used, RootHandle_used, IoStatus_used); // NtLoadKeyEx

	if (RootHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)RootHandle_used, x32based_RootHandle);
	}
	if (IoStatus_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatus_used, x32based_IoStatus);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReplaceKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_NewFile = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_TargetHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_OldFile = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t NewFile_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES NewFile_used = (POBJECT_ATTRIBUTES)&NewFile_holder;
	HANDLE TargetHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TargetHandle);
	uint8_t OldFile_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES OldFile_used = (POBJECT_ATTRIBUTES)&OldFile_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewFile != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&NewFile_used, x32based_NewFile);
	}
	else {
		NewFile_used = 0;
	}
	if (x32based_OldFile != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&OldFile_used, x32based_OldFile);
	}
	else {
		OldFile_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, NewFile_used, TargetHandle_used, OldFile_used); // NtReplaceKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSaveKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, KeyHandle_used, FileHandle_used); // NtSaveKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSaveKeyEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ULONG Format_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, KeyHandle_used, FileHandle_used, Format_used); // NtSaveKeyEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSaveMergedKeys(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_HighPrecedenceKeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_LowPrecedenceKeyHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE HighPrecedenceKeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_HighPrecedenceKeyHandle);
	HANDLE LowPrecedenceKeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_LowPrecedenceKeyHandle);
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, HighPrecedenceKeyHandle_used, LowPrecedenceKeyHandle_used, FileHandle_used); // NtSaveMergedKeys

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRestoreKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_FileHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[4]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	HANDLE FileHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FileHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, KeyHandle_used, FileHandle_used, Flags_used); // NtRestoreKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnloadKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 1, TargetKey_used); // NtUnloadKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnloadKey2(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, TargetKey_used, Flags_used); // NtUnloadKey2

	return ret_value;
}


NTSTATUS WINAPI _w32_NtUnloadKeyEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, TargetKey_used, Event_used); // NtUnloadKeyEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtNotifyChangeKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[4]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[6]); // PIO_STATUS_BLOCK  OUT 
	ULONG CompletionFilter_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	BOOLEAN WatchTree_used = (BOOLEAN)(x32based_args[8]); // BOOLEAN  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[9]); // PVOID  OUT 
	ULONG BufferSize_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	BOOLEAN Asynchronous_used = (BOOLEAN)(x32based_args[11]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 10, KeyHandle_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, CompletionFilter_used, WatchTree_used, Buffer_used, BufferSize_used, Asynchronous_used); // NtNotifyChangeKey

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtNotifyChangeMultipleKeys(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_MasterKeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Count_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_SubordinateObjects = (uint32_t)(x32based_args[4]); // OBJECT_ATTRIBUTES *  IN 
	uint32_t x32based_Event = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	PIO_APC_ROUTINE ApcRoutine_used = (PIO_APC_ROUTINE)(x32based_args[6]); // PIO_APC_ROUTINE  IN 
	PVOID ApcContext_used = (PVOID)(x32based_args[7]); // PVOID  IN 
	uint32_t x32based_IoStatusBlock = (uint32_t)(x32based_args[8]); // PIO_STATUS_BLOCK  OUT 
	ULONG CompletionFilter_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	BOOLEAN WatchTree_used = (BOOLEAN)(x32based_args[10]); // BOOLEAN  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[11]); // PVOID  OUT 
	ULONG BufferSize_used = (ULONG)(x32based_args[12]); // ULONG  IN 
	BOOLEAN Asynchronous_used = (BOOLEAN)(x32based_args[13]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE MasterKeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_MasterKeyHandle);
	uint8_t SubordinateObjects_holder[sizeof(_OBJECT_ATTRIBUTES)];
	OBJECT_ATTRIBUTES* SubordinateObjects_used = (OBJECT_ATTRIBUTES*)&SubordinateObjects_holder;
	HANDLE Event_used = Handle32ToHandle((const void* __ptr32)x32based_Event);
	uint8_t IoStatusBlock_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatusBlock_used = (PIO_STATUS_BLOCK)&IoStatusBlock_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubordinateObjects != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&SubordinateObjects_used, x32based_SubordinateObjects);
	}
	else {
		SubordinateObjects_used = 0;
	}
	if (x32based_IoStatusBlock == NULL) {
		IoStatusBlock_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 12, MasterKeyHandle_used, Count_used, SubordinateObjects_used, Event_used, ApcRoutine_used, ApcContext_used, IoStatusBlock_used, CompletionFilter_used, WatchTree_used, Buffer_used, BufferSize_used, Asynchronous_used); // NtNotifyChangeMultipleKeys

	if (IoStatusBlock_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatusBlock_used, x32based_IoStatusBlock);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryOpenSubKeys(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	PULONG HandleCount_used = (PULONG)(x32based_args[3]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, TargetKey_used, HandleCount_used); // NtQueryOpenSubKeys

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryOpenSubKeysEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TargetKey = (uint32_t)(x32based_args[2]); // POBJECT_ATTRIBUTES  IN 
	ULONG BufferLength_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	PULONG RequiredSize_used = (PULONG)(x32based_args[5]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TargetKey_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES TargetKey_used = (POBJECT_ATTRIBUTES)&TargetKey_holder;

	// Convert parameters from x32 to x64
	if (x32based_TargetKey != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&TargetKey_used, x32based_TargetKey);
	}
	else {
		TargetKey_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, TargetKey_used, BufferLength_used, Buffer_used, RequiredSize_used); // NtQueryOpenSubKeysEx

	return ret_value;
}


NTSTATUS WINAPI _w32_NtInitializeRegistry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	USHORT BootCondition_used = (USHORT)(x32based_args[2]); // USHORT  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, BootCondition_used); // NtInitializeRegistry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLockRegistryKey(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_KeyHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE KeyHandle_used = Handle32ToHandle((const void* __ptr32)x32based_KeyHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, KeyHandle_used); // NtLockRegistryKey

	return ret_value;
}


NTSTATUS WINAPI _w32_NtLockProductActivationKeys(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG* pPrivateVer_used = (ULONG*)(x32based_args[2]); // ULONG *  IN  OUT 
	ULONG* pSafeMode_used = (ULONG*)(x32based_args[3]); // ULONG *  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, pPrivateVer_used, pSafeMode_used); // NtLockProductActivationKeys

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFreezeRegistry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG TimeOutInSeconds_used = (ULONG)(x32based_args[2]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, TimeOutInSeconds_used); // NtFreezeRegistry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtThawRegistry(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtThawRegistry

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	TOKEN_TYPE TokenType_used = (TOKEN_TYPE)(x32based_args[5]); // TOKEN_TYPE  IN 
	PLUID AuthenticationId_used = (PLUID)(x32based_args[6]); // PLUID  IN 
	PLARGE_INTEGER ExpirationTime_used = (PLARGE_INTEGER)(x32based_args[7]); // PLARGE_INTEGER  IN 
	uint32_t x32based_User = (uint32_t)(x32based_args[8]); // PTOKEN_USER  IN 
	uint32_t x32based_Groups = (uint32_t)(x32based_args[9]); // PTOKEN_GROUPS  IN 
	PTOKEN_PRIVILEGES Privileges_used = (PTOKEN_PRIVILEGES)(x32based_args[10]); // PTOKEN_PRIVILEGES  IN 
	uint32_t x32based_Owner = (uint32_t)(x32based_args[11]); // PTOKEN_OWNER  IN 
	uint32_t x32based_PrimaryGroup = (uint32_t)(x32based_args[12]); // PTOKEN_PRIMARY_GROUP  IN 
	uint32_t x32based_DefaultDacl = (uint32_t)(x32based_args[13]); // PTOKEN_DEFAULT_DACL  IN 
	PTOKEN_SOURCE TokenSource_used = (PTOKEN_SOURCE)(x32based_args[14]); // PTOKEN_SOURCE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t User_holder[sizeof(_TOKEN_USER)];
	PTOKEN_USER User_used = (PTOKEN_USER)&User_holder;
	uint8_t Groups_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS Groups_used = (PTOKEN_GROUPS)&Groups_holder;
	uint8_t Owner_holder[sizeof(_TOKEN_OWNER)];
	PTOKEN_OWNER Owner_used = (PTOKEN_OWNER)&Owner_holder;
	uint8_t PrimaryGroup_holder[sizeof(_TOKEN_PRIMARY_GROUP)];
	PTOKEN_PRIMARY_GROUP PrimaryGroup_used = (PTOKEN_PRIMARY_GROUP)&PrimaryGroup_holder;
	uint8_t DefaultDacl_holder[sizeof(_TOKEN_DEFAULT_DACL)];
	PTOKEN_DEFAULT_DACL DefaultDacl_used = (PTOKEN_DEFAULT_DACL)&DefaultDacl_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_User != NULL) {
		convert__TOKEN_USER_32TO64(ctx, (_TOKEN_USER**)&User_used, x32based_User);
	}
	else {
		User_used = 0;
	}
	if (x32based_Groups != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&Groups_used, x32based_Groups);
	}
	else {
		Groups_used = 0;
	}
	if (x32based_Owner != NULL) {
		convert__TOKEN_OWNER_32TO64(ctx, (_TOKEN_OWNER**)&Owner_used, x32based_Owner);
	}
	else {
		Owner_used = 0;
	}
	if (x32based_PrimaryGroup != NULL) {
		convert__TOKEN_PRIMARY_GROUP_32TO64(ctx, (_TOKEN_PRIMARY_GROUP**)&PrimaryGroup_used, x32based_PrimaryGroup);
	}
	else {
		PrimaryGroup_used = 0;
	}
	if (x32based_DefaultDacl != NULL) {
		convert__TOKEN_DEFAULT_DACL_32TO64(ctx, (_TOKEN_DEFAULT_DACL**)&DefaultDacl_used, x32based_DefaultDacl);
	}
	else {
		DefaultDacl_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 13, TokenHandle_used, DesiredAccess_used, ObjectAttributes_used, TokenType_used, AuthenticationId_used, ExpirationTime_used, User_used, Groups_used, Privileges_used, Owner_used, PrimaryGroup_used, DefaultDacl_used, TokenSource_used); // NtCreateToken

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateLowBoxToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	uint32_t x32based_ExistingTokenHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[4]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[5]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_PackageSid = (uint32_t)(x32based_args[6]); // PSID  IN 
	ULONG CapabilityCount_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_Capabilities = (uint32_t)(x32based_args[8]); // PSID_AND_ATTRIBUTES  IN 
	ULONG HandleCount_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	uint32_t x32based_Handles = (uint32_t)(x32based_args[10]); // HANDLE *  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;
	HANDLE ExistingTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ExistingTokenHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t PackageSid_holder[sizeof(PVOID)];
	PSID PackageSid_used = (PSID)&PackageSid_holder;
	uint8_t Capabilities_holder[sizeof(_SID_AND_ATTRIBUTES)];
	PSID_AND_ATTRIBUTES Capabilities_used = (PSID_AND_ATTRIBUTES)&Capabilities_holder;
	uint8_t Handles_holder[sizeof(PVOID)];
	HANDLE* Handles_used = (HANDLE*)&Handles_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_PackageSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PackageSid_used, x32based_PackageSid);
	}
	else {
		PackageSid_used = 0;
	}
	if (x32based_Capabilities != NULL) {
		convert__SID_AND_ATTRIBUTES_32TO64(ctx, (_SID_AND_ATTRIBUTES**)&Capabilities_used, x32based_Capabilities);
	}
	else {
		Capabilities_used = 0;
	}
	if (x32based_Handles != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&Handles_used, x32based_Handles);
	}
	else {
		Handles_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 9, TokenHandle_used, ExistingTokenHandle_used, DesiredAccess_used, ObjectAttributes_used, PackageSid_used, CapabilityCount_used, Capabilities_used, HandleCount_used, Handles_used); // NtCreateLowBoxToken

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateTokenEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	TOKEN_TYPE TokenType_used = (TOKEN_TYPE)(x32based_args[5]); // TOKEN_TYPE  IN 
	PLUID AuthenticationId_used = (PLUID)(x32based_args[6]); // PLUID  IN 
	PLARGE_INTEGER ExpirationTime_used = (PLARGE_INTEGER)(x32based_args[7]); // PLARGE_INTEGER  IN 
	uint32_t x32based_User = (uint32_t)(x32based_args[8]); // PTOKEN_USER  IN 
	uint32_t x32based_Groups = (uint32_t)(x32based_args[9]); // PTOKEN_GROUPS  IN 
	PTOKEN_PRIVILEGES Privileges_used = (PTOKEN_PRIVILEGES)(x32based_args[10]); // PTOKEN_PRIVILEGES  IN 
	uint32_t x32based_UserAttributes = (uint32_t)(x32based_args[11]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_DeviceAttributes = (uint32_t)(x32based_args[12]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_DeviceGroups = (uint32_t)(x32based_args[13]); // PTOKEN_GROUPS  IN 
	PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy_used = (PTOKEN_MANDATORY_POLICY)(x32based_args[14]); // PTOKEN_MANDATORY_POLICY  IN 
	uint32_t x32based_Owner = (uint32_t)(x32based_args[15]); // PTOKEN_OWNER  IN 
	uint32_t x32based_PrimaryGroup = (uint32_t)(x32based_args[16]); // PTOKEN_PRIMARY_GROUP  IN 
	uint32_t x32based_DefaultDacl = (uint32_t)(x32based_args[17]); // PTOKEN_DEFAULT_DACL  IN 
	PTOKEN_SOURCE TokenSource_used = (PTOKEN_SOURCE)(x32based_args[18]); // PTOKEN_SOURCE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t User_holder[sizeof(_TOKEN_USER)];
	PTOKEN_USER User_used = (PTOKEN_USER)&User_holder;
	uint8_t Groups_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS Groups_used = (PTOKEN_GROUPS)&Groups_holder;
	uint8_t UserAttributes_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&UserAttributes_holder;
	uint8_t DeviceAttributes_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&DeviceAttributes_holder;
	uint8_t DeviceGroups_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS DeviceGroups_used = (PTOKEN_GROUPS)&DeviceGroups_holder;
	uint8_t Owner_holder[sizeof(_TOKEN_OWNER)];
	PTOKEN_OWNER Owner_used = (PTOKEN_OWNER)&Owner_holder;
	uint8_t PrimaryGroup_holder[sizeof(_TOKEN_PRIMARY_GROUP)];
	PTOKEN_PRIMARY_GROUP PrimaryGroup_used = (PTOKEN_PRIMARY_GROUP)&PrimaryGroup_holder;
	uint8_t DefaultDacl_holder[sizeof(_TOKEN_DEFAULT_DACL)];
	PTOKEN_DEFAULT_DACL DefaultDacl_used = (PTOKEN_DEFAULT_DACL)&DefaultDacl_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_User != NULL) {
		convert__TOKEN_USER_32TO64(ctx, (_TOKEN_USER**)&User_used, x32based_User);
	}
	else {
		User_used = 0;
	}
	if (x32based_Groups != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&Groups_used, x32based_Groups);
	}
	else {
		Groups_used = 0;
	}
	if (x32based_UserAttributes != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&UserAttributes_used, x32based_UserAttributes);
	}
	else {
		UserAttributes_used = 0;
	}
	if (x32based_DeviceAttributes != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&DeviceAttributes_used, x32based_DeviceAttributes);
	}
	else {
		DeviceAttributes_used = 0;
	}
	if (x32based_DeviceGroups != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&DeviceGroups_used, x32based_DeviceGroups);
	}
	else {
		DeviceGroups_used = 0;
	}
	if (x32based_Owner != NULL) {
		convert__TOKEN_OWNER_32TO64(ctx, (_TOKEN_OWNER**)&Owner_used, x32based_Owner);
	}
	else {
		Owner_used = 0;
	}
	if (x32based_PrimaryGroup != NULL) {
		convert__TOKEN_PRIMARY_GROUP_32TO64(ctx, (_TOKEN_PRIMARY_GROUP**)&PrimaryGroup_used, x32based_PrimaryGroup);
	}
	else {
		PrimaryGroup_used = 0;
	}
	if (x32based_DefaultDacl != NULL) {
		convert__TOKEN_DEFAULT_DACL_32TO64(ctx, (_TOKEN_DEFAULT_DACL**)&DefaultDacl_used, x32based_DefaultDacl);
	}
	else {
		DefaultDacl_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 17, TokenHandle_used, DesiredAccess_used, ObjectAttributes_used, TokenType_used, AuthenticationId_used, ExpirationTime_used, User_used, Groups_used, Privileges_used, UserAttributes_used, DeviceAttributes_used, DeviceGroups_used, TokenMandatoryPolicy_used, Owner_used, PrimaryGroup_used, DefaultDacl_used, TokenSource_used); // NtCreateTokenEx

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenProcessToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[4]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 3, ProcessHandle_used, DesiredAccess_used, TokenHandle_used); // NtOpenProcessToken

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenProcessTokenEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	ULONG HandleAttributes_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[5]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, DesiredAccess_used, HandleAttributes_used, TokenHandle_used); // NtOpenProcessTokenEx

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenThreadToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	BOOLEAN OpenAsSelf_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[5]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 4, ThreadHandle_used, DesiredAccess_used, OpenAsSelf_used, TokenHandle_used); // NtOpenThreadToken

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenThreadTokenEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	BOOLEAN OpenAsSelf_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	ULONG HandleAttributes_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[6]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);
	uint8_t TokenHandle_holder[sizeof(PVOID)];
	PHANDLE TokenHandle_used = (PHANDLE)&TokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_TokenHandle == NULL) {
		TokenHandle_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 5, ThreadHandle_used, DesiredAccess_used, OpenAsSelf_used, HandleAttributes_used, TokenHandle_used); // NtOpenThreadTokenEx

	if (TokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TokenHandle_used, x32based_TokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDuplicateToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ExistingTokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	BOOLEAN EffectiveOnly_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	TOKEN_TYPE TokenType_used = (TOKEN_TYPE)(x32based_args[6]); // TOKEN_TYPE  IN 
	uint32_t x32based_NewTokenHandle = (uint32_t)(x32based_args[7]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ExistingTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ExistingTokenHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t NewTokenHandle_holder[sizeof(PVOID)];
	PHANDLE NewTokenHandle_used = (PHANDLE)&NewTokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_NewTokenHandle == NULL) {
		NewTokenHandle_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ExistingTokenHandle_used, DesiredAccess_used, ObjectAttributes_used, EffectiveOnly_used, TokenType_used, NewTokenHandle_used); // NtDuplicateToken

	if (NewTokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NewTokenHandle_used, x32based_NewTokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TOKEN_INFORMATION_CLASS TokenInformationClass_used = (TOKEN_INFORMATION_CLASS)(x32based_args[3]); // TOKEN_INFORMATION_CLASS  IN 
	PVOID TokenInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG TokenInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, TokenHandle_used, TokenInformationClass_used, TokenInformation_used, TokenInformationLength_used, ReturnLength_used); // NtQueryInformationToken

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TOKEN_INFORMATION_CLASS TokenInformationClass_used = (TOKEN_INFORMATION_CLASS)(x32based_args[3]); // TOKEN_INFORMATION_CLASS  IN 
	PVOID TokenInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG TokenInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TokenHandle_used, TokenInformationClass_used, TokenInformation_used, TokenInformationLength_used); // NtSetInformationToken

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAdjustPrivilegesToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN DisableAllPrivileges_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	PTOKEN_PRIVILEGES NewState_used = (PTOKEN_PRIVILEGES)(x32based_args[4]); // PTOKEN_PRIVILEGES  IN 
	ULONG BufferLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PTOKEN_PRIVILEGES PreviousState_used = (PTOKEN_PRIVILEGES)(x32based_args[6]); // PTOKEN_PRIVILEGES  OUT 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, TokenHandle_used, DisableAllPrivileges_used, NewState_used, BufferLength_used, PreviousState_used, ReturnLength_used); // NtAdjustPrivilegesToken

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAdjustGroupsToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN ResetToDefault_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	uint32_t x32based_NewState = (uint32_t)(x32based_args[4]); // PTOKEN_GROUPS  IN 
	ULONG BufferLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_PreviousState = (uint32_t)(x32based_args[6]); // PTOKEN_GROUPS  OUT 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);
	uint8_t NewState_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS NewState_used = (PTOKEN_GROUPS)&NewState_holder;
	uint8_t PreviousState_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS PreviousState_used = (PTOKEN_GROUPS)&PreviousState_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewState != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&NewState_used, x32based_NewState);
	}
	else {
		NewState_used = 0;
	}
	if (x32based_PreviousState == NULL) {
		PreviousState_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, TokenHandle_used, ResetToDefault_used, NewState_used, BufferLength_used, PreviousState_used, ReturnLength_used); // NtAdjustGroupsToken

	if (PreviousState_used != NULL) {
		convert__TOKEN_GROUPS_64TO32(ctx, (_TOKEN_GROUPS*)PreviousState_used, x32based_PreviousState);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAdjustTokenClaimsAndDeviceGroups(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN UserResetToDefault_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 
	BOOLEAN DeviceResetToDefault_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 
	BOOLEAN DeviceGroupsResetToDefault_used = (BOOLEAN)(x32based_args[5]); // BOOLEAN  IN 
	uint32_t x32based_NewUserState = (uint32_t)(x32based_args[6]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_NewDeviceState = (uint32_t)(x32based_args[7]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_NewDeviceGroupsState = (uint32_t)(x32based_args[8]); // PTOKEN_GROUPS  IN 
	ULONG UserBufferLength_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	uint32_t x32based_PreviousUserState = (uint32_t)(x32based_args[10]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OUT 
	ULONG DeviceBufferLength_used = (ULONG)(x32based_args[11]); // ULONG  IN 
	uint32_t x32based_PreviousDeviceState = (uint32_t)(x32based_args[12]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  OUT 
	ULONG DeviceGroupsBufferLength_used = (ULONG)(x32based_args[13]); // ULONG  IN 
	uint32_t x32based_PreviousDeviceGroups = (uint32_t)(x32based_args[14]); // PTOKEN_GROUPS  OUT 
	PULONG UserReturnLength_used = (PULONG)(x32based_args[15]); // PULONG  OUT 
	PULONG DeviceReturnLength_used = (PULONG)(x32based_args[16]); // PULONG  OUT 
	PULONG DeviceGroupsReturnBufferLength_used = (PULONG)(x32based_args[17]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);
	uint8_t NewUserState_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&NewUserState_holder;
	uint8_t NewDeviceState_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&NewDeviceState_holder;
	uint8_t NewDeviceGroupsState_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS NewDeviceGroupsState_used = (PTOKEN_GROUPS)&NewDeviceGroupsState_holder;
	uint8_t PreviousUserState_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&PreviousUserState_holder;
	uint8_t PreviousDeviceState_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&PreviousDeviceState_holder;
	uint8_t PreviousDeviceGroups_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS PreviousDeviceGroups_used = (PTOKEN_GROUPS)&PreviousDeviceGroups_holder;

	// Convert parameters from x32 to x64
	if (x32based_NewUserState != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&NewUserState_used, x32based_NewUserState);
	}
	else {
		NewUserState_used = 0;
	}
	if (x32based_NewDeviceState != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&NewDeviceState_used, x32based_NewDeviceState);
	}
	else {
		NewDeviceState_used = 0;
	}
	if (x32based_NewDeviceGroupsState != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&NewDeviceGroupsState_used, x32based_NewDeviceGroupsState);
	}
	else {
		NewDeviceGroupsState_used = 0;
	}
	if (x32based_PreviousUserState == NULL) {
		PreviousUserState_used = 0;
	}
	if (x32based_PreviousDeviceState == NULL) {
		PreviousDeviceState_used = 0;
	}
	if (x32based_PreviousDeviceGroups == NULL) {
		PreviousDeviceGroups_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 16, TokenHandle_used, UserResetToDefault_used, DeviceResetToDefault_used, DeviceGroupsResetToDefault_used, NewUserState_used, NewDeviceState_used, NewDeviceGroupsState_used, UserBufferLength_used, PreviousUserState_used, DeviceBufferLength_used, PreviousDeviceState_used, DeviceGroupsBufferLength_used, PreviousDeviceGroups_used, UserReturnLength_used, DeviceReturnLength_used, DeviceGroupsReturnBufferLength_used); // NtAdjustTokenClaimsAndDeviceGroups

	if (PreviousUserState_used != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_64TO32(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION*)PreviousUserState_used, x32based_PreviousUserState);
	}
	if (PreviousDeviceState_used != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_64TO32(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION*)PreviousDeviceState_used, x32based_PreviousDeviceState);
	}
	if (PreviousDeviceGroups_used != NULL) {
		convert__TOKEN_GROUPS_64TO32(ctx, (_TOKEN_GROUPS*)PreviousDeviceGroups_used, x32based_PreviousDeviceGroups);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFilterToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ExistingTokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_SidsToDisable = (uint32_t)(x32based_args[4]); // PTOKEN_GROUPS  IN 
	PTOKEN_PRIVILEGES PrivilegesToDelete_used = (PTOKEN_PRIVILEGES)(x32based_args[5]); // PTOKEN_PRIVILEGES  IN 
	uint32_t x32based_RestrictedSids = (uint32_t)(x32based_args[6]); // PTOKEN_GROUPS  IN 
	uint32_t x32based_NewTokenHandle = (uint32_t)(x32based_args[7]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ExistingTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ExistingTokenHandle);
	uint8_t SidsToDisable_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS SidsToDisable_used = (PTOKEN_GROUPS)&SidsToDisable_holder;
	uint8_t RestrictedSids_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS RestrictedSids_used = (PTOKEN_GROUPS)&RestrictedSids_holder;
	uint8_t NewTokenHandle_holder[sizeof(PVOID)];
	PHANDLE NewTokenHandle_used = (PHANDLE)&NewTokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_SidsToDisable != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&SidsToDisable_used, x32based_SidsToDisable);
	}
	else {
		SidsToDisable_used = 0;
	}
	if (x32based_RestrictedSids != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&RestrictedSids_used, x32based_RestrictedSids);
	}
	else {
		RestrictedSids_used = 0;
	}
	if (x32based_NewTokenHandle == NULL) {
		NewTokenHandle_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, ExistingTokenHandle_used, Flags_used, SidsToDisable_used, PrivilegesToDelete_used, RestrictedSids_used, NewTokenHandle_used); // NtFilterToken

	if (NewTokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NewTokenHandle_used, x32based_NewTokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFilterTokenEx(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ExistingTokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	uint32_t x32based_SidsToDisable = (uint32_t)(x32based_args[4]); // PTOKEN_GROUPS  IN 
	PTOKEN_PRIVILEGES PrivilegesToDelete_used = (PTOKEN_PRIVILEGES)(x32based_args[5]); // PTOKEN_PRIVILEGES  IN 
	uint32_t x32based_RestrictedSids = (uint32_t)(x32based_args[6]); // PTOKEN_GROUPS  IN 
	ULONG DisableUserClaimsCount_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_UserClaimsToDisable = (uint32_t)(x32based_args[8]); // PUNICODE_STRING  IN 
	ULONG DisableDeviceClaimsCount_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	uint32_t x32based_DeviceClaimsToDisable = (uint32_t)(x32based_args[10]); // PUNICODE_STRING  IN 
	uint32_t x32based_DeviceGroupsToDisable = (uint32_t)(x32based_args[11]); // PTOKEN_GROUPS  IN 
	uint32_t x32based_RestrictedUserAttributes = (uint32_t)(x32based_args[12]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_RestrictedDeviceAttributes = (uint32_t)(x32based_args[13]); // PTOKEN_SECURITY_ATTRIBUTES_INFORMATION  IN 
	uint32_t x32based_RestrictedDeviceGroups = (uint32_t)(x32based_args[14]); // PTOKEN_GROUPS  IN 
	uint32_t x32based_NewTokenHandle = (uint32_t)(x32based_args[15]); // PHANDLE  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ExistingTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ExistingTokenHandle);
	uint8_t SidsToDisable_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS SidsToDisable_used = (PTOKEN_GROUPS)&SidsToDisable_holder;
	uint8_t RestrictedSids_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS RestrictedSids_used = (PTOKEN_GROUPS)&RestrictedSids_holder;
	uint8_t UserClaimsToDisable_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING UserClaimsToDisable_used = (PUNICODE_STRING)&UserClaimsToDisable_holder;
	uint8_t DeviceClaimsToDisable_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING DeviceClaimsToDisable_used = (PUNICODE_STRING)&DeviceClaimsToDisable_holder;
	uint8_t DeviceGroupsToDisable_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS DeviceGroupsToDisable_used = (PTOKEN_GROUPS)&DeviceGroupsToDisable_holder;
	uint8_t RestrictedUserAttributes_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&RestrictedUserAttributes_holder;
	uint8_t RestrictedDeviceAttributes_holder[sizeof(_TOKEN_SECURITY_ATTRIBUTES_INFORMATION)];
	PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes_used = (PTOKEN_SECURITY_ATTRIBUTES_INFORMATION)&RestrictedDeviceAttributes_holder;
	uint8_t RestrictedDeviceGroups_holder[sizeof(_TOKEN_GROUPS)];
	PTOKEN_GROUPS RestrictedDeviceGroups_used = (PTOKEN_GROUPS)&RestrictedDeviceGroups_holder;
	uint8_t NewTokenHandle_holder[sizeof(PVOID)];
	PHANDLE NewTokenHandle_used = (PHANDLE)&NewTokenHandle_holder;

	// Convert parameters from x32 to x64
	if (x32based_SidsToDisable != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&SidsToDisable_used, x32based_SidsToDisable);
	}
	else {
		SidsToDisable_used = 0;
	}
	if (x32based_RestrictedSids != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&RestrictedSids_used, x32based_RestrictedSids);
	}
	else {
		RestrictedSids_used = 0;
	}
	if (x32based_UserClaimsToDisable != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&UserClaimsToDisable_used, x32based_UserClaimsToDisable);
	}
	else {
		UserClaimsToDisable_used = 0;
	}
	if (x32based_DeviceClaimsToDisable != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&DeviceClaimsToDisable_used, x32based_DeviceClaimsToDisable);
	}
	else {
		DeviceClaimsToDisable_used = 0;
	}
	if (x32based_DeviceGroupsToDisable != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&DeviceGroupsToDisable_used, x32based_DeviceGroupsToDisable);
	}
	else {
		DeviceGroupsToDisable_used = 0;
	}
	if (x32based_RestrictedUserAttributes != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&RestrictedUserAttributes_used, x32based_RestrictedUserAttributes);
	}
	else {
		RestrictedUserAttributes_used = 0;
	}
	if (x32based_RestrictedDeviceAttributes != NULL) {
		convert__TOKEN_SECURITY_ATTRIBUTES_INFORMATION_32TO64(ctx, (_TOKEN_SECURITY_ATTRIBUTES_INFORMATION**)&RestrictedDeviceAttributes_used, x32based_RestrictedDeviceAttributes);
	}
	else {
		RestrictedDeviceAttributes_used = 0;
	}
	if (x32based_RestrictedDeviceGroups != NULL) {
		convert__TOKEN_GROUPS_32TO64(ctx, (_TOKEN_GROUPS**)&RestrictedDeviceGroups_used, x32based_RestrictedDeviceGroups);
	}
	else {
		RestrictedDeviceGroups_used = 0;
	}
	if (x32based_NewTokenHandle == NULL) {
		NewTokenHandle_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 14, ExistingTokenHandle_used, Flags_used, SidsToDisable_used, PrivilegesToDelete_used, RestrictedSids_used, DisableUserClaimsCount_used, UserClaimsToDisable_used, DisableDeviceClaimsCount_used, DeviceClaimsToDisable_used, DeviceGroupsToDisable_used, RestrictedUserAttributes_used, RestrictedDeviceAttributes_used, RestrictedDeviceGroups_used, NewTokenHandle_used); // NtFilterTokenEx

	if (NewTokenHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)NewTokenHandle_used, x32based_NewTokenHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCompareTokens(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_FirstTokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_SecondTokenHandle = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	PBOOLEAN Equal_used = (PBOOLEAN)(x32based_args[4]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE FirstTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_FirstTokenHandle);
	HANDLE SecondTokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_SecondTokenHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, FirstTokenHandle_used, SecondTokenHandle_used, Equal_used); // NtCompareTokens

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrivilegeCheck(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PPRIVILEGE_SET RequiredPrivileges_used = (PPRIVILEGE_SET)(x32based_args[3]); // PPRIVILEGE_SET  IN  OUT 
	PBOOLEAN Result_used = (PBOOLEAN)(x32based_args[4]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ClientToken_used, RequiredPrivileges_used, Result_used); // NtPrivilegeCheck

	return ret_value;
}


NTSTATUS WINAPI _w32_NtImpersonateAnonymousToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ThreadHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ThreadHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ThreadHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ThreadHandle_used); // NtImpersonateAnonymousToken

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQuerySecurityAttributesToken(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TokenHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_Attributes = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	ULONG NumberOfAttributes_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[5]); // PVOID  OUT 
	ULONG Length_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TokenHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TokenHandle);
	uint8_t Attributes_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Attributes_used = (PUNICODE_STRING)&Attributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_Attributes != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Attributes_used, x32based_Attributes);
	}
	else {
		Attributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, TokenHandle_used, Attributes_used, NumberOfAttributes_used, Buffer_used, Length_used, ReturnLength_used); // NtQuerySecurityAttributesToken

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheck(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[2]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[3]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[4]); // ACCESS_MASK  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[5]); // PGENERIC_MAPPING  IN 
	PPRIVILEGE_SET PrivilegeSet_used = (PPRIVILEGE_SET)(x32based_args[6]); // PPRIVILEGE_SET  OUT 
	PULONG PrivilegeSetLength_used = (PULONG)(x32based_args[7]); // PULONG  IN  OUT 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[8]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[9]); // PNTSTATUS  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, SecurityDescriptor_used, ClientToken_used, DesiredAccess_used, GenericMapping_used, PrivilegeSet_used, PrivilegeSetLength_used, GrantedAccess_used, AccessStatus_used); // NtAccessCheck

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckByType(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[2]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_PrincipalSelfSid = (uint32_t)(x32based_args[3]); // PSID  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[5]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectTypeList = (uint32_t)(x32based_args[6]); // POBJECT_TYPE_LIST  IN 
	ULONG ObjectTypeListLength_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[8]); // PGENERIC_MAPPING  IN 
	PPRIVILEGE_SET PrivilegeSet_used = (PPRIVILEGE_SET)(x32based_args[9]); // PPRIVILEGE_SET  OUT 
	PULONG PrivilegeSetLength_used = (PULONG)(x32based_args[10]); // PULONG  IN  OUT 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[11]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[12]); // PNTSTATUS  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	uint8_t PrincipalSelfSid_holder[sizeof(PVOID)];
	PSID PrincipalSelfSid_used = (PSID)&PrincipalSelfSid_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);
	uint8_t ObjectTypeList_holder[sizeof(_OBJECT_TYPE_LIST)];
	POBJECT_TYPE_LIST ObjectTypeList_used = (POBJECT_TYPE_LIST)&ObjectTypeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}
	if (x32based_PrincipalSelfSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PrincipalSelfSid_used, x32based_PrincipalSelfSid);
	}
	else {
		PrincipalSelfSid_used = 0;
	}
	if (x32based_ObjectTypeList != NULL) {
		convert__OBJECT_TYPE_LIST_32TO64(ctx, (_OBJECT_TYPE_LIST**)&ObjectTypeList_used, x32based_ObjectTypeList);
	}
	else {
		ObjectTypeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, SecurityDescriptor_used, PrincipalSelfSid_used, ClientToken_used, DesiredAccess_used, ObjectTypeList_used, ObjectTypeListLength_used, GenericMapping_used, PrivilegeSet_used, PrivilegeSetLength_used, GrantedAccess_used, AccessStatus_used); // NtAccessCheckByType

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultList(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[2]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_PrincipalSelfSid = (uint32_t)(x32based_args[3]); // PSID  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[5]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectTypeList = (uint32_t)(x32based_args[6]); // POBJECT_TYPE_LIST  IN 
	ULONG ObjectTypeListLength_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[8]); // PGENERIC_MAPPING  IN 
	PPRIVILEGE_SET PrivilegeSet_used = (PPRIVILEGE_SET)(x32based_args[9]); // PPRIVILEGE_SET  OUT 
	PULONG PrivilegeSetLength_used = (PULONG)(x32based_args[10]); // PULONG  IN  OUT 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[11]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[12]); // PNTSTATUS  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	uint8_t PrincipalSelfSid_holder[sizeof(PVOID)];
	PSID PrincipalSelfSid_used = (PSID)&PrincipalSelfSid_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);
	uint8_t ObjectTypeList_holder[sizeof(_OBJECT_TYPE_LIST)];
	POBJECT_TYPE_LIST ObjectTypeList_used = (POBJECT_TYPE_LIST)&ObjectTypeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}
	if (x32based_PrincipalSelfSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PrincipalSelfSid_used, x32based_PrincipalSelfSid);
	}
	else {
		PrincipalSelfSid_used = 0;
	}
	if (x32based_ObjectTypeList != NULL) {
		convert__OBJECT_TYPE_LIST_32TO64(ctx, (_OBJECT_TYPE_LIST**)&ObjectTypeList_used, x32based_ObjectTypeList);
	}
	else {
		ObjectTypeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, SecurityDescriptor_used, PrincipalSelfSid_used, ClientToken_used, DesiredAccess_used, ObjectTypeList_used, ObjectTypeListLength_used, GenericMapping_used, PrivilegeSet_used, PrivilegeSetLength_used, GrantedAccess_used, AccessStatus_used); // NtAccessCheckByTypeResultList

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetCachedSigningLevel(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	ULONG Flags_used = (ULONG)(x32based_args[2]); // ULONG  IN 
	SE_SIGNING_LEVEL InputSigningLevel_used = (SE_SIGNING_LEVEL)(x32based_args[3]); // SE_SIGNING_LEVEL  IN 
	uint32_t x32based_SourceFiles = (uint32_t)(x32based_args[4]); // PHANDLE  IN 
	ULONG SourceFileCount_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	uint32_t x32based_TargetFile = (uint32_t)(x32based_args[6]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SourceFiles_holder[sizeof(PVOID)];
	PHANDLE SourceFiles_used = (PHANDLE)&SourceFiles_holder;
	HANDLE TargetFile_used = Handle32ToHandle((const void* __ptr32)x32based_TargetFile);

	// Convert parameters from x32 to x64
	if (x32based_SourceFiles != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SourceFiles_used, x32based_SourceFiles);
	}
	else {
		SourceFiles_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, Flags_used, InputSigningLevel_used, SourceFiles_used, SourceFileCount_used, TargetFile_used); // NtSetCachedSigningLevel

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetCachedSigningLevel(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_File = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PULONG Flags_used = (PULONG)(x32based_args[3]); // PULONG  OUT 
	PSE_SIGNING_LEVEL SigningLevel_used = (PSE_SIGNING_LEVEL)(x32based_args[4]); // PSE_SIGNING_LEVEL  OUT 
	PUCHAR Thumbprint_used = (PUCHAR)(x32based_args[5]); // PUCHAR  IN  OUT 
	PULONG ThumbprintSize_used = (PULONG)(x32based_args[6]); // PULONG  IN  OUT 
	PULONG ThumbprintAlgorithm_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE File_used = Handle32ToHandle((const void* __ptr32)x32based_File);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, File_used, Flags_used, SigningLevel_used, Thumbprint_used, ThumbprintSize_used, ThumbprintAlgorithm_used); // NtGetCachedSigningLevel

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckAndAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ObjectTypeName = (uint32_t)(x32based_args[4]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[6]); // PSECURITY_DESCRIPTOR  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[7]); // ACCESS_MASK  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[8]); // PGENERIC_MAPPING  IN 
	BOOLEAN ObjectCreation_used = (BOOLEAN)(x32based_args[9]); // BOOLEAN  IN 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[10]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[11]); // PNTSTATUS  OUT 
	PBOOLEAN GenerateOnClose_used = (PBOOLEAN)(x32based_args[12]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	uint8_t ObjectTypeName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectTypeName_used = (PUNICODE_STRING)&ObjectTypeName_holder;
	uint8_t ObjectName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectName_used = (PUNICODE_STRING)&ObjectName_holder;
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ObjectTypeName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectTypeName_used, x32based_ObjectTypeName);
	}
	else {
		ObjectTypeName_used = 0;
	}
	if (x32based_ObjectName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectName_used, x32based_ObjectName);
	}
	else {
		ObjectName_used = 0;
	}
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 11, SubsystemName_used, HandleId_used, ObjectTypeName_used, ObjectName_used, SecurityDescriptor_used, DesiredAccess_used, GenericMapping_used, ObjectCreation_used, GrantedAccess_used, AccessStatus_used, GenerateOnClose_used); // NtAccessCheckAndAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckByTypeAndAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ObjectTypeName = (uint32_t)(x32based_args[4]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[6]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_PrincipalSelfSid = (uint32_t)(x32based_args[7]); // PSID  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[8]); // ACCESS_MASK  IN 
	AUDIT_EVENT_TYPE AuditType_used = (AUDIT_EVENT_TYPE)(x32based_args[9]); // AUDIT_EVENT_TYPE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	uint32_t x32based_ObjectTypeList = (uint32_t)(x32based_args[11]); // POBJECT_TYPE_LIST  IN 
	ULONG ObjectTypeListLength_used = (ULONG)(x32based_args[12]); // ULONG  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[13]); // PGENERIC_MAPPING  IN 
	BOOLEAN ObjectCreation_used = (BOOLEAN)(x32based_args[14]); // BOOLEAN  IN 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[15]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[16]); // PNTSTATUS  OUT 
	PBOOLEAN GenerateOnClose_used = (PBOOLEAN)(x32based_args[17]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	uint8_t ObjectTypeName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectTypeName_used = (PUNICODE_STRING)&ObjectTypeName_holder;
	uint8_t ObjectName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectName_used = (PUNICODE_STRING)&ObjectName_holder;
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	uint8_t PrincipalSelfSid_holder[sizeof(PVOID)];
	PSID PrincipalSelfSid_used = (PSID)&PrincipalSelfSid_holder;
	uint8_t ObjectTypeList_holder[sizeof(_OBJECT_TYPE_LIST)];
	POBJECT_TYPE_LIST ObjectTypeList_used = (POBJECT_TYPE_LIST)&ObjectTypeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ObjectTypeName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectTypeName_used, x32based_ObjectTypeName);
	}
	else {
		ObjectTypeName_used = 0;
	}
	if (x32based_ObjectName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectName_used, x32based_ObjectName);
	}
	else {
		ObjectName_used = 0;
	}
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}
	if (x32based_PrincipalSelfSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PrincipalSelfSid_used, x32based_PrincipalSelfSid);
	}
	else {
		PrincipalSelfSid_used = 0;
	}
	if (x32based_ObjectTypeList != NULL) {
		convert__OBJECT_TYPE_LIST_32TO64(ctx, (_OBJECT_TYPE_LIST**)&ObjectTypeList_used, x32based_ObjectTypeList);
	}
	else {
		ObjectTypeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 16, SubsystemName_used, HandleId_used, ObjectTypeName_used, ObjectName_used, SecurityDescriptor_used, PrincipalSelfSid_used, DesiredAccess_used, AuditType_used, Flags_used, ObjectTypeList_used, ObjectTypeListLength_used, GenericMapping_used, ObjectCreation_used, GrantedAccess_used, AccessStatus_used, GenerateOnClose_used); // NtAccessCheckByTypeAndAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultListAndAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ObjectTypeName = (uint32_t)(x32based_args[4]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[6]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_PrincipalSelfSid = (uint32_t)(x32based_args[7]); // PSID  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[8]); // ACCESS_MASK  IN 
	AUDIT_EVENT_TYPE AuditType_used = (AUDIT_EVENT_TYPE)(x32based_args[9]); // AUDIT_EVENT_TYPE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[10]); // ULONG  IN 
	uint32_t x32based_ObjectTypeList = (uint32_t)(x32based_args[11]); // POBJECT_TYPE_LIST  IN 
	ULONG ObjectTypeListLength_used = (ULONG)(x32based_args[12]); // ULONG  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[13]); // PGENERIC_MAPPING  IN 
	BOOLEAN ObjectCreation_used = (BOOLEAN)(x32based_args[14]); // BOOLEAN  IN 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[15]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[16]); // PNTSTATUS  OUT 
	PBOOLEAN GenerateOnClose_used = (PBOOLEAN)(x32based_args[17]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	uint8_t ObjectTypeName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectTypeName_used = (PUNICODE_STRING)&ObjectTypeName_holder;
	uint8_t ObjectName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectName_used = (PUNICODE_STRING)&ObjectName_holder;
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	uint8_t PrincipalSelfSid_holder[sizeof(PVOID)];
	PSID PrincipalSelfSid_used = (PSID)&PrincipalSelfSid_holder;
	uint8_t ObjectTypeList_holder[sizeof(_OBJECT_TYPE_LIST)];
	POBJECT_TYPE_LIST ObjectTypeList_used = (POBJECT_TYPE_LIST)&ObjectTypeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ObjectTypeName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectTypeName_used, x32based_ObjectTypeName);
	}
	else {
		ObjectTypeName_used = 0;
	}
	if (x32based_ObjectName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectName_used, x32based_ObjectName);
	}
	else {
		ObjectName_used = 0;
	}
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}
	if (x32based_PrincipalSelfSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PrincipalSelfSid_used, x32based_PrincipalSelfSid);
	}
	else {
		PrincipalSelfSid_used = 0;
	}
	if (x32based_ObjectTypeList != NULL) {
		convert__OBJECT_TYPE_LIST_32TO64(ctx, (_OBJECT_TYPE_LIST**)&ObjectTypeList_used, x32based_ObjectTypeList);
	}
	else {
		ObjectTypeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 16, SubsystemName_used, HandleId_used, ObjectTypeName_used, ObjectName_used, SecurityDescriptor_used, PrincipalSelfSid_used, DesiredAccess_used, AuditType_used, Flags_used, ObjectTypeList_used, ObjectTypeListLength_used, GenericMapping_used, ObjectCreation_used, GrantedAccess_used, AccessStatus_used, GenerateOnClose_used); // NtAccessCheckByTypeResultListAndAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtAccessCheckByTypeResultListAndAuditAlarmByHandle(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	uint32_t x32based_ObjectTypeName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectName = (uint32_t)(x32based_args[6]); // PUNICODE_STRING  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[7]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_PrincipalSelfSid = (uint32_t)(x32based_args[8]); // PSID  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[9]); // ACCESS_MASK  IN 
	AUDIT_EVENT_TYPE AuditType_used = (AUDIT_EVENT_TYPE)(x32based_args[10]); // AUDIT_EVENT_TYPE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[11]); // ULONG  IN 
	uint32_t x32based_ObjectTypeList = (uint32_t)(x32based_args[12]); // POBJECT_TYPE_LIST  IN 
	ULONG ObjectTypeListLength_used = (ULONG)(x32based_args[13]); // ULONG  IN 
	PGENERIC_MAPPING GenericMapping_used = (PGENERIC_MAPPING)(x32based_args[14]); // PGENERIC_MAPPING  IN 
	BOOLEAN ObjectCreation_used = (BOOLEAN)(x32based_args[15]); // BOOLEAN  IN 
	PACCESS_MASK GrantedAccess_used = (PACCESS_MASK)(x32based_args[16]); // PACCESS_MASK  OUT 
	PNTSTATUS AccessStatus_used = (PNTSTATUS)(x32based_args[17]); // PNTSTATUS  OUT 
	PBOOLEAN GenerateOnClose_used = (PBOOLEAN)(x32based_args[18]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);
	uint8_t ObjectTypeName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectTypeName_used = (PUNICODE_STRING)&ObjectTypeName_holder;
	uint8_t ObjectName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectName_used = (PUNICODE_STRING)&ObjectName_holder;
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	uint8_t PrincipalSelfSid_holder[sizeof(PVOID)];
	PSID PrincipalSelfSid_used = (PSID)&PrincipalSelfSid_holder;
	uint8_t ObjectTypeList_holder[sizeof(_OBJECT_TYPE_LIST)];
	POBJECT_TYPE_LIST ObjectTypeList_used = (POBJECT_TYPE_LIST)&ObjectTypeList_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ObjectTypeName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectTypeName_used, x32based_ObjectTypeName);
	}
	else {
		ObjectTypeName_used = 0;
	}
	if (x32based_ObjectName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectName_used, x32based_ObjectName);
	}
	else {
		ObjectName_used = 0;
	}
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}
	if (x32based_PrincipalSelfSid != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&PrincipalSelfSid_used, x32based_PrincipalSelfSid);
	}
	else {
		PrincipalSelfSid_used = 0;
	}
	if (x32based_ObjectTypeList != NULL) {
		convert__OBJECT_TYPE_LIST_32TO64(ctx, (_OBJECT_TYPE_LIST**)&ObjectTypeList_used, x32based_ObjectTypeList);
	}
	else {
		ObjectTypeList_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 17, SubsystemName_used, HandleId_used, ClientToken_used, ObjectTypeName_used, ObjectName_used, SecurityDescriptor_used, PrincipalSelfSid_used, DesiredAccess_used, AuditType_used, Flags_used, ObjectTypeList_used, ObjectTypeListLength_used, GenericMapping_used, ObjectCreation_used, GrantedAccess_used, AccessStatus_used, GenerateOnClose_used); // NtAccessCheckByTypeResultListAndAuditAlarmByHandle

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenObjectAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ObjectTypeName = (uint32_t)(x32based_args[4]); // PUNICODE_STRING  IN 
	uint32_t x32based_ObjectName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	uint32_t x32based_SecurityDescriptor = (uint32_t)(x32based_args[6]); // PSECURITY_DESCRIPTOR  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[7]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[8]); // ACCESS_MASK  IN 
	ACCESS_MASK GrantedAccess_used = (ACCESS_MASK)(x32based_args[9]); // ACCESS_MASK  IN 
	PPRIVILEGE_SET Privileges_used = (PPRIVILEGE_SET)(x32based_args[10]); // PPRIVILEGE_SET  IN 
	BOOLEAN ObjectCreation_used = (BOOLEAN)(x32based_args[11]); // BOOLEAN  IN 
	BOOLEAN AccessGranted_used = (BOOLEAN)(x32based_args[12]); // BOOLEAN  IN 
	PBOOLEAN GenerateOnClose_used = (PBOOLEAN)(x32based_args[13]); // PBOOLEAN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	uint8_t ObjectTypeName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectTypeName_used = (PUNICODE_STRING)&ObjectTypeName_holder;
	uint8_t ObjectName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ObjectName_used = (PUNICODE_STRING)&ObjectName_holder;
	uint8_t SecurityDescriptor_holder[sizeof(PVOID)];
	PSECURITY_DESCRIPTOR SecurityDescriptor_used = (PSECURITY_DESCRIPTOR)&SecurityDescriptor_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ObjectTypeName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectTypeName_used, x32based_ObjectTypeName);
	}
	else {
		ObjectTypeName_used = 0;
	}
	if (x32based_ObjectName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ObjectName_used, x32based_ObjectName);
	}
	else {
		ObjectName_used = 0;
	}
	if (x32based_SecurityDescriptor != NULL) {
		convert_HANDLE_32TO64(ctx, (HANDLE**)&SecurityDescriptor_used, x32based_SecurityDescriptor);
	}
	else {
		SecurityDescriptor_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 12, SubsystemName_used, HandleId_used, ObjectTypeName_used, ObjectName_used, SecurityDescriptor_used, ClientToken_used, DesiredAccess_used, GrantedAccess_used, Privileges_used, ObjectCreation_used, AccessGranted_used, GenerateOnClose_used); // NtOpenObjectAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrivilegeObjectAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[5]); // ACCESS_MASK  IN 
	PPRIVILEGE_SET Privileges_used = (PPRIVILEGE_SET)(x32based_args[6]); // PPRIVILEGE_SET  IN 
	BOOLEAN AccessGranted_used = (BOOLEAN)(x32based_args[7]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, SubsystemName_used, HandleId_used, ClientToken_used, DesiredAccess_used, Privileges_used, AccessGranted_used); // NtPrivilegeObjectAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCloseObjectAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	BOOLEAN GenerateOnClose_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SubsystemName_used, HandleId_used, GenerateOnClose_used); // NtCloseObjectAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtDeleteObjectAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	PVOID HandleId_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	BOOLEAN GenerateOnClose_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, SubsystemName_used, HandleId_used, GenerateOnClose_used); // NtDeleteObjectAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrivilegedServiceAuditAlarm(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_SubsystemName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	uint32_t x32based_ServiceName = (uint32_t)(x32based_args[3]); // PUNICODE_STRING  IN 
	uint32_t x32based_ClientToken = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	PPRIVILEGE_SET Privileges_used = (PPRIVILEGE_SET)(x32based_args[5]); // PPRIVILEGE_SET  IN 
	BOOLEAN AccessGranted_used = (BOOLEAN)(x32based_args[6]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t SubsystemName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING SubsystemName_used = (PUNICODE_STRING)&SubsystemName_holder;
	uint8_t ServiceName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING ServiceName_used = (PUNICODE_STRING)&ServiceName_holder;
	HANDLE ClientToken_used = Handle32ToHandle((const void* __ptr32)x32based_ClientToken);

	// Convert parameters from x32 to x64
	if (x32based_SubsystemName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&SubsystemName_used, x32based_SubsystemName);
	}
	else {
		SubsystemName_used = 0;
	}
	if (x32based_ServiceName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&ServiceName_used, x32based_ServiceName);
	}
	else {
		ServiceName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, SubsystemName_used, ServiceName_used, ClientToken_used, Privileges_used, AccessGranted_used); // NtPrivilegedServiceAuditAlarm

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_LogFileName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG CommitStrength_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TmHandle_holder[sizeof(PVOID)];
	PHANDLE TmHandle_used = (PHANDLE)&TmHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t LogFileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING LogFileName_used = (PUNICODE_STRING)&LogFileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_TmHandle == NULL) {
		TmHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_LogFileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&LogFileName_used, x32based_LogFileName);
	}
	else {
		LogFileName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, TmHandle_used, DesiredAccess_used, ObjectAttributes_used, LogFileName_used, CreateOptions_used, CommitStrength_used); // NtCreateTransactionManager

	if (TmHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TmHandle_used, x32based_TmHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	uint32_t x32based_LogFileName = (uint32_t)(x32based_args[5]); // PUNICODE_STRING  IN 
	LPGUID TmIdentity_used = (LPGUID)(x32based_args[6]); // LPGUID  IN 
	ULONG OpenOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TmHandle_holder[sizeof(PVOID)];
	PHANDLE TmHandle_used = (PHANDLE)&TmHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t LogFileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING LogFileName_used = (PUNICODE_STRING)&LogFileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_TmHandle == NULL) {
		TmHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_LogFileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&LogFileName_used, x32based_LogFileName);
	}
	else {
		LogFileName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 6, TmHandle_used, DesiredAccess_used, ObjectAttributes_used, LogFileName_used, TmIdentity_used, OpenOptions_used); // NtOpenTransactionManager

	if (TmHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TmHandle_used, x32based_TmHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRenameTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_LogFileName = (uint32_t)(x32based_args[2]); // PUNICODE_STRING  IN 
	LPGUID ExistingTransactionManagerGuid_used = (LPGUID)(x32based_args[3]); // LPGUID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t LogFileName_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING LogFileName_used = (PUNICODE_STRING)&LogFileName_holder;

	// Convert parameters from x32 to x64
	if (x32based_LogFileName != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&LogFileName_used, x32based_LogFileName);
	}
	else {
		LogFileName_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 2, LogFileName_used, ExistingTransactionManagerGuid_used); // NtRenameTransactionManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRollforwardTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TransactionManagerHandle_used, TmVirtualClock_used); // NtRollforwardTransactionManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRecoverTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, TransactionManagerHandle_used); // NtRecoverTransactionManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass_used = (TRANSACTIONMANAGER_INFORMATION_CLASS)(x32based_args[3]); // TRANSACTIONMANAGER_INFORMATION_CLASS  IN 
	PVOID TransactionManagerInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG TransactionManagerInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, TransactionManagerHandle_used, TransactionManagerInformationClass_used, TransactionManagerInformation_used, TransactionManagerInformationLength_used, ReturnLength_used); // NtQueryInformationTransactionManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationTransactionManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass_used = (TRANSACTIONMANAGER_INFORMATION_CLASS)(x32based_args[3]); // TRANSACTIONMANAGER_INFORMATION_CLASS  IN 
	PVOID TransactionManagerInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG TransactionManagerInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TmHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TmHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TmHandle_used, TransactionManagerInformationClass_used, TransactionManagerInformation_used, TransactionManagerInformationLength_used); // NtSetInformationTransactionManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtEnumerateTransactionObject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_RootObjectHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	KTMOBJECT_TYPE QueryType_used = (KTMOBJECT_TYPE)(x32based_args[3]); // KTMOBJECT_TYPE  IN 
	PKTMOBJECT_CURSOR ObjectCursor_used = (PKTMOBJECT_CURSOR)(x32based_args[4]); // PKTMOBJECT_CURSOR  IN  OUT 
	ULONG ObjectCursorLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE RootObjectHandle_used = Handle32ToHandle((const void* __ptr32)x32based_RootObjectHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, RootObjectHandle_used, QueryType_used, ObjectCursor_used, ObjectCursorLength_used, ReturnLength_used); // NtEnumerateTransactionObject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	LPGUID Uow_used = (LPGUID)(x32based_args[5]); // LPGUID  IN 
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[6]); // HANDLE  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG IsolationLevel_used = (ULONG)(x32based_args[8]); // ULONG  IN 
	ULONG IsolationFlags_used = (ULONG)(x32based_args[9]); // ULONG  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[10]); // PLARGE_INTEGER  IN 
	uint32_t x32based_Description = (uint32_t)(x32based_args[11]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TransactionHandle_holder[sizeof(PVOID)];
	PHANDLE TransactionHandle_used = (PHANDLE)&TransactionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE TmHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TmHandle);
	uint8_t Description_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Description_used = (PUNICODE_STRING)&Description_holder;

	// Convert parameters from x32 to x64
	if (x32based_TransactionHandle == NULL) {
		TransactionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_Description != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Description_used, x32based_Description);
	}
	else {
		Description_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 10, TransactionHandle_used, DesiredAccess_used, ObjectAttributes_used, Uow_used, TmHandle_used, CreateOptions_used, IsolationLevel_used, IsolationFlags_used, Timeout_used, Description_used); // NtCreateTransaction

	if (TransactionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TransactionHandle_used, x32based_TransactionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[4]); // POBJECT_ATTRIBUTES  IN 
	LPGUID Uow_used = (LPGUID)(x32based_args[5]); // LPGUID  IN 
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[6]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t TransactionHandle_holder[sizeof(PVOID)];
	PHANDLE TransactionHandle_used = (PHANDLE)&TransactionHandle_holder;
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	HANDLE TmHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TmHandle);

	// Convert parameters from x32 to x64
	if (x32based_TransactionHandle == NULL) {
		TransactionHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, TransactionHandle_used, DesiredAccess_used, ObjectAttributes_used, Uow_used, TmHandle_used); // NtOpenTransaction

	if (TransactionHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)TransactionHandle_used, x32based_TransactionHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TRANSACTION_INFORMATION_CLASS TransactionInformationClass_used = (TRANSACTION_INFORMATION_CLASS)(x32based_args[3]); // TRANSACTION_INFORMATION_CLASS  IN 
	PVOID TransactionInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG TransactionInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, TransactionHandle_used, TransactionInformationClass_used, TransactionInformation_used, TransactionInformationLength_used, ReturnLength_used); // NtQueryInformationTransaction

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	TRANSACTION_INFORMATION_CLASS TransactionInformationClass_used = (TRANSACTION_INFORMATION_CLASS)(x32based_args[3]); // TRANSACTION_INFORMATION_CLASS  IN 
	PVOID TransactionInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG TransactionInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TransactionHandle_used, TransactionInformationClass_used, TransactionInformation_used, TransactionInformationLength_used); // NtSetInformationTransaction

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCommitTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN Wait_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TransactionHandle_used, Wait_used); // NtCommitTransaction

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRollbackTransaction(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	BOOLEAN Wait_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, TransactionHandle_used, Wait_used); // NtRollbackTransaction

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	uint32_t x32based_TransactionHandle = (uint32_t)(x32based_args[5]); // HANDLE  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[6]); // POBJECT_ATTRIBUTES  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	NOTIFICATION_MASK NotificationMask_used = (NOTIFICATION_MASK)(x32based_args[8]); // NOTIFICATION_MASK  IN 
	PVOID EnlistmentKey_used = (PVOID)(x32based_args[9]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EnlistmentHandle_holder[sizeof(PVOID)];
	PHANDLE EnlistmentHandle_used = (PHANDLE)&EnlistmentHandle_holder;
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);
	HANDLE TransactionHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TransactionHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EnlistmentHandle == NULL) {
		EnlistmentHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 8, EnlistmentHandle_used, DesiredAccess_used, ResourceManagerHandle_used, TransactionHandle_used, ObjectAttributes_used, CreateOptions_used, NotificationMask_used, EnlistmentKey_used); // NtCreateEnlistment

	if (EnlistmentHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EnlistmentHandle_used, x32based_EnlistmentHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	LPGUID EnlistmentGuid_used = (LPGUID)(x32based_args[5]); // LPGUID  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[6]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t EnlistmentHandle_holder[sizeof(PVOID)];
	PHANDLE EnlistmentHandle_used = (PHANDLE)&EnlistmentHandle_holder;
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_EnlistmentHandle == NULL) {
		EnlistmentHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, EnlistmentHandle_used, DesiredAccess_used, ResourceManagerHandle_used, EnlistmentGuid_used, ObjectAttributes_used); // NtOpenEnlistment

	if (EnlistmentHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)EnlistmentHandle_used, x32based_EnlistmentHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass_used = (ENLISTMENT_INFORMATION_CLASS)(x32based_args[3]); // ENLISTMENT_INFORMATION_CLASS  IN 
	PVOID EnlistmentInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG EnlistmentInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, EnlistmentHandle_used, EnlistmentInformationClass_used, EnlistmentInformation_used, EnlistmentInformationLength_used, ReturnLength_used); // NtQueryInformationEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass_used = (ENLISTMENT_INFORMATION_CLASS)(x32based_args[3]); // ENLISTMENT_INFORMATION_CLASS  IN 
	PVOID EnlistmentInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG EnlistmentInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, EnlistmentHandle_used, EnlistmentInformationClass_used, EnlistmentInformation_used, EnlistmentInformationLength_used); // NtSetInformationEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRecoverEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID EnlistmentKey_used = (PVOID)(x32based_args[3]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, EnlistmentKey_used); // NtRecoverEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrePrepareEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtPrePrepareEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrepareEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtPrepareEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCommitEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtCommitEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRollbackEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtRollbackEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrePrepareComplete(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtPrePrepareComplete

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPrepareComplete(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtPrepareComplete

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCommitComplete(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtCommitComplete

	return ret_value;
}


NTSTATUS WINAPI _w32_NtReadOnlyEnlistment(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtReadOnlyEnlistment

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRollbackComplete(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtRollbackComplete

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSinglePhaseReject(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_EnlistmentHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PLARGE_INTEGER TmVirtualClock_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE EnlistmentHandle_used = Handle32ToHandle((const void* __ptr32)x32based_EnlistmentHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, EnlistmentHandle_used, TmVirtualClock_used); // NtSinglePhaseReject

	return ret_value;
}


NTSTATUS WINAPI _w32_NtCreateResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	LPGUID RmGuid_used = (LPGUID)(x32based_args[5]); // LPGUID  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[6]); // POBJECT_ATTRIBUTES  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	uint32_t x32based_Description = (uint32_t)(x32based_args[8]); // PUNICODE_STRING  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ResourceManagerHandle_holder[sizeof(PVOID)];
	PHANDLE ResourceManagerHandle_used = (PHANDLE)&ResourceManagerHandle_holder;
	HANDLE TmHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TmHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;
	uint8_t Description_holder[sizeof(_UNICODE_STRING)];
	PUNICODE_STRING Description_used = (PUNICODE_STRING)&Description_holder;

	// Convert parameters from x32 to x64
	if (x32based_ResourceManagerHandle == NULL) {
		ResourceManagerHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}
	if (x32based_Description != NULL) {
		convert__UNICODE_STRING_32TO64(ctx, (_UNICODE_STRING**)&Description_used, x32based_Description);
	}
	else {
		Description_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 7, ResourceManagerHandle_used, DesiredAccess_used, TmHandle_used, RmGuid_used, ObjectAttributes_used, CreateOptions_used, Description_used); // NtCreateResourceManager

	if (ResourceManagerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ResourceManagerHandle_used, x32based_ResourceManagerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtOpenResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // PHANDLE  OUT 
	ACCESS_MASK DesiredAccess_used = (ACCESS_MASK)(x32based_args[3]); // ACCESS_MASK  IN 
	uint32_t x32based_TmHandle = (uint32_t)(x32based_args[4]); // HANDLE  IN 
	LPGUID ResourceManagerGuid_used = (LPGUID)(x32based_args[5]); // LPGUID  IN 
	uint32_t x32based_ObjectAttributes = (uint32_t)(x32based_args[6]); // POBJECT_ATTRIBUTES  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ResourceManagerHandle_holder[sizeof(PVOID)];
	PHANDLE ResourceManagerHandle_used = (PHANDLE)&ResourceManagerHandle_holder;
	HANDLE TmHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TmHandle);
	uint8_t ObjectAttributes_holder[sizeof(_OBJECT_ATTRIBUTES)];
	POBJECT_ATTRIBUTES ObjectAttributes_used = (POBJECT_ATTRIBUTES)&ObjectAttributes_holder;

	// Convert parameters from x32 to x64
	if (x32based_ResourceManagerHandle == NULL) {
		ResourceManagerHandle_used = 0;
	}
	if (x32based_ObjectAttributes != NULL) {
		convert__OBJECT_ATTRIBUTES_32TO64(ctx, (_OBJECT_ATTRIBUTES**)&ObjectAttributes_used, x32based_ObjectAttributes);
	}
	else {
		ObjectAttributes_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 5, ResourceManagerHandle_used, DesiredAccess_used, TmHandle_used, ResourceManagerGuid_used, ObjectAttributes_used); // NtOpenResourceManager

	if (ResourceManagerHandle_used != NULL) {
		convert_HANDLE_64TO32(ctx, (HANDLE*)ResourceManagerHandle_used, x32based_ResourceManagerHandle);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRecoverResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 1, ResourceManagerHandle_used); // NtRecoverResourceManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtGetNotificationResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_TransactionNotification = (uint32_t)(x32based_args[3]); // PTRANSACTION_NOTIFICATION  OUT 
	ULONG NotificationLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PLARGE_INTEGER Timeout_used = (PLARGE_INTEGER)(x32based_args[5]); // PLARGE_INTEGER  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 
	ULONG Asynchronous_used = (ULONG)(x32based_args[7]); // ULONG  IN 
	ULONG_PTR AsynchronousContext_used = (ULONG_PTR)(x32based_args[8]); // ULONG_PTR  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);
	uint8_t TransactionNotification_holder[sizeof(_TRANSACTION_NOTIFICATION)];
	PTRANSACTION_NOTIFICATION TransactionNotification_used = (PTRANSACTION_NOTIFICATION)&TransactionNotification_holder;

	// Convert parameters from x32 to x64
	if (x32based_TransactionNotification == NULL) {
		TransactionNotification_used = 0;
	}
	ret_value = __syscall64(syscall_idx, 7, ResourceManagerHandle_used, TransactionNotification_used, NotificationLength_used, Timeout_used, ReturnLength_used, Asynchronous_used, AsynchronousContext_used); // NtGetNotificationResourceManager

	if (TransactionNotification_used != NULL) {
		convert__TRANSACTION_NOTIFICATION_64TO32(ctx, (_TRANSACTION_NOTIFICATION*)TransactionNotification_used, x32based_TransactionNotification);
	}

	return ret_value;
}


NTSTATUS WINAPI _w32_NtQueryInformationResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass_used = (RESOURCEMANAGER_INFORMATION_CLASS)(x32based_args[3]); // RESOURCEMANAGER_INFORMATION_CLASS  IN 
	PVOID ResourceManagerInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN  OUT 
	ULONG ResourceManagerInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, ResourceManagerHandle_used, ResourceManagerInformationClass_used, ResourceManagerInformation_used, ResourceManagerInformationLength_used, ReturnLength_used); // NtQueryInformationResourceManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtSetInformationResourceManager(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass_used = (RESOURCEMANAGER_INFORMATION_CLASS)(x32based_args[3]); // RESOURCEMANAGER_INFORMATION_CLASS  IN 
	PVOID ResourceManagerInformation_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	ULONG ResourceManagerInformationLength_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, ResourceManagerHandle_used, ResourceManagerInformationClass_used, ResourceManagerInformation_used, ResourceManagerInformationLength_used); // NtSetInformationResourceManager

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRegisterProtocolAddressInformation(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManager = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PCRM_PROTOCOL_ID ProtocolId_used = (PCRM_PROTOCOL_ID)(x32based_args[3]); // PCRM_PROTOCOL_ID  IN 
	ULONG ProtocolInformationSize_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID ProtocolInformation_used = (PVOID)(x32based_args[5]); // PVOID  IN 
	ULONG CreateOptions_used = (ULONG)(x32based_args[6]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManager_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManager);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 5, ResourceManager_used, ProtocolId_used, ProtocolInformationSize_used, ProtocolInformation_used, CreateOptions_used); // NtRegisterProtocolAddressInformation

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPropagationComplete(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG RequestCookie_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	ULONG BufferLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[5]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, ResourceManagerHandle_used, RequestCookie_used, BufferLength_used, Buffer_used); // NtPropagationComplete

	return ret_value;
}


NTSTATUS WINAPI _w32_NtPropagationFailed(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ResourceManagerHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG RequestCookie_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	NTSTATUS PropStatus_used = (NTSTATUS)(x32based_args[4]); // NTSTATUS  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ResourceManagerHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ResourceManagerHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 3, ResourceManagerHandle_used, RequestCookie_used, PropStatus_used); // NtPropagationFailed

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFreezeTransactions(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PLARGE_INTEGER FreezeTimeout_used = (PLARGE_INTEGER)(x32based_args[2]); // PLARGE_INTEGER  IN 
	PLARGE_INTEGER ThawTimeout_used = (PLARGE_INTEGER)(x32based_args[3]); // PLARGE_INTEGER  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, FreezeTimeout_used, ThawTimeout_used); // NtFreezeTransactions

	return ret_value;
}


NTSTATUS WINAPI _w32_NtThawTransactions(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 0); // NtThawTransactions

	return ret_value;
}


NTSTATUS WINAPI _w32_NtContinue(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	PCONTEXT ContextRecord_used = (PCONTEXT)(x32based_args[2]); // PCONTEXT  IN 
	BOOLEAN TestAlert_used = (BOOLEAN)(x32based_args[3]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, ContextRecord_used, TestAlert_used); // NtContinue

	return ret_value;
}


NTSTATUS WINAPI _w32_NtRaiseException(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ExceptionRecord = (uint32_t)(x32based_args[2]); // PEXCEPTION_RECORD  IN 
	PCONTEXT ContextRecord_used = (PCONTEXT)(x32based_args[3]); // PCONTEXT  IN 
	BOOLEAN FirstChance_used = (BOOLEAN)(x32based_args[4]); // BOOLEAN  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	uint8_t ExceptionRecord_holder[sizeof(_EXCEPTION_RECORD)];
	PEXCEPTION_RECORD ExceptionRecord_used = (PEXCEPTION_RECORD)&ExceptionRecord_holder;

	// Convert parameters from x32 to x64
	if (x32based_ExceptionRecord != NULL) {
		convert__EXCEPTION_RECORD_32TO64(ctx, (_EXCEPTION_RECORD**)&ExceptionRecord_used, x32based_ExceptionRecord);
	}
	else {
		ExceptionRecord_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 3, ExceptionRecord_used, ContextRecord_used, FirstChance_used); // NtRaiseException

	return ret_value;
}


NTSTATUS WINAPI _w32_NtVdmControl(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	VDMSERVICECLASS Service_used = (VDMSERVICECLASS)(x32based_args[2]); // VDMSERVICECLASS  IN 
	PVOID ServiceData_used = (PVOID)(x32based_args[3]); // PVOID  IN  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 2, Service_used, ServiceData_used); // NtVdmControl

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTraceEvent(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_TraceHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	ULONG Flags_used = (ULONG)(x32based_args[3]); // ULONG  IN 
	ULONG FieldSize_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID Fields_used = (PVOID)(x32based_args[5]); // PVOID  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE TraceHandle_used = Handle32ToHandle((const void* __ptr32)x32based_TraceHandle);

	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 4, TraceHandle_used, Flags_used, FieldSize_used, Fields_used); // NtTraceEvent

	return ret_value;
}


NTSTATUS WINAPI _w32_NtTraceControl(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	TRACE_CONTROL_INFORMATION_CLASS TraceInformationClass_used = (TRACE_CONTROL_INFORMATION_CLASS)(x32based_args[2]); // TRACE_CONTROL_INFORMATION_CLASS  IN 
	PVOID InputBuffer_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	ULONG InputBufferLength_used = (ULONG)(x32based_args[4]); // ULONG  IN 
	PVOID TraceInformation_used = (PVOID)(x32based_args[5]); // PVOID  IN  OUT 
	ULONG TraceInformationLength_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	PULONG ReturnLength_used = (PULONG)(x32based_args[7]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	// Convert parameters from x32 to x64
	ret_value = __syscall64(syscall_idx, 6, TraceInformationClass_used, InputBuffer_used, InputBufferLength_used, TraceInformation_used, TraceInformationLength_used, ReturnLength_used); // NtTraceControl

	return ret_value;
}


NTSTATUS WINAPI _w32_NtFlushVirtualMemory(uint32_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint32_t x32based_BaseAddress = (uint32_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint32_t x32based_RegionSize = (uint32_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	uint32_t x32based_IoStatus = (uint32_t)(x32based_args[5]); // PIO_STATUS_BLOCK  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);
	uint8_t BaseAddress_holder[sizeof(PVOID)];
	PVOID* BaseAddress_used = (PVOID*)&BaseAddress_holder;
	uint8_t RegionSize_holder[sizeof(long long unsigned int)];
	PSIZE_T RegionSize_used = (PSIZE_T)&RegionSize_holder;
	uint8_t IoStatus_holder[sizeof(_IO_STATUS_BLOCK)];
	PIO_STATUS_BLOCK IoStatus_used = (PIO_STATUS_BLOCK)&IoStatus_holder;

	// Convert parameters from x32 to x64
	if (x32based_BaseAddress != NULL) {
		*((SIZE_T*)BaseAddress_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_BaseAddress));
	}
	else {
		BaseAddress_used = 0;
	}
	if (x32based_RegionSize != NULL) {
		*((SIZE_T*)RegionSize_holder) = (SIZE_T)(*((X32_SIZE_T*)x32based_RegionSize));
	}
	else {
		RegionSize_used = 0;
	}
	if (x32based_IoStatus == NULL) {
		IoStatus_used = 0;
	}

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, BaseAddress_used, RegionSize_used, IoStatus_used); // NtFlushVirtualMemory

	if (x32based_BaseAddress != NULL) {
		*((X32_SIZE_T*)x32based_BaseAddress) = (X32_SIZE_T)(*(SIZE_T*)BaseAddress_used);
	}
	if (x32based_RegionSize != NULL) {
		*((X32_SIZE_T*)x32based_RegionSize) = (X32_SIZE_T)(*(SIZE_T*)RegionSize_used);
	}
	if (IoStatus_used != NULL) {
		convert__IO_STATUS_BLOCK_64TO32(ctx, (_IO_STATUS_BLOCK*)IoStatus_used, x32based_IoStatus);
	}

	return ret_value;
}

NTSTATUS __cdecl _w64_NtAllocateVirtualMemory(uint64_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint64_t x64based_BaseAddress = (uint64_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint64_t ZeroBits_used = (uint64_t)(x32based_args[4]); // ULONG_PTR  IN 
	uint64_t x64based_RegionSize = (uint64_t)(x32based_args[5]); // PSIZE_T  IN  OUT 
	ULONG AllocationType_used = (ULONG)(x32based_args[6]); // ULONG  IN 
	ULONG Protect_used = (ULONG)(x32based_args[7]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	ret_value = __syscall64(syscall_idx, 6, ProcessHandle_used, x64based_BaseAddress, ZeroBits_used, x64based_RegionSize, AllocationType_used, Protect_used); // NtAllocateVirtualMemory

	return ret_value;
}

NTSTATUS __cdecl _w64_NtFreeVirtualMemory(uint64_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint64_t x64based_BaseAddress = (uint64_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint64_t x64based_RegionSize = (uint64_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG FreeType_used = (ULONG)(x32based_args[5]); // ULONG  IN 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	ret_value = __syscall64(syscall_idx, 4, ProcessHandle_used, x64based_BaseAddress, x64based_RegionSize, FreeType_used); // NtFreeVirtualMemory

	return ret_value;
}

NTSTATUS __cdecl _w64_NtReadVirtualMemory(uint64_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  OUT 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint64_t x64based_NumberOfBytesRead = (uint64_t)(x32based_args[6]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, Buffer_used, BufferSize_used, x64based_NumberOfBytesRead); // NtReadVirtualMemory

	return ret_value;
}

NTSTATUS __cdecl _w64_NtWriteVirtualMemory(uint64_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	PVOID BaseAddress_used = (PVOID)(x32based_args[3]); // PVOID  IN 
	PVOID Buffer_used = (PVOID)(x32based_args[4]); // PVOID  IN 
	SIZE_T BufferSize_used = (SIZE_T)(x32based_args[5]); // SIZE_T  IN 
	uint64_t x64based_NumberOfBytesWritten = (uint64_t)(x32based_args[6]); // PSIZE_T  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, BaseAddress_used, Buffer_used, BufferSize_used, x64based_NumberOfBytesWritten); // NtWriteVirtualMemory

	return ret_value;
}

NTSTATUS __cdecl _w64_NtProtectVirtualMemory(uint64_t* x32based_args) {

	// Declare parameters from stack
	void* ctx = (void*)(x32based_args[0]);
	uint32_t syscall_idx = (uint32_t)(x32based_args[1]);
	uint32_t x32based_ProcessHandle = (uint32_t)(x32based_args[2]); // HANDLE  IN 
	uint64_t x64based_BaseAddress = (uint64_t)(x32based_args[3]); // PVOID *  IN  OUT 
	uint64_t x64based_RegionSize = (uint64_t)(x32based_args[4]); // PSIZE_T  IN  OUT 
	ULONG NewProtect_used = (ULONG)(x32based_args[5]); // ULONG  IN 
	PULONG OldProtect_used = (PULONG)(x32based_args[6]); // PULONG  OUT 

	NTSTATUS ret_value = 0;

	// Declare space used in parameters
	HANDLE ProcessHandle_used = Handle32ToHandle((const void* __ptr32)x32based_ProcessHandle);

	ret_value = __syscall64(syscall_idx, 5, ProcessHandle_used, x64based_BaseAddress, x64based_RegionSize, NewProtect_used, OldProtect_used); // NtProtectVirtualMemory

	return ret_value;
}

#pragma warning(pop)