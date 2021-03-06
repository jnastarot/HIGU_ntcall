#pragma once

#include <list>

extern "C" {

    //Because mangling in x64 and x32 are different
#pragma comment(linker, "/alternatename:__ImageBase=___ImageBase")

    NTSTATUS __cdecl w32_NtMapViewOfSectionEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCallbackReturn(uint32_t* x32based_args);
    void __cdecl w32_NtFlushProcessWriteBuffers(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDebugFilterState(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetDebugFilterState(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtYieldExecution(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDelayExecution(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySystemEnvironmentValue(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSystemEnvironmentValue(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySystemEnvironmentValueEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSystemEnvironmentValueEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateSystemEnvironmentValuesEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAddBootEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteBootEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtModifyBootEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateBootEntries(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryBootEntryOrder(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetBootEntryOrder(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryBootOptions(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetBootOptions(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTranslateFilePath(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAddDriverEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteDriverEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtModifyDriverEntry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateDriverEntries(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDriverEntryOrder(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetDriverEntryOrder(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFilterBootOption(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetEventBoostPriority(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtClearEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtResetEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPulseEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetLowEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetHighEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitLowEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitHighEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetLowWaitHighEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetHighWaitLowEventPair(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateMutant(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenMutant(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReleaseMutant(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryMutant(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateSemaphore(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenSemaphore(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReleaseSemaphore(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySemaphore(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetTimerEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateIRTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetIRTimer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateTimer2(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetTimer2(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelTimer2(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateProfile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateProfileEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtStartProfile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtStopProfile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryIntervalProfile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetIntervalProfile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateKeyedEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenKeyedEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReleaseKeyedEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForKeyedEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUmsThreadYield(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateWnfStateName(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteWnfStateName(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUpdateWnfStateData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteWnfStateData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryWnfStateData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryWnfStateNameInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSubscribeWnfStateChange(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnsubscribeWnfStateChange(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetCompleteWnfStateSubscription(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetWnfProcessNotificationEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateWorkerFactory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationWorkerFactory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationWorkerFactory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtShutdownWorkerFactory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReleaseWorkerFactoryWorker(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWorkerFactoryWorkerReady(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForWorkViaWorkerFactory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSystemTime(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryTimerResolution(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetTimerResolution(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryPerformanceCounter(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAllocateLocallyUniqueId(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetUuidSeed(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAllocateUuids(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySystemInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySystemInformationEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSystemInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSystemDebugControl(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRaiseHardError(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDefaultLocale(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetDefaultLocale(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInstallUILanguage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushInstallUILanguage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDefaultUILanguage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetDefaultUILanguage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtIsUILanguageComitted(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtInitializeNlsFiles(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetNlsSectionPtr(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMapCMFModule(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetMUIRegistryInfo(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAddAtom(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAddAtomEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFindAtom(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteAtom(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationAtom(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryLicenseValue(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetDefaultHardErrorPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtShutdownSystem(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDisplayString(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDrawText(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAllocateVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFreeVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReadVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWriteVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtProtectVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLockVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnlockVirtualMemory(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateSectionEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMapViewOfSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnmapViewOfSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnmapViewOfSectionEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtExtendSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAreMappedFilesTheSame(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreatePartition(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenPartition(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtManagePartition(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMapUserPhysicalPages(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMapUserPhysicalPagesScatter(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAllocateUserPhysicalPages(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFreeUserPhysicalPages(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetWriteWatch(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtResetWriteWatch(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreatePagingFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushInstructionCache(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushWriteBuffer(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateEnclave(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLoadEnclaveData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtInitializeEnclave(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTerminateEnclave(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCallEnclave(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDuplicateObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMakeTemporaryObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtMakePermanentObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSignalAndWaitForSingleObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForSingleObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForMultipleObjects(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForMultipleObjects32(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSecurityObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySecurityObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtClose(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCompareObjects(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateDirectoryObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateDirectoryObjectEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenDirectoryObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDirectoryObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreatePrivateNamespace(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenPrivateNamespace(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeletePrivateNamespace(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateSymbolicLinkObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenSymbolicLinkObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySymbolicLinkObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateProcessEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTerminateProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSuspendProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtResumeProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetNextProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetNextThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryPortInformationProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTerminateThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSuspendThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtResumeThread(uint32_t* x32based_args);
    ULONG __cdecl w32_NtGetCurrentProcessorNumber(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetContextThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetContextThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlertThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlertResumeThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTestAlert(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtImpersonateThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRegisterThreadTerminatePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetLdtEntries(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueueApcThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueueApcThreadEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlertThreadByThreadId(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForAlertByThreadId(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateUserProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateThreadEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAssignProcessToJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTerminateJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtIsProcessInJob(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationJobObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateJobSet(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRevertContainerImpersonation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAllocateReserveObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateDebugObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDebugActiveProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDebugContinue(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRemoveProcessDebug(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationDebugObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWaitForDebugEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateNamedPipeFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateMailslotFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushBuffersFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushBuffersFileEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationByName(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDirectoryFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryDirectoryFileEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryEaFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetEaFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryQuotaInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetQuotaInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryVolumeInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetVolumeInformationFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelIoFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelIoFileEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelSynchronousIoFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeviceIoControlFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFsControlFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReadFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWriteFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReadFileScatter(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWriteFileGather(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLockFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnlockFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryAttributesFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryFullAttributesFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtNotifyChangeDirectoryFile(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtNotifyChangeDirectoryFileEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLoadDriver(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnloadDriver(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateIoCompletion(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenIoCompletion(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryIoCompletion(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetIoCompletion(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetIoCompletionEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRemoveIoCompletion(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRemoveIoCompletionEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateWaitCompletionPacket(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAssociateWaitCompletionPacket(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCancelWaitCompletionPacket(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenSession(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtNotifyChangeSession(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreatePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateWaitablePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSecureConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtListenPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAcceptConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCompleteConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRequestPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRequestWaitReplyPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplyPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplyWaitReplyPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplyWaitReceivePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplyWaitReceivePortEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtImpersonateClientOfPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReadRequestData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtWriteRequestData(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCreatePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcDisconnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcQueryInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcSetInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCreatePortSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcDeletePortSection(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCreateResourceReserve(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcDeleteResourceReserve(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCreateSectionView(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcDeleteSectionView(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCreateSecurityContext(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcDeleteSecurityContext(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcRevokeSecurityContext(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcQueryInformationMessage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcConnectPortEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcAcceptConnectPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcSendWaitReceivePort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcCancelMessage(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcImpersonateClientOfPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcImpersonateClientContainerOfPort(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcOpenSenderProcess(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAlpcOpenSenderThread(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPlugPlayControl(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSerializeBoot(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnableLastKnownGood(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDisableLastKnownGood(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplacePartitionUnit(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPowerInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetThreadExecutionState(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtInitiatePowerAction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetSystemPowerState(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetDevicePowerState(uint32_t* x32based_args);
    BOOLEAN __cdecl w32_NtIsSystemResumeAutomatic(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateKeyTransacted(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenKeyTransacted(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenKeyEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenKeyTransactedEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRenameKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteValueKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryValueKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetValueKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryMultipleValueKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateValueKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCompactKeys(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCompressKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLoadKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLoadKey2(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLoadKeyEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReplaceKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSaveKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSaveKeyEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSaveMergedKeys(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRestoreKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnloadKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnloadKey2(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtUnloadKeyEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtNotifyChangeKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtNotifyChangeMultipleKeys(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryOpenSubKeys(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryOpenSubKeysEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtInitializeRegistry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLockRegistryKey(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtLockProductActivationKeys(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFreezeRegistry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtThawRegistry(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateLowBoxToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateTokenEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenProcessToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenProcessTokenEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenThreadToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenThreadTokenEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDuplicateToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAdjustPrivilegesToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAdjustGroupsToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAdjustTokenClaimsAndDeviceGroups(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFilterToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFilterTokenEx(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCompareTokens(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrivilegeCheck(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtImpersonateAnonymousToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQuerySecurityAttributesToken(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheck(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckByType(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckByTypeResultList(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetCachedSigningLevel(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetCachedSigningLevel(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckAndAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckByTypeAndAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckByTypeResultListAndAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtAccessCheckByTypeResultListAndAuditAlarmByHandle(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenObjectAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrivilegeObjectAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCloseObjectAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtDeleteObjectAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrivilegedServiceAuditAlarm(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRenameTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRollforwardTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRecoverTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationTransactionManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtEnumerateTransactionObject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCommitTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRollbackTransaction(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRecoverEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrePrepareEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrepareEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCommitEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRollbackEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrePrepareComplete(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPrepareComplete(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCommitComplete(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtReadOnlyEnlistment(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRollbackComplete(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSinglePhaseReject(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtCreateResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtOpenResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRecoverResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtGetNotificationResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtQueryInformationResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtSetInformationResourceManager(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRegisterProtocolAddressInformation(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPropagationComplete(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtPropagationFailed(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFreezeTransactions(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtThawTransactions(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtContinue(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtRaiseException(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtVdmControl(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTraceEvent(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtTraceControl(uint32_t* x32based_args);
    NTSTATUS __cdecl w32_NtFlushVirtualMemory(uint32_t* x32based_args);

    //wow64 to amd64
    NTSTATUS __cdecl w64_NtAllocateVirtualMemory(uint64_t* x32based_args);
    NTSTATUS __cdecl w64_NtFreeVirtualMemory(uint64_t* x32based_args);
    NTSTATUS __cdecl w64_NtReadVirtualMemory(uint64_t* x32based_args);
    NTSTATUS __cdecl w64_NtWriteVirtualMemory(uint64_t* x32based_args);
    NTSTATUS __cdecl w64_NtProtectVirtualMemory(uint64_t* x32based_args);
};