#pragma once

#include <stdint.h>


 typedef enum _syscall_table_enum {

    SYSCALL_NtAcceptConnectPort,
    SYSCALL_NtAccessCheck,
    SYSCALL_NtAccessCheckAndAuditAlarm,
    SYSCALL_NtAccessCheckByType,
    SYSCALL_NtAccessCheckByTypeAndAuditAlarm,
    SYSCALL_NtAccessCheckByTypeResultList,
    SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarm,
    SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarmByHandle,
    SYSCALL_NtAcquireProcessActivityReference,
    SYSCALL_NtAddAtom,
    SYSCALL_NtAddAtomEx,
    SYSCALL_NtAddBootEntry,
    SYSCALL_NtAddDriverEntry,
    SYSCALL_NtAdjustGroupsToken,
    SYSCALL_NtAdjustPrivilegesToken,
    SYSCALL_NtAdjustTokenClaimsAndDeviceGroups,
    SYSCALL_NtAlertResumeThread,
    SYSCALL_NtAlertThread,
    SYSCALL_NtAlertThreadByThreadId,
    SYSCALL_NtAllocateLocallyUniqueId,
    SYSCALL_NtAllocateReserveObject,
    SYSCALL_NtAllocateUserPhysicalPages,
    SYSCALL_NtAllocateUuids,
    SYSCALL_NtAllocateVirtualMemory,
    SYSCALL_NtAllocateVirtualMemoryEx,
    SYSCALL_NtAlpcAcceptConnectPort,
    SYSCALL_NtAlpcCancelMessage,
    SYSCALL_NtAlpcConnectPort,
    SYSCALL_NtAlpcConnectPortEx,
    SYSCALL_NtAlpcCreatePort,
    SYSCALL_NtAlpcCreatePortSection,
    SYSCALL_NtAlpcCreateResourceReserve,
    SYSCALL_NtAlpcCreateSectionView,
    SYSCALL_NtAlpcCreateSecurityContext,
    SYSCALL_NtAlpcDeletePortSection,
    SYSCALL_NtAlpcDeleteResourceReserve,
    SYSCALL_NtAlpcDeleteSectionView,
    SYSCALL_NtAlpcDeleteSecurityContext,
    SYSCALL_NtAlpcDisconnectPort,
    SYSCALL_NtAlpcImpersonateClientContainerOfPort,
    SYSCALL_NtAlpcImpersonateClientOfPort,
    SYSCALL_NtAlpcOpenSenderProcess,
    SYSCALL_NtAlpcOpenSenderThread,
    SYSCALL_NtAlpcQueryInformation,
    SYSCALL_NtAlpcQueryInformationMessage,
    SYSCALL_NtAlpcRevokeSecurityContext,
    SYSCALL_NtAlpcSendWaitReceivePort,
    SYSCALL_NtAlpcSetInformation,
    SYSCALL_NtApphelpCacheControl,
    SYSCALL_NtAreMappedFilesTheSame,
    SYSCALL_NtAssignProcessToJobObject,
    SYSCALL_NtAssociateWaitCompletionPacket,
    SYSCALL_NtCallEnclave,
    SYSCALL_NtCallbackReturn,
    SYSCALL_NtCancelIoFile,
    SYSCALL_NtCancelIoFileEx,
    SYSCALL_NtCancelSynchronousIoFile,
    SYSCALL_NtCancelTimer,
    SYSCALL_NtCancelTimer2,
    SYSCALL_NtCancelWaitCompletionPacket,
    SYSCALL_NtClearEvent,
    SYSCALL_NtClose,
    SYSCALL_NtCloseObjectAuditAlarm,
    SYSCALL_NtCommitComplete,
    SYSCALL_NtCommitEnlistment,
    SYSCALL_NtCommitRegistryTransaction,
    SYSCALL_NtCommitTransaction,
    SYSCALL_NtCompactKeys,
    SYSCALL_NtCompareObjects,
    SYSCALL_NtCompareSigningLevels,
    SYSCALL_NtCompareTokens,
    SYSCALL_NtCompleteConnectPort,
    SYSCALL_NtCompressKey,
    SYSCALL_NtConnectPort,
    SYSCALL_NtContinue,
    SYSCALL_NtConvertBetweenAuxiliaryCounterAndPerformanceCounter,
    SYSCALL_NtCreateCrossVmEvent,
    SYSCALL_NtCreateDebugObject,
    SYSCALL_NtCreateDirectoryObject,
    SYSCALL_NtCreateDirectoryObjectEx,
    SYSCALL_NtCreateEnclave,
    SYSCALL_NtCreateEnlistment,
    SYSCALL_NtCreateEvent,
    SYSCALL_NtCreateEventPair,
    SYSCALL_NtCreateFile,
    SYSCALL_NtCreateIRTimer,
    SYSCALL_NtCreateIoCompletion,
    SYSCALL_NtCreateJobObject,
    SYSCALL_NtCreateJobSet,
    SYSCALL_NtCreateKey,
    SYSCALL_NtCreateKeyTransacted,
    SYSCALL_NtCreateKeyedEvent,
    SYSCALL_NtCreateLowBoxToken,
    SYSCALL_NtCreateMailslotFile,
    SYSCALL_NtCreateMutant,
    SYSCALL_NtCreateNamedPipeFile,
    SYSCALL_NtCreatePagingFile,
    SYSCALL_NtCreatePartition,
    SYSCALL_NtCreatePort,
    SYSCALL_NtCreatePrivateNamespace,
    SYSCALL_NtCreateProcess,
    SYSCALL_NtCreateProcessEx,
    SYSCALL_NtCreateProfile,
    SYSCALL_NtCreateProfileEx,
    SYSCALL_NtCreateRegistryTransaction,
    SYSCALL_NtCreateResourceManager,
    SYSCALL_NtCreateSection,
    SYSCALL_NtCreateSectionEx,
    SYSCALL_NtCreateSemaphore,
    SYSCALL_NtCreateSymbolicLinkObject,
    SYSCALL_NtCreateThread,
    SYSCALL_NtCreateThreadEx,
    SYSCALL_NtCreateTimer,
    SYSCALL_NtCreateTimer2,
    SYSCALL_NtCreateToken,
    SYSCALL_NtCreateTokenEx,
    SYSCALL_NtCreateTransaction,
    SYSCALL_NtCreateTransactionManager,
    SYSCALL_NtCreateUserProcess,
    SYSCALL_NtCreateWaitCompletionPacket,
    SYSCALL_NtCreateWaitablePort,
    SYSCALL_NtCreateWnfStateName,
    SYSCALL_NtCreateWorkerFactory,
    SYSCALL_NtDebugActiveProcess,
    SYSCALL_NtDebugContinue,
    SYSCALL_NtDelayExecution,
    SYSCALL_NtDeleteAtom,
    SYSCALL_NtDeleteBootEntry,
    SYSCALL_NtDeleteDriverEntry,
    SYSCALL_NtDeleteFile,
    SYSCALL_NtDeleteKey,
    SYSCALL_NtDeleteObjectAuditAlarm,
    SYSCALL_NtDeletePrivateNamespace,
    SYSCALL_NtDeleteValueKey,
    SYSCALL_NtDeleteWnfStateData,
    SYSCALL_NtDeleteWnfStateName,
    SYSCALL_NtDeviceIoControlFile,
    SYSCALL_NtDisableLastKnownGood,
    SYSCALL_NtDisplayString,
    SYSCALL_NtDrawText,
    SYSCALL_NtDuplicateObject,
    SYSCALL_NtDuplicateToken,
    SYSCALL_NtEnableLastKnownGood,
    SYSCALL_NtEnumerateBootEntries,
    SYSCALL_NtEnumerateDriverEntries,
    SYSCALL_NtEnumerateKey,
    SYSCALL_NtEnumerateSystemEnvironmentValuesEx,
    SYSCALL_NtEnumerateTransactionObject,
    SYSCALL_NtEnumerateValueKey,
    SYSCALL_NtExtendSection,
    SYSCALL_NtFilterBootOption,
    SYSCALL_NtFilterToken,
    SYSCALL_NtFilterTokenEx,
    SYSCALL_NtFindAtom,
    SYSCALL_NtFlushBuffersFile,
    SYSCALL_NtFlushBuffersFileEx,
    SYSCALL_NtFlushInstallUILanguage,
    SYSCALL_NtFlushInstructionCache,
    SYSCALL_NtFlushKey,
    SYSCALL_NtFlushProcessWriteBuffers,
    SYSCALL_NtFlushVirtualMemory,
    SYSCALL_NtFlushWriteBuffer,
    SYSCALL_NtFreeUserPhysicalPages,
    SYSCALL_NtFreeVirtualMemory,
    SYSCALL_NtFreezeRegistry,
    SYSCALL_NtFreezeTransactions,
    SYSCALL_NtFsControlFile,
    SYSCALL_NtGetCachedSigningLevel,
    SYSCALL_NtGetCompleteWnfStateSubscription,
    SYSCALL_NtGetContextThread,
    SYSCALL_NtGetCurrentProcessorNumber,
    SYSCALL_NtGetCurrentProcessorNumberEx,
    SYSCALL_NtGetDevicePowerState,
    SYSCALL_NtGetMUIRegistryInfo,
    SYSCALL_NtGetNextProcess,
    SYSCALL_NtGetNextThread,
    SYSCALL_NtGetNlsSectionPtr,
    SYSCALL_NtGetNotificationResourceManager,
    SYSCALL_NtGetWriteWatch,
    SYSCALL_NtImpersonateAnonymousToken,
    SYSCALL_NtImpersonateClientOfPort,
    SYSCALL_NtImpersonateThread,
    SYSCALL_NtInitializeEnclave,
    SYSCALL_NtInitializeNlsFiles,
    SYSCALL_NtInitializeRegistry,
    SYSCALL_NtInitiatePowerAction,
    SYSCALL_NtIsProcessInJob,
    SYSCALL_NtIsSystemResumeAutomatic,
    SYSCALL_NtIsUILanguageComitted,
    SYSCALL_NtListenPort,
    SYSCALL_NtLoadDriver,
    SYSCALL_NtLoadEnclaveData,
    SYSCALL_NtLoadKey,
    SYSCALL_NtLoadKey2,
    SYSCALL_NtLoadKeyEx,
    SYSCALL_NtLockFile,
    SYSCALL_NtLockProductActivationKeys,
    SYSCALL_NtLockRegistryKey,
    SYSCALL_NtLockVirtualMemory,
    SYSCALL_NtMakePermanentObject,
    SYSCALL_NtMakeTemporaryObject,
    SYSCALL_NtManageHotPatch,
    SYSCALL_NtManagePartition,
    SYSCALL_NtMapCMFModule,
    SYSCALL_NtMapUserPhysicalPages,
    SYSCALL_NtMapUserPhysicalPagesScatter,
    SYSCALL_NtMapViewOfSection,
    SYSCALL_NtMapViewOfSectionEx,
    SYSCALL_NtModifyBootEntry,
    SYSCALL_NtModifyDriverEntry,
    SYSCALL_NtNotifyChangeDirectoryFile,
    SYSCALL_NtNotifyChangeDirectoryFileEx,
    SYSCALL_NtNotifyChangeKey,
    SYSCALL_NtNotifyChangeMultipleKeys,
    SYSCALL_NtNotifyChangeSession,
    SYSCALL_NtOpenDirectoryObject,
    SYSCALL_NtOpenEnlistment,
    SYSCALL_NtOpenEvent,
    SYSCALL_NtOpenEventPair,
    SYSCALL_NtOpenFile,
    SYSCALL_NtOpenIoCompletion,
    SYSCALL_NtOpenJobObject,
    SYSCALL_NtOpenKey,
    SYSCALL_NtOpenKeyEx,
    SYSCALL_NtOpenKeyTransacted,
    SYSCALL_NtOpenKeyTransactedEx,
    SYSCALL_NtOpenKeyedEvent,
    SYSCALL_NtOpenMutant,
    SYSCALL_NtOpenObjectAuditAlarm,
    SYSCALL_NtOpenPartition,
    SYSCALL_NtOpenPrivateNamespace,
    SYSCALL_NtOpenProcess,
    SYSCALL_NtOpenProcessToken,
    SYSCALL_NtOpenProcessTokenEx,
    SYSCALL_NtOpenRegistryTransaction,
    SYSCALL_NtOpenResourceManager,
    SYSCALL_NtOpenSection,
    SYSCALL_NtOpenSemaphore,
    SYSCALL_NtOpenSession,
    SYSCALL_NtOpenSymbolicLinkObject,
    SYSCALL_NtOpenThread,
    SYSCALL_NtOpenThreadToken,
    SYSCALL_NtOpenThreadTokenEx,
    SYSCALL_NtOpenTimer,
    SYSCALL_NtOpenTransaction,
    SYSCALL_NtOpenTransactionManager,
    SYSCALL_NtPlugPlayControl,
    SYSCALL_NtPowerInformation,
    SYSCALL_NtPrePrepareComplete,
    SYSCALL_NtPrePrepareEnlistment,
    SYSCALL_NtPrepareComplete,
    SYSCALL_NtPrepareEnlistment,
    SYSCALL_NtPrivilegeCheck,
    SYSCALL_NtPrivilegeObjectAuditAlarm,
    SYSCALL_NtPrivilegedServiceAuditAlarm,
    SYSCALL_NtPropagationComplete,
    SYSCALL_NtPropagationFailed,
    SYSCALL_NtProtectVirtualMemory,
    SYSCALL_NtPulseEvent,
    SYSCALL_NtQueryAttributesFile,
    SYSCALL_NtQueryAuxiliaryCounterFrequency,
    SYSCALL_NtQueryBootEntryOrder,
    SYSCALL_NtQueryBootOptions,
    SYSCALL_NtQueryDebugFilterState,
    SYSCALL_NtQueryDefaultLocale,
    SYSCALL_NtQueryDefaultUILanguage,
    SYSCALL_NtQueryDirectoryFile,
    SYSCALL_NtQueryDirectoryFileEx,
    SYSCALL_NtQueryDirectoryObject,
    SYSCALL_NtQueryDriverEntryOrder,
    SYSCALL_NtQueryEaFile,
    SYSCALL_NtQueryEvent,
    SYSCALL_NtQueryFullAttributesFile,
    SYSCALL_NtQueryInformationAtom,
    SYSCALL_NtQueryInformationByName,
    SYSCALL_NtQueryInformationEnlistment,
    SYSCALL_NtQueryInformationFile,
    SYSCALL_NtQueryInformationJobObject,
    SYSCALL_NtQueryInformationPort,
    SYSCALL_NtQueryInformationProcess,
    SYSCALL_NtQueryInformationResourceManager,
    SYSCALL_NtQueryInformationThread,
    SYSCALL_NtQueryInformationToken,
    SYSCALL_NtQueryInformationTransaction,
    SYSCALL_NtQueryInformationTransactionManager,
    SYSCALL_NtQueryInformationWorkerFactory,
    SYSCALL_NtQueryInstallUILanguage,
    SYSCALL_NtQueryIntervalProfile,
    SYSCALL_NtQueryIoCompletion,
    SYSCALL_NtQueryKey,
    SYSCALL_NtQueryLicenseValue,
    SYSCALL_NtQueryMultipleValueKey,
    SYSCALL_NtQueryMutant,
    SYSCALL_NtQueryObject,
    SYSCALL_NtQueryOpenSubKeys,
    SYSCALL_NtQueryOpenSubKeysEx,
    SYSCALL_NtQueryPerformanceCounter,
    SYSCALL_NtQueryPortInformationProcess,
    SYSCALL_NtQueryQuotaInformationFile,
    SYSCALL_NtQuerySection,
    SYSCALL_NtQuerySecurityAttributesToken,
    SYSCALL_NtQuerySecurityObject,
    SYSCALL_NtQuerySecurityPolicy,
    SYSCALL_NtQuerySemaphore,
    SYSCALL_NtQuerySymbolicLinkObject,
    SYSCALL_NtQuerySystemEnvironmentValue,
    SYSCALL_NtQuerySystemEnvironmentValueEx,
    SYSCALL_NtQuerySystemInformation,
    SYSCALL_NtQuerySystemInformationEx,
    SYSCALL_NtQueryTimer,
    SYSCALL_NtQueryTimerResolution,
    SYSCALL_NtQueryValueKey,
    SYSCALL_NtQueryVirtualMemory,
    SYSCALL_NtQueryVolumeInformationFile,
    SYSCALL_NtQueryWnfStateData,
    SYSCALL_NtQueryWnfStateNameInformation,
    SYSCALL_NtQueueApcThread,
    SYSCALL_NtQueueApcThreadEx,
    SYSCALL_NtRaiseException,
    SYSCALL_NtRaiseHardError,
    SYSCALL_NtReadFile,
    SYSCALL_NtReadFileScatter,
    SYSCALL_NtReadOnlyEnlistment,
    SYSCALL_NtReadRequestData,
    SYSCALL_NtReadVirtualMemory,
    SYSCALL_NtRecoverEnlistment,
    SYSCALL_NtRecoverResourceManager,
    SYSCALL_NtRecoverTransactionManager,
    SYSCALL_NtRegisterProtocolAddressInformation,
    SYSCALL_NtRegisterThreadTerminatePort,
    SYSCALL_NtReleaseKeyedEvent,
    SYSCALL_NtReleaseMutant,
    SYSCALL_NtReleaseSemaphore,
    SYSCALL_NtReleaseWorkerFactoryWorker,
    SYSCALL_NtRemoveIoCompletion,
    SYSCALL_NtRemoveIoCompletionEx,
    SYSCALL_NtRemoveProcessDebug,
    SYSCALL_NtRenameKey,
    SYSCALL_NtRenameTransactionManager,
    SYSCALL_NtReplaceKey,
    SYSCALL_NtReplacePartitionUnit,
    SYSCALL_NtReplyPort,
    SYSCALL_NtReplyWaitReceivePort,
    SYSCALL_NtReplyWaitReceivePortEx,
    SYSCALL_NtReplyWaitReplyPort,
    SYSCALL_NtRequestPort,
    SYSCALL_NtRequestWaitReplyPort,
    SYSCALL_NtResetEvent,
    SYSCALL_NtResetWriteWatch,
    SYSCALL_NtRestoreKey,
    SYSCALL_NtResumeProcess,
    SYSCALL_NtResumeThread,
    SYSCALL_NtRevertContainerImpersonation,
    SYSCALL_NtRollbackComplete,
    SYSCALL_NtRollbackEnlistment,
    SYSCALL_NtRollbackRegistryTransaction,
    SYSCALL_NtRollbackTransaction,
    SYSCALL_NtRollforwardTransactionManager,
    SYSCALL_NtSaveKey,
    SYSCALL_NtSaveKeyEx,
    SYSCALL_NtSaveMergedKeys,
    SYSCALL_NtSecureConnectPort,
    SYSCALL_NtSerializeBoot,
    SYSCALL_NtSetBootEntryOrder,
    SYSCALL_NtSetBootOptions,
    SYSCALL_NtSetCachedSigningLevel,
    SYSCALL_NtSetCachedSigningLevel2,
    SYSCALL_NtSetContextThread,
    SYSCALL_NtSetDebugFilterState,
    SYSCALL_NtSetDefaultHardErrorPort,
    SYSCALL_NtSetDefaultLocale,
    SYSCALL_NtSetDefaultUILanguage,
    SYSCALL_NtSetDriverEntryOrder,
    SYSCALL_NtSetEaFile,
    SYSCALL_NtSetEvent,
    SYSCALL_NtSetEventBoostPriority,
    SYSCALL_NtSetHighEventPair,
    SYSCALL_NtSetHighWaitLowEventPair,
    SYSCALL_NtSetIRTimer,
    SYSCALL_NtSetInformationDebugObject,
    SYSCALL_NtSetInformationEnlistment,
    SYSCALL_NtSetInformationFile,
    SYSCALL_NtSetInformationJobObject,
    SYSCALL_NtSetInformationKey,
    SYSCALL_NtSetInformationObject,
    SYSCALL_NtSetInformationProcess,
    SYSCALL_NtSetInformationResourceManager,
    SYSCALL_NtSetInformationSymbolicLink,
    SYSCALL_NtSetInformationThread,
    SYSCALL_NtSetInformationToken,
    SYSCALL_NtSetInformationTransaction,
    SYSCALL_NtSetInformationTransactionManager,
    SYSCALL_NtSetInformationVirtualMemory,
    SYSCALL_NtSetInformationWorkerFactory,
    SYSCALL_NtSetIntervalProfile,
    SYSCALL_NtSetIoCompletion,
    SYSCALL_NtSetIoCompletionEx,
    SYSCALL_NtSetLdtEntries,
    SYSCALL_NtSetLowEventPair,
    SYSCALL_NtSetLowWaitHighEventPair,
    SYSCALL_NtSetQuotaInformationFile,
    SYSCALL_NtSetSecurityObject,
    SYSCALL_NtSetSystemEnvironmentValue,
    SYSCALL_NtSetSystemEnvironmentValueEx,
    SYSCALL_NtSetSystemInformation,
    SYSCALL_NtSetSystemPowerState,
    SYSCALL_NtSetSystemTime,
    SYSCALL_NtSetThreadExecutionState,
    SYSCALL_NtSetTimer,
    SYSCALL_NtSetTimer2,
    SYSCALL_NtSetTimerEx,
    SYSCALL_NtSetTimerResolution,
    SYSCALL_NtSetUuidSeed,
    SYSCALL_NtSetValueKey,
    SYSCALL_NtSetVolumeInformationFile,
    SYSCALL_NtSetWnfProcessNotificationEvent,
    SYSCALL_NtShutdownSystem,
    SYSCALL_NtShutdownWorkerFactory,
    SYSCALL_NtSignalAndWaitForSingleObject,
    SYSCALL_NtSinglePhaseReject,
    SYSCALL_NtStartProfile,
    SYSCALL_NtStopProfile,
    SYSCALL_NtSubscribeWnfStateChange,
    SYSCALL_NtSuspendProcess,
    SYSCALL_NtSuspendThread,
    SYSCALL_NtSystemDebugControl,
    SYSCALL_NtTerminateEnclave,
    SYSCALL_NtTerminateJobObject,
    SYSCALL_NtTerminateProcess,
    SYSCALL_NtTerminateThread,
    SYSCALL_NtTestAlert,
    SYSCALL_NtThawRegistry,
    SYSCALL_NtThawTransactions,
    SYSCALL_NtTraceControl,
    SYSCALL_NtTraceEvent,
    SYSCALL_NtTranslateFilePath,
    SYSCALL_NtUmsThreadYield,
    SYSCALL_NtUnloadDriver,
    SYSCALL_NtUnloadKey,
    SYSCALL_NtUnloadKey2,
    SYSCALL_NtUnloadKeyEx,
    SYSCALL_NtUnlockFile,
    SYSCALL_NtUnlockVirtualMemory,
    SYSCALL_NtUnmapViewOfSection,
    SYSCALL_NtUnmapViewOfSectionEx,
    SYSCALL_NtUnsubscribeWnfStateChange,
    SYSCALL_NtUpdateWnfStateData,
    SYSCALL_NtVdmControl,
    SYSCALL_NtWaitForAlertByThreadId,
    SYSCALL_NtWaitForDebugEvent,
    SYSCALL_NtWaitForKeyedEvent,
    SYSCALL_NtWaitForMultipleObjects,
    SYSCALL_NtWaitForMultipleObjects32,
    SYSCALL_NtWaitForSingleObject,
    SYSCALL_NtWaitForWorkViaWorkerFactory,
    SYSCALL_NtWaitHighEventPair,
    SYSCALL_NtWaitLowEventPair,
    SYSCALL_NtWorkerFactoryWorkerReady,
    SYSCALL_NtWriteFile,
    SYSCALL_NtWriteFileGather,
    SYSCALL_NtWriteRequestData,
    SYSCALL_NtWriteVirtualMemory,
    SYSCALL_NtYieldExecution,

    SYSCALL_TABLE_MAX

} syscall_table_enum;


extern "C" {

    uint32_t get_syscall_by_name(const char* name); // return -1 if failed

    uint32_t get_syscall_by_idx(syscall_table_enum idx); // return -1 if failed
    
    const char* get_syscall_name_by_idx(syscall_table_enum idx);
    
    void set_syscall_by_idx(syscall_table_enum idx, uint32_t syscall_idx);
};

