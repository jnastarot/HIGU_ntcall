#include "pch.h"
#include "ntdll_functions.h"

#ifdef _M_IX86
#include "ntdll_3264_thunks.h"
#endif

extern "C" {

#pragma warning(push)
#pragma warning(disable: 26812 4273 4244)
   
    NTSTATUS WINAPI NtAcceptConnectPort(PHANDLE PortHandle, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, BOOLEAN AcceptConnection, PPORT_VIEW ServerView, PREMOTE_PORT_VIEW ClientView) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAcceptConnectPort), 0, 6, PortHandle, PortContext, ConnectionRequest, AcceptConnection, ServerView, ClientView);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAcceptConnectPort), (uint32_t)w32_NtAcceptConnectPort, 6, PortHandle, PortContext, ConnectionRequest, AcceptConnection, ServerView, ClientView);
#endif
    }

    NTSTATUS WINAPI NtAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheck), 0, 8, SecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheck), (uint32_t)w32_NtAccessCheck, 8, SecurityDescriptor, ClientToken, DesiredAccess, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus, PBOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckAndAuditAlarm), 0, 11, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckAndAuditAlarm), (uint32_t)w32_NtAccessCheckAndAuditAlarm, 11, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, DesiredAccess, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckByType(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByType), 0, 11, SecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByType), (uint32_t)w32_NtAccessCheckByType, 11, SecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckByTypeAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus, PBOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeAndAuditAlarm), 0, 16, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeAndAuditAlarm), (uint32_t)w32_NtAccessCheckByTypeAndAuditAlarm, 16, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE ClientToken, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultList), 0, 11, SecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultList), (uint32_t)w32_NtAccessCheckByTypeResultList, 11, SecurityDescriptor, PrincipalSelfSid, ClientToken, DesiredAccess, ObjectTypeList, ObjectTypeListLength, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckByTypeResultListAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus, PBOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarm), 0, 16, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarm), (uint32_t)w32_NtAccessCheckByTypeResultListAndAuditAlarm, 16, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtAccessCheckByTypeResultListAndAuditAlarmByHandle(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PNTSTATUS AccessStatus, PBOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarmByHandle), 0, 17, SubsystemName, HandleId, ClientToken, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAccessCheckByTypeResultListAndAuditAlarmByHandle), (uint32_t)w32_NtAccessCheckByTypeResultListAndAuditAlarmByHandle, 17, SubsystemName, HandleId, ClientToken, ObjectTypeName, ObjectName, SecurityDescriptor, PrincipalSelfSid, DesiredAccess, AuditType, Flags, ObjectTypeList, ObjectTypeListLength, GenericMapping, ObjectCreation, GrantedAccess, AccessStatus, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtAddAtom(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddAtom), 0, 3, AtomName, Length, Atom);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddAtom), (uint32_t)w32_NtAddAtom, 3, AtomName, Length, Atom);
#endif
    }

    NTSTATUS WINAPI NtAddAtomEx(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddAtomEx), 0, 4, AtomName, Length, Atom, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddAtomEx), (uint32_t)w32_NtAddAtomEx, 4, AtomName, Length, Atom, Flags);
#endif
    }

    NTSTATUS WINAPI NtAddBootEntry(PBOOT_ENTRY BootEntry, PULONG Id) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddBootEntry), 0, 2, BootEntry, Id);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddBootEntry), (uint32_t)w32_NtAddBootEntry, 2, BootEntry, Id);
#endif
    }

    NTSTATUS WINAPI NtAddDriverEntry(PEFI_DRIVER_ENTRY DriverEntry, PULONG Id) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddDriverEntry), 0, 2, DriverEntry, Id);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAddDriverEntry), (uint32_t)w32_NtAddDriverEntry, 2, DriverEntry, Id);
#endif
    }

    NTSTATUS WINAPI NtAdjustGroupsToken(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustGroupsToken), 0, 6, TokenHandle, ResetToDefault, NewState, BufferLength, PreviousState, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustGroupsToken), (uint32_t)w32_NtAdjustGroupsToken, 6, TokenHandle, ResetToDefault, NewState, BufferLength, PreviousState, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustPrivilegesToken), 0, 6, TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustPrivilegesToken), (uint32_t)w32_NtAdjustPrivilegesToken, 6, TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtAdjustTokenClaimsAndDeviceGroups(HANDLE TokenHandle, BOOLEAN UserResetToDefault, BOOLEAN DeviceResetToDefault, BOOLEAN DeviceGroupsResetToDefault, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState, PTOKEN_GROUPS NewDeviceGroupsState, ULONG UserBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState, ULONG DeviceBufferLength, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState, ULONG DeviceGroupsBufferLength, PTOKEN_GROUPS PreviousDeviceGroups, PULONG UserReturnLength, PULONG DeviceReturnLength, PULONG DeviceGroupsReturnBufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustTokenClaimsAndDeviceGroups), 0, 16, TokenHandle, UserResetToDefault, DeviceResetToDefault, DeviceGroupsResetToDefault, NewUserState, NewDeviceState, NewDeviceGroupsState, UserBufferLength, PreviousUserState, DeviceBufferLength, PreviousDeviceState, DeviceGroupsBufferLength, PreviousDeviceGroups, UserReturnLength, DeviceReturnLength, DeviceGroupsReturnBufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAdjustTokenClaimsAndDeviceGroups), (uint32_t)w32_NtAdjustTokenClaimsAndDeviceGroups, 16, TokenHandle, UserResetToDefault, DeviceResetToDefault, DeviceGroupsResetToDefault, NewUserState, NewDeviceState, NewDeviceGroupsState, UserBufferLength, PreviousUserState, DeviceBufferLength, PreviousDeviceState, DeviceGroupsBufferLength, PreviousDeviceGroups, UserReturnLength, DeviceReturnLength, DeviceGroupsReturnBufferLength);
#endif
    }

    NTSTATUS WINAPI NtAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertResumeThread), 0, 2, ThreadHandle, PreviousSuspendCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertResumeThread), (uint32_t)w32_NtAlertResumeThread, 2, ThreadHandle, PreviousSuspendCount);
#endif
    }

    NTSTATUS WINAPI NtAlertThread(HANDLE ThreadHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertThread), 0, 1, ThreadHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertThread), (uint32_t)w32_NtAlertThread, 1, ThreadHandle);
#endif
    }

    NTSTATUS WINAPI NtAlertThreadByThreadId(HANDLE ThreadId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertThreadByThreadId), 0, 1, ThreadId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlertThreadByThreadId), (uint32_t)w32_NtAlertThreadByThreadId, 1, ThreadId);
#endif
    }

    NTSTATUS WINAPI NtAllocateLocallyUniqueId(PLUID Luid) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateLocallyUniqueId), 0, 1, Luid);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateLocallyUniqueId), (uint32_t)w32_NtAllocateLocallyUniqueId, 1, Luid);
#endif
    }

    NTSTATUS WINAPI NtAllocateReserveObject(PHANDLE MemoryReserveHandle, POBJECT_ATTRIBUTES ObjectAttributes, MEMORY_RESERVE_TYPE Type) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateReserveObject), 0, 3, MemoryReserveHandle, ObjectAttributes, Type);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateReserveObject), (uint32_t)w32_NtAllocateReserveObject, 3, MemoryReserveHandle, ObjectAttributes, Type);
#endif
    }

    NTSTATUS WINAPI NtAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateUserPhysicalPages), 0, 3, ProcessHandle, NumberOfPages, UserPfnArray);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateUserPhysicalPages), (uint32_t)w32_NtAllocateUserPhysicalPages, 3, ProcessHandle, NumberOfPages, UserPfnArray);
#endif
    }

    NTSTATUS WINAPI NtAllocateUuids(PULARGE_INTEGER Time, PULONG Range, PULONG Sequence, PCHAR Seed) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateUuids), 0, 4, Time, Range, Sequence, Seed);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateUuids), (uint32_t)w32_NtAllocateUuids, 4, Time, Range, Sequence, Seed);
#endif
    }

    NTSTATUS WINAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateVirtualMemory), 0, 6, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAllocateVirtualMemory), (uint32_t)w32_NtAllocateVirtualMemory, 6, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
#endif
    }

    NTSTATUS WINAPI NtAlpcAcceptConnectPort(PHANDLE PortHandle, HANDLE ConnectionPortHandle, ULONG Flags, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, PVOID PortContext, PPORT_MESSAGE ConnectionRequest, PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes, BOOLEAN AcceptConnection) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcAcceptConnectPort), 0, 9, PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcAcceptConnectPort), (uint32_t)w32_NtAlpcAcceptConnectPort, 9, PortHandle, ConnectionPortHandle, Flags, ObjectAttributes, PortAttributes, PortContext, ConnectionRequest, ConnectionMessageAttributes, AcceptConnection);
#endif
    }

    NTSTATUS WINAPI NtAlpcCancelMessage(HANDLE PortHandle, ULONG Flags, PALPC_CONTEXT_ATTR MessageContext) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCancelMessage), 0, 3, PortHandle, Flags, MessageContext);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCancelMessage), (uint32_t)w32_NtAlpcCancelMessage, 3, PortHandle, Flags, MessageContext);
#endif
    }

    NTSTATUS WINAPI NtAlpcConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSID RequiredServerSid, PPORT_MESSAGE ConnectionMessage, PULONG BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcConnectPort), 0, 11, PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcConnectPort), (uint32_t)w32_NtAlpcConnectPort, 11, PortHandle, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout);
#endif
    }

    NTSTATUS WINAPI NtAlpcConnectPortEx(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes, POBJECT_ATTRIBUTES ClientPortObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes, ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements, PPORT_MESSAGE ConnectionMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes, PALPC_MESSAGE_ATTRIBUTES InMessageAttributes, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcConnectPortEx), 0, 11, PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcConnectPortEx), (uint32_t)w32_NtAlpcConnectPortEx, 11, PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout);
#endif
    }

    NTSTATUS WINAPI NtAlpcCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, PALPC_PORT_ATTRIBUTES PortAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreatePort), 0, 3, PortHandle, ObjectAttributes, PortAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreatePort), (uint32_t)w32_NtAlpcCreatePort, 3, PortHandle, ObjectAttributes, PortAttributes);
#endif
    }

    NTSTATUS WINAPI NtAlpcCreatePortSection(HANDLE PortHandle, ULONG Flags, HANDLE SectionHandle, SIZE_T SectionSize, PALPC_HANDLE AlpcSectionHandle, PSIZE_T ActualSectionSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreatePortSection), 0, 6, PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreatePortSection), (uint32_t)w32_NtAlpcCreatePortSection, 6, PortHandle, Flags, SectionHandle, SectionSize, AlpcSectionHandle, ActualSectionSize);
#endif
    }

    NTSTATUS WINAPI NtAlpcCreateResourceReserve(HANDLE PortHandle, ULONG Flags, SIZE_T MessageSize, PALPC_HANDLE ResourceId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateResourceReserve), 0, 4, PortHandle, Flags, MessageSize, ResourceId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateResourceReserve), (uint32_t)w32_NtAlpcCreateResourceReserve, 4, PortHandle, Flags, MessageSize, ResourceId);
#endif
    }

    NTSTATUS WINAPI NtAlpcCreateSectionView(HANDLE PortHandle, ULONG Flags, PALPC_DATA_VIEW_ATTR ViewAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateSectionView), 0, 3, PortHandle, Flags, ViewAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateSectionView), (uint32_t)w32_NtAlpcCreateSectionView, 3, PortHandle, Flags, ViewAttributes);
#endif
    }

    NTSTATUS WINAPI NtAlpcCreateSecurityContext(HANDLE PortHandle, ULONG Flags, PALPC_SECURITY_ATTR SecurityAttribute) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateSecurityContext), 0, 3, PortHandle, Flags, SecurityAttribute);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcCreateSecurityContext), (uint32_t)w32_NtAlpcCreateSecurityContext, 3, PortHandle, Flags, SecurityAttribute);
#endif
    }

    NTSTATUS WINAPI NtAlpcDeletePortSection(HANDLE PortHandle, ULONG Flags, ALPC_HANDLE SectionHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeletePortSection), 0, 3, PortHandle, Flags, SectionHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeletePortSection), (uint32_t)w32_NtAlpcDeletePortSection, 3, PortHandle, Flags, SectionHandle);
#endif
    }

    NTSTATUS WINAPI NtAlpcDeleteResourceReserve(HANDLE PortHandle, ULONG Flags, ALPC_HANDLE ResourceId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteResourceReserve), 0, 3, PortHandle, Flags, ResourceId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteResourceReserve), (uint32_t)w32_NtAlpcDeleteResourceReserve, 3, PortHandle, Flags, ResourceId);
#endif
    }

    NTSTATUS WINAPI NtAlpcDeleteSectionView(HANDLE PortHandle, ULONG Flags, PVOID ViewBase) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteSectionView), 0, 3, PortHandle, Flags, ViewBase);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteSectionView), (uint32_t)w32_NtAlpcDeleteSectionView, 3, PortHandle, Flags, ViewBase);
#endif
    }

    NTSTATUS WINAPI NtAlpcDeleteSecurityContext(HANDLE PortHandle, ULONG Flags, ALPC_HANDLE ContextHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteSecurityContext), 0, 3, PortHandle, Flags, ContextHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDeleteSecurityContext), (uint32_t)w32_NtAlpcDeleteSecurityContext, 3, PortHandle, Flags, ContextHandle);
#endif
    }

    NTSTATUS WINAPI NtAlpcDisconnectPort(HANDLE PortHandle, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDisconnectPort), 0, 2, PortHandle, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcDisconnectPort), (uint32_t)w32_NtAlpcDisconnectPort, 2, PortHandle, Flags);
#endif
    }

    NTSTATUS WINAPI NtAlpcImpersonateClientContainerOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcImpersonateClientContainerOfPort), 0, 3, PortHandle, Message, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcImpersonateClientContainerOfPort), (uint32_t)w32_NtAlpcImpersonateClientContainerOfPort, 3, PortHandle, Message, Flags);
#endif
    }

    NTSTATUS WINAPI NtAlpcImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message, PVOID Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcImpersonateClientOfPort), 0, 3, PortHandle, Message, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcImpersonateClientOfPort), (uint32_t)w32_NtAlpcImpersonateClientOfPort, 3, PortHandle, Message, Flags);
#endif
    }

    NTSTATUS WINAPI NtAlpcOpenSenderProcess(PHANDLE ProcessHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcOpenSenderProcess), 0, 6, ProcessHandle, PortHandle, PortMessage, Flags, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcOpenSenderProcess), (uint32_t)w32_NtAlpcOpenSenderProcess, 6, ProcessHandle, PortHandle, PortMessage, Flags, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtAlpcOpenSenderThread(PHANDLE ThreadHandle, HANDLE PortHandle, PPORT_MESSAGE PortMessage, ULONG Flags, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcOpenSenderThread), 0, 6, ThreadHandle, PortHandle, PortMessage, Flags, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcOpenSenderThread), (uint32_t)w32_NtAlpcOpenSenderThread, 6, ThreadHandle, PortHandle, PortMessage, Flags, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtAlpcQueryInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcQueryInformation), 0, 5, PortHandle, PortInformationClass, PortInformation, Length, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcQueryInformation), (uint32_t)w32_NtAlpcQueryInformation, 5, PortHandle, PortInformationClass, PortInformation, Length, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtAlpcQueryInformationMessage(HANDLE PortHandle, PPORT_MESSAGE PortMessage, ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass, PVOID MessageInformation, ULONG Length, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcQueryInformationMessage), 0, 6, PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcQueryInformationMessage), (uint32_t)w32_NtAlpcQueryInformationMessage, 6, PortHandle, PortMessage, MessageInformationClass, MessageInformation, Length, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtAlpcRevokeSecurityContext(HANDLE PortHandle, ULONG Flags, ALPC_HANDLE ContextHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcRevokeSecurityContext), 0, 3, PortHandle, Flags, ContextHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcRevokeSecurityContext), (uint32_t)w32_NtAlpcRevokeSecurityContext, 3, PortHandle, Flags, ContextHandle);
#endif
    }

    NTSTATUS WINAPI NtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessageA, PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes, PPORT_MESSAGE ReceiveMessage, PSIZE_T BufferLength, PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcSendWaitReceivePort), 0, 8, PortHandle, Flags, SendMessageA, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcSendWaitReceivePort), (uint32_t)w32_NtAlpcSendWaitReceivePort, 8, PortHandle, Flags, SendMessageA, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout);
#endif
    }

    NTSTATUS WINAPI NtAlpcSetInformation(HANDLE PortHandle, ALPC_PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcSetInformation), 0, 4, PortHandle, PortInformationClass, PortInformation, Length);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAlpcSetInformation), (uint32_t)w32_NtAlpcSetInformation, 4, PortHandle, PortInformationClass, PortInformation, Length);
#endif
    }

    NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID File1MappedAsAnImage, PVOID File2MappedAsFile) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAreMappedFilesTheSame), 0, 2, File1MappedAsAnImage, File2MappedAsFile);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAreMappedFilesTheSame), (uint32_t)w32_NtAreMappedFilesTheSame, 2, File1MappedAsAnImage, File2MappedAsFile);
#endif
    }

    NTSTATUS WINAPI NtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAssignProcessToJobObject), 0, 2, JobHandle, ProcessHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAssignProcessToJobObject), (uint32_t)w32_NtAssignProcessToJobObject, 2, JobHandle, ProcessHandle);
#endif
    }

    NTSTATUS WINAPI NtAssociateWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, HANDLE IoCompletionHandle, HANDLE TargetObjectHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation, PBOOLEAN AlreadySignaled) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAssociateWaitCompletionPacket), 0, 8, WaitCompletionPacketHandle, IoCompletionHandle, TargetObjectHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation, AlreadySignaled);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtAssociateWaitCompletionPacket), (uint32_t)w32_NtAssociateWaitCompletionPacket, 8, WaitCompletionPacketHandle, IoCompletionHandle, TargetObjectHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation, AlreadySignaled);
#endif
    }

    NTSTATUS WINAPI NtCallEnclave(PENCLAVE_ROUTINE Routine, PVOID Parameter, BOOLEAN WaitForThread, PVOID* ReturnValue) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCallEnclave), 0, 4, Routine, Parameter, WaitForThread, ReturnValue);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCallEnclave), (uint32_t)w32_NtCallEnclave, 4, Routine, Parameter, WaitForThread, ReturnValue);
#endif
    }

    NTSTATUS WINAPI NtCallbackReturn(PVOID OutputBuffer, ULONG OutputLength, NTSTATUS Status) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCallbackReturn), 0, 3, OutputBuffer, OutputLength, Status);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCallbackReturn), (uint32_t)w32_NtCallbackReturn, 3, OutputBuffer, OutputLength, Status);
#endif
    }

    NTSTATUS WINAPI NtCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelIoFile), 0, 2, FileHandle, IoStatusBlock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelIoFile), (uint32_t)w32_NtCancelIoFile, 2, FileHandle, IoStatusBlock);
#endif
    }

    NTSTATUS WINAPI NtCancelIoFileEx(HANDLE FileHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelIoFileEx), 0, 3, FileHandle, IoRequestToCancel, IoStatusBlock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelIoFileEx), (uint32_t)w32_NtCancelIoFileEx, 3, FileHandle, IoRequestToCancel, IoStatusBlock);
#endif
    }

    NTSTATUS WINAPI NtCancelSynchronousIoFile(HANDLE ThreadHandle, PIO_STATUS_BLOCK IoRequestToCancel, PIO_STATUS_BLOCK IoStatusBlock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelSynchronousIoFile), 0, 3, ThreadHandle, IoRequestToCancel, IoStatusBlock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelSynchronousIoFile), (uint32_t)w32_NtCancelSynchronousIoFile, 3, ThreadHandle, IoRequestToCancel, IoStatusBlock);
#endif
    }

    NTSTATUS WINAPI NtCancelTimer(HANDLE TimerHandle, PBOOLEAN CurrentState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelTimer), 0, 2, TimerHandle, CurrentState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelTimer), (uint32_t)w32_NtCancelTimer, 2, TimerHandle, CurrentState);
#endif
    }

    NTSTATUS WINAPI NtCancelTimer2(HANDLE TimerHandle, PT2_CANCEL_PARAMETERS Parameters) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelTimer2), 0, 2, TimerHandle, Parameters);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelTimer2), (uint32_t)w32_NtCancelTimer2, 2, TimerHandle, Parameters);
#endif
    }

    NTSTATUS WINAPI NtCancelWaitCompletionPacket(HANDLE WaitCompletionPacketHandle, BOOLEAN RemoveSignaledPacket) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelWaitCompletionPacket), 0, 2, WaitCompletionPacketHandle, RemoveSignaledPacket);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCancelWaitCompletionPacket), (uint32_t)w32_NtCancelWaitCompletionPacket, 2, WaitCompletionPacketHandle, RemoveSignaledPacket);
#endif
    }

    NTSTATUS WINAPI NtClearEvent(HANDLE EventHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtClearEvent), 0, 1, EventHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtClearEvent), (uint32_t)w32_NtClearEvent, 1, EventHandle);
#endif
    }

    NTSTATUS WINAPI NtClose(HANDLE Handle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtClose), 0, 1, Handle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtClose), (uint32_t)w32_NtClose, 1, Handle);
#endif
    }

    NTSTATUS WINAPI NtCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCloseObjectAuditAlarm), 0, 3, SubsystemName, HandleId, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCloseObjectAuditAlarm), (uint32_t)w32_NtCloseObjectAuditAlarm, 3, SubsystemName, HandleId, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtCommitComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitComplete), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitComplete), (uint32_t)w32_NtCommitComplete, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtCommitEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitEnlistment), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitEnlistment), (uint32_t)w32_NtCommitEnlistment, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtCommitTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitTransaction), 0, 2, TransactionHandle, Wait);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCommitTransaction), (uint32_t)w32_NtCommitTransaction, 2, TransactionHandle, Wait);
#endif
    }

    NTSTATUS WINAPI NtCompactKeys(ULONG Count, HANDLE* KeyArray) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompactKeys), 0, 2, Count, KeyArray);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompactKeys), (uint32_t)w32_NtCompactKeys, 2, Count, KeyArray);
#endif
    }

    NTSTATUS WINAPI NtCompareObjects(HANDLE FirstObjectHandle, HANDLE SecondObjectHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompareObjects), 0, 2, FirstObjectHandle, SecondObjectHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompareObjects), (uint32_t)w32_NtCompareObjects, 2, FirstObjectHandle, SecondObjectHandle);
#endif
    }

    NTSTATUS WINAPI NtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompareTokens), 0, 3, FirstTokenHandle, SecondTokenHandle, Equal);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompareTokens), (uint32_t)w32_NtCompareTokens, 3, FirstTokenHandle, SecondTokenHandle, Equal);
#endif
    }

    NTSTATUS WINAPI NtCompleteConnectPort(HANDLE PortHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompleteConnectPort), 0, 1, PortHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompleteConnectPort), (uint32_t)w32_NtCompleteConnectPort, 1, PortHandle);
#endif
    }

    NTSTATUS WINAPI NtCompressKey(HANDLE Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompressKey), 0, 1, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCompressKey), (uint32_t)w32_NtCompressKey, 1, Key);
#endif
    }

    NTSTATUS WINAPI NtConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtConnectPort), 0, 8, PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtConnectPort), (uint32_t)w32_NtConnectPort, 8, PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength);
#endif
    }

    NTSTATUS WINAPI NtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtContinue), 0, 2, ContextRecord, TestAlert);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtContinue), (uint32_t)w32_NtContinue, 2, ContextRecord, TestAlert);
#endif
    }

    NTSTATUS WINAPI NtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDebugObject), 0, 4, DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDebugObject), (uint32_t)w32_NtCreateDebugObject, 4, DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
#endif
    }

    NTSTATUS WINAPI NtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDirectoryObject), 0, 3, DirectoryHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDirectoryObject), (uint32_t)w32_NtCreateDirectoryObject, 3, DirectoryHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtCreateDirectoryObjectEx(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ShadowDirectoryHandle, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDirectoryObjectEx), 0, 5, DirectoryHandle, DesiredAccess, ObjectAttributes, ShadowDirectoryHandle, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateDirectoryObjectEx), (uint32_t)w32_NtCreateDirectoryObjectEx, 5, DirectoryHandle, DesiredAccess, ObjectAttributes, ShadowDirectoryHandle, Flags);
#endif
    }

    NTSTATUS WINAPI NtCreateEnclave(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T Size, SIZE_T InitialCommitment, ULONG EnclaveType, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEnclave), 0, 9, ProcessHandle, BaseAddress, ZeroBits, Size, InitialCommitment, EnclaveType, EnclaveInformation, EnclaveInformationLength, EnclaveError);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEnclave), (uint32_t)w32_NtCreateEnclave, 9, ProcessHandle, BaseAddress, ZeroBits, Size, InitialCommitment, EnclaveType, EnclaveInformation, EnclaveInformationLength, EnclaveError);
#endif
    }

    NTSTATUS WINAPI NtCreateEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, HANDLE TransactionHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, NOTIFICATION_MASK NotificationMask, PVOID EnlistmentKey) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEnlistment), 0, 8, EnlistmentHandle, DesiredAccess, ResourceManagerHandle, TransactionHandle, ObjectAttributes, CreateOptions, NotificationMask, EnlistmentKey);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEnlistment), (uint32_t)w32_NtCreateEnlistment, 8, EnlistmentHandle, DesiredAccess, ResourceManagerHandle, TransactionHandle, ObjectAttributes, CreateOptions, NotificationMask, EnlistmentKey);
#endif
    }

    NTSTATUS WINAPI NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEvent), 0, 5, EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEvent), (uint32_t)w32_NtCreateEvent, 5, EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
#endif
    }

    NTSTATUS WINAPI NtCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEventPair), 0, 3, EventPairHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateEventPair), (uint32_t)w32_NtCreateEventPair, 3, EventPairHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateFile), 0, 11, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateFile), (uint32_t)w32_NtCreateFile, 11, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
#endif
    }

    NTSTATUS WINAPI NtCreateIRTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateIRTimer), 0, 2, TimerHandle, DesiredAccess);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateIRTimer), (uint32_t)w32_NtCreateIRTimer, 2, TimerHandle, DesiredAccess);
#endif
    }

    NTSTATUS WINAPI NtCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Count) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateIoCompletion), 0, 4, IoCompletionHandle, DesiredAccess, ObjectAttributes, Count);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateIoCompletion), (uint32_t)w32_NtCreateIoCompletion, 4, IoCompletionHandle, DesiredAccess, ObjectAttributes, Count);
#endif
    }

    NTSTATUS WINAPI NtCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateJobObject), 0, 3, JobHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateJobObject), (uint32_t)w32_NtCreateJobObject, 3, JobHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateJobSet), 0, 3, NumJob, UserJobSet, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateJobSet), (uint32_t)w32_NtCreateJobSet, 3, NumJob, UserJobSet, Flags);
#endif
    }

    NTSTATUS WINAPI NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKey), 0, 7, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKey), (uint32_t)w32_NtCreateKey, 7, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
#endif
    }

    NTSTATUS WINAPI NtCreateKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, HANDLE TransactionHandle, PULONG Disposition) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKeyTransacted), 0, 8, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKeyTransacted), (uint32_t)w32_NtCreateKeyTransacted, 8, KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, TransactionHandle, Disposition);
#endif
    }

    NTSTATUS WINAPI NtCreateKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKeyedEvent), 0, 4, KeyedEventHandle, DesiredAccess, ObjectAttributes, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateKeyedEvent), (uint32_t)w32_NtCreateKeyedEvent, 4, KeyedEventHandle, DesiredAccess, ObjectAttributes, Flags);
#endif
    }

    NTSTATUS WINAPI NtCreateLowBoxToken(PHANDLE TokenHandle, HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PSID PackageSid, ULONG CapabilityCount, PSID_AND_ATTRIBUTES Capabilities, ULONG HandleCount, HANDLE* Handles) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateLowBoxToken), 0, 9, TokenHandle, ExistingTokenHandle, DesiredAccess, ObjectAttributes, PackageSid, CapabilityCount, Capabilities, HandleCount, Handles);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateLowBoxToken), (uint32_t)w32_NtCreateLowBoxToken, 9, TokenHandle, ExistingTokenHandle, DesiredAccess, ObjectAttributes, PackageSid, CapabilityCount, Capabilities, HandleCount, Handles);
#endif
    }

    NTSTATUS WINAPI NtCreateMailslotFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota, ULONG MaximumMessageSize, PLARGE_INTEGER ReadTimeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateMailslotFile), 0, 8, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, CreateOptions, MailslotQuota, MaximumMessageSize, ReadTimeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateMailslotFile), (uint32_t)w32_NtCreateMailslotFile, 8, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, CreateOptions, MailslotQuota, MaximumMessageSize, ReadTimeout);
#endif
    }

    NTSTATUS WINAPI NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateMutant), 0, 4, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateMutant), (uint32_t)w32_NtCreateMutant, 4, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
#endif
    }

    NTSTATUS WINAPI NtCreateNamedPipeFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateNamedPipeFile), 0, 14, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateNamedPipeFile), (uint32_t)w32_NtCreateNamedPipeFile, 14, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
#endif
    }

    NTSTATUS WINAPI NtCreatePagingFile(PUNICODE_STRING PageFileName, PLARGE_INTEGER MinimumSize, PLARGE_INTEGER MaximumSize, ULONG Priority) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePagingFile), 0, 4, PageFileName, MinimumSize, MaximumSize, Priority);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePagingFile), (uint32_t)w32_NtCreatePagingFile, 4, PageFileName, MinimumSize, MaximumSize, Priority);
#endif
    }

    NTSTATUS WINAPI NtCreatePartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG PreferredNode) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePartition), 0, 4, PartitionHandle, DesiredAccess, ObjectAttributes, PreferredNode);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePartition), (uint32_t)w32_NtCreatePartition, 4, PartitionHandle, DesiredAccess, ObjectAttributes, PreferredNode);
#endif
    }

    NTSTATUS WINAPI NtCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePort), 0, 5, PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePort), (uint32_t)w32_NtCreatePort, 5, PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
#endif
    }

    NTSTATUS WINAPI NtCreatePrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePrivateNamespace), 0, 4, NamespaceHandle, DesiredAccess, ObjectAttributes, BoundaryDescriptor);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreatePrivateNamespace), (uint32_t)w32_NtCreatePrivateNamespace, 4, NamespaceHandle, DesiredAccess, ObjectAttributes, BoundaryDescriptor);
#endif
    }

    NTSTATUS WINAPI NtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProcess), 0, 8, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProcess), (uint32_t)w32_NtCreateProcess, 8, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
#endif
    }

    NTSTATUS WINAPI NtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProcessEx), 0, 9, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProcessEx), (uint32_t)w32_NtCreateProcessEx, 9, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
#endif
    }

    NTSTATUS WINAPI NtCreateProfile(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, SIZE_T ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, KAFFINITY Affinity) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProfile), 0, 9, ProfileHandle, Process, ProfileBase, ProfileSize, BucketSize, Buffer, BufferSize, ProfileSource, Affinity);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProfile), (uint32_t)w32_NtCreateProfile, 9, ProfileHandle, Process, ProfileBase, ProfileSize, BucketSize, Buffer, BufferSize, ProfileSource, Affinity);
#endif
    }

    NTSTATUS WINAPI NtCreateProfileEx(PHANDLE ProfileHandle, HANDLE Process, PVOID ProfileBase, SIZE_T ProfileSize, ULONG BucketSize, PULONG Buffer, ULONG BufferSize, KPROFILE_SOURCE ProfileSource, USHORT GroupCount, PGROUP_AFFINITY GroupAffinity) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProfileEx), 0, 10, ProfileHandle, Process, ProfileBase, ProfileSize, BucketSize, Buffer, BufferSize, ProfileSource, GroupCount, GroupAffinity);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateProfileEx), (uint32_t)w32_NtCreateProfileEx, 10, ProfileHandle, Process, ProfileBase, ProfileSize, BucketSize, Buffer, BufferSize, ProfileSource, GroupCount, GroupAffinity);
#endif
    }

    NTSTATUS WINAPI NtCreateResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID RmGuid, POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions, PUNICODE_STRING Description) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateResourceManager), 0, 7, ResourceManagerHandle, DesiredAccess, TmHandle, RmGuid, ObjectAttributes, CreateOptions, Description);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateResourceManager), (uint32_t)w32_NtCreateResourceManager, 7, ResourceManagerHandle, DesiredAccess, TmHandle, RmGuid, ObjectAttributes, CreateOptions, Description);
#endif
    }

    NTSTATUS WINAPI NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSection), 0, 7, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSection), (uint32_t)w32_NtCreateSection, 7, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
#endif
    }

    NTSTATUS WINAPI NtCreateSectionEx(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSectionEx), 0, 9, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, ExtendedParameters, ExtendedParameterCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSectionEx), (uint32_t)w32_NtCreateSectionEx, 9, SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle, ExtendedParameters, ExtendedParameterCount);
#endif
    }

    NTSTATUS WINAPI NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSemaphore), 0, 5, SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSemaphore), (uint32_t)w32_NtCreateSemaphore, 5, SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
#endif
    }

    NTSTATUS WINAPI NtCreateSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LinkTarget) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSymbolicLinkObject), 0, 4, LinkHandle, DesiredAccess, ObjectAttributes, LinkTarget);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateSymbolicLinkObject), (uint32_t)w32_NtCreateSymbolicLinkObject, 4, LinkHandle, DesiredAccess, ObjectAttributes, LinkTarget);
#endif
    }

    NTSTATUS WINAPI NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateThread), 0, 8, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateThread), (uint32_t)w32_NtCreateThread, 8, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
#endif
    }

    NTSTATUS WINAPI NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateThreadEx), 0, 11, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateThreadEx), (uint32_t)w32_NtCreateThreadEx, 11, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
#endif
    }

    NTSTATUS WINAPI NtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTimer), 0, 4, TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTimer), (uint32_t)w32_NtCreateTimer, 4, TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
#endif
    }

    NTSTATUS WINAPI NtCreateTimer2(PHANDLE TimerHandle, PVOID Reserved1, PVOID Reserved2, ULONG Attributes, ACCESS_MASK DesiredAccess) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTimer2), 0, 5, TimerHandle, Reserved1, Reserved2, Attributes, DesiredAccess);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTimer2), (uint32_t)w32_NtCreateTimer2, 5, TimerHandle, Reserved1, Reserved2, Attributes, DesiredAccess);
#endif
    }

    NTSTATUS WINAPI NtCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateToken), 0, 13, TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId, ExpirationTime, User, Groups, Privileges, Owner, PrimaryGroup, DefaultDacl, TokenSource);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateToken), (uint32_t)w32_NtCreateToken, 13, TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId, ExpirationTime, User, Groups, Privileges, Owner, PrimaryGroup, DefaultDacl, TokenSource);
#endif
    }

    NTSTATUS WINAPI NtCreateTokenEx(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE TokenType, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes, PTOKEN_GROUPS DeviceGroups, PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE TokenSource) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTokenEx), 0, 17, TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId, ExpirationTime, User, Groups, Privileges, UserAttributes, DeviceAttributes, DeviceGroups, TokenMandatoryPolicy, Owner, PrimaryGroup, DefaultDacl, TokenSource);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTokenEx), (uint32_t)w32_NtCreateTokenEx, 17, TokenHandle, DesiredAccess, ObjectAttributes, TokenType, AuthenticationId, ExpirationTime, User, Groups, Privileges, UserAttributes, DeviceAttributes, DeviceGroups, TokenMandatoryPolicy, Owner, PrimaryGroup, DefaultDacl, TokenSource);
#endif
    }

    NTSTATUS WINAPI NtCreateTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle, ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags, PLARGE_INTEGER Timeout, PUNICODE_STRING Description) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTransaction), 0, 10, TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTransaction), (uint32_t)w32_NtCreateTransaction, 10, TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, Timeout, Description);
#endif
    }

    NTSTATUS WINAPI NtCreateTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, ULONG CreateOptions, ULONG CommitStrength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTransactionManager), 0, 6, TmHandle, DesiredAccess, ObjectAttributes, LogFileName, CreateOptions, CommitStrength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateTransactionManager), (uint32_t)w32_NtCreateTransactionManager, 6, TmHandle, DesiredAccess, ObjectAttributes, LogFileName, CreateOptions, CommitStrength);
#endif
    }

    NTSTATUS WINAPI NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateUserProcess), 0, 11, ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateUserProcess), (uint32_t)w32_NtCreateUserProcess, 11, ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
#endif
    }

    NTSTATUS WINAPI NtCreateWaitCompletionPacket(PHANDLE WaitCompletionPacketHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWaitCompletionPacket), 0, 3, WaitCompletionPacketHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWaitCompletionPacket), (uint32_t)w32_NtCreateWaitCompletionPacket, 3, WaitCompletionPacketHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtCreateWaitablePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxConnectionInfoLength, ULONG MaxMessageLength, ULONG MaxPoolUsage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWaitablePort), 0, 5, PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWaitablePort), (uint32_t)w32_NtCreateWaitablePort, 5, PortHandle, ObjectAttributes, MaxConnectionInfoLength, MaxMessageLength, MaxPoolUsage);
#endif
    }

    NTSTATUS WINAPI NtCreateWnfStateName(PWNF_STATE_NAME StateName, WNF_STATE_NAME_LIFETIME NameLifetime, WNF_DATA_SCOPE DataScope, BOOLEAN PersistData, PCWNF_TYPE_ID TypeId, ULONG MaximumStateSize, PSECURITY_DESCRIPTOR SecurityDescriptor) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWnfStateName), 0, 7, StateName, NameLifetime, DataScope, PersistData, TypeId, MaximumStateSize, SecurityDescriptor);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWnfStateName), (uint32_t)w32_NtCreateWnfStateName, 7, StateName, NameLifetime, DataScope, PersistData, TypeId, MaximumStateSize, SecurityDescriptor);
#endif
    }

    NTSTATUS WINAPI NtCreateWorkerFactory(PHANDLE WorkerFactoryHandleReturn, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE CompletionPortHandle, HANDLE WorkerProcessHandle, PVOID StartRoutine, PVOID StartParameter, ULONG MaxThreadCount, SIZE_T StackReserve, SIZE_T StackCommit) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWorkerFactory), 0, 10, WorkerFactoryHandleReturn, DesiredAccess, ObjectAttributes, CompletionPortHandle, WorkerProcessHandle, StartRoutine, StartParameter, MaxThreadCount, StackReserve, StackCommit);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtCreateWorkerFactory), (uint32_t)w32_NtCreateWorkerFactory, 10, WorkerFactoryHandleReturn, DesiredAccess, ObjectAttributes, CompletionPortHandle, WorkerProcessHandle, StartRoutine, StartParameter, MaxThreadCount, StackReserve, StackCommit);
#endif
    }

    NTSTATUS WINAPI NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDebugActiveProcess), 0, 2, ProcessHandle, DebugObjectHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDebugActiveProcess), (uint32_t)w32_NtDebugActiveProcess, 2, ProcessHandle, DebugObjectHandle);
#endif
    }

    NTSTATUS WINAPI NtDebugContinue(HANDLE DebugObjectHandle, PCLIENT_ID ClientId, NTSTATUS ContinueStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDebugContinue), 0, 3, DebugObjectHandle, ClientId, ContinueStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDebugContinue), (uint32_t)w32_NtDebugContinue, 3, DebugObjectHandle, ClientId, ContinueStatus);
#endif
    }

    NTSTATUS WINAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDelayExecution), 0, 2, Alertable, DelayInterval);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDelayExecution), (uint32_t)w32_NtDelayExecution, 2, Alertable, DelayInterval);
#endif
    }

    NTSTATUS WINAPI NtDeleteAtom(RTL_ATOM Atom) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteAtom), 0, 1, Atom);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteAtom), (uint32_t)w32_NtDeleteAtom, 1, Atom);
#endif
    }

    NTSTATUS WINAPI NtDeleteBootEntry(ULONG Id) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteBootEntry), 0, 1, Id);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteBootEntry), (uint32_t)w32_NtDeleteBootEntry, 1, Id);
#endif
    }

    NTSTATUS WINAPI NtDeleteDriverEntry(ULONG Id) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteDriverEntry), 0, 1, Id);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteDriverEntry), (uint32_t)w32_NtDeleteDriverEntry, 1, Id);
#endif
    }

    NTSTATUS WINAPI NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteFile), 0, 1, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteFile), (uint32_t)w32_NtDeleteFile, 1, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtDeleteKey(HANDLE KeyHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteKey), 0, 1, KeyHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteKey), (uint32_t)w32_NtDeleteKey, 1, KeyHandle);
#endif
    }

    NTSTATUS WINAPI NtDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteObjectAuditAlarm), 0, 3, SubsystemName, HandleId, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteObjectAuditAlarm), (uint32_t)w32_NtDeleteObjectAuditAlarm, 3, SubsystemName, HandleId, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtDeletePrivateNamespace(HANDLE NamespaceHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeletePrivateNamespace), 0, 1, NamespaceHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeletePrivateNamespace), (uint32_t)w32_NtDeletePrivateNamespace, 1, NamespaceHandle);
#endif
    }

    NTSTATUS WINAPI NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteValueKey), 0, 2, KeyHandle, ValueName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteValueKey), (uint32_t)w32_NtDeleteValueKey, 2, KeyHandle, ValueName);
#endif
    }

    NTSTATUS WINAPI NtDeleteWnfStateData(PCWNF_STATE_NAME StateName, void const* ExplicitScope) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteWnfStateData), 0, 2, StateName, ExplicitScope);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteWnfStateData), (uint32_t)w32_NtDeleteWnfStateData, 2, StateName, ExplicitScope);
#endif
    }

    NTSTATUS WINAPI NtDeleteWnfStateName(PCWNF_STATE_NAME StateName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteWnfStateName), 0, 1, StateName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeleteWnfStateName), (uint32_t)w32_NtDeleteWnfStateName, 1, StateName);
#endif
    }

    NTSTATUS WINAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeviceIoControlFile), 0, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDeviceIoControlFile), (uint32_t)w32_NtDeviceIoControlFile, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#endif
    }

    NTSTATUS WINAPI NtDisableLastKnownGood() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDisableLastKnownGood), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDisableLastKnownGood), (uint32_t)w32_NtDisableLastKnownGood, 0);
#endif
    }

    NTSTATUS WINAPI NtDisplayString(PUNICODE_STRING String) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDisplayString), 0, 1, String);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDisplayString), (uint32_t)w32_NtDisplayString, 1, String);
#endif
    }

    NTSTATUS WINAPI NtDrawText(PUNICODE_STRING Text) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDrawText), 0, 1, Text);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDrawText), (uint32_t)w32_NtDrawText, 1, Text);
#endif
    }

    NTSTATUS WINAPI NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDuplicateObject), 0, 7, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDuplicateObject), (uint32_t)w32_NtDuplicateObject, 7, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
#endif
    }

    NTSTATUS WINAPI NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDuplicateToken), 0, 6, ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtDuplicateToken), (uint32_t)w32_NtDuplicateToken, 6, ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle);
#endif
    }

    NTSTATUS WINAPI NtEnableLastKnownGood() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnableLastKnownGood), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnableLastKnownGood), (uint32_t)w32_NtEnableLastKnownGood, 0);
#endif
    }

    NTSTATUS WINAPI NtEnumerateBootEntries(PVOID Buffer, PULONG BufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateBootEntries), 0, 2, Buffer, BufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateBootEntries), (uint32_t)w32_NtEnumerateBootEntries, 2, Buffer, BufferLength);
#endif
    }

    NTSTATUS WINAPI NtEnumerateDriverEntries(PVOID Buffer, PULONG BufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateDriverEntries), 0, 2, Buffer, BufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateDriverEntries), (uint32_t)w32_NtEnumerateDriverEntries, 2, Buffer, BufferLength);
#endif
    }

    NTSTATUS WINAPI NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateKey), 0, 6, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateKey), (uint32_t)w32_NtEnumerateKey, 6, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
#endif
    }

    NTSTATUS WINAPI NtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, PULONG BufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateSystemEnvironmentValuesEx), 0, 3, InformationClass, Buffer, BufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateSystemEnvironmentValuesEx), (uint32_t)w32_NtEnumerateSystemEnvironmentValuesEx, 3, InformationClass, Buffer, BufferLength);
#endif
    }

    NTSTATUS WINAPI NtEnumerateTransactionObject(HANDLE RootObjectHandle, KTMOBJECT_TYPE QueryType, PKTMOBJECT_CURSOR ObjectCursor, ULONG ObjectCursorLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateTransactionObject), 0, 5, RootObjectHandle, QueryType, ObjectCursor, ObjectCursorLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateTransactionObject), (uint32_t)w32_NtEnumerateTransactionObject, 5, RootObjectHandle, QueryType, ObjectCursor, ObjectCursorLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateValueKey), 0, 6, KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtEnumerateValueKey), (uint32_t)w32_NtEnumerateValueKey, 6, KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
#endif
    }

    NTSTATUS WINAPI NtExtendSection(HANDLE SectionHandle, PLARGE_INTEGER NewSectionSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtExtendSection), 0, 2, SectionHandle, NewSectionSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtExtendSection), (uint32_t)w32_NtExtendSection, 2, SectionHandle, NewSectionSize);
#endif
    }

    NTSTATUS WINAPI NtFilterBootOption(FILTER_BOOT_OPTION_OPERATION FilterOperation, ULONG ObjectType, ULONG ElementType, PVOID Data, ULONG DataSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterBootOption), 0, 5, FilterOperation, ObjectType, ElementType, Data, DataSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterBootOption), (uint32_t)w32_NtFilterBootOption, 5, FilterOperation, ObjectType, ElementType, Data, DataSize);
#endif
    }

    NTSTATUS WINAPI NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, PHANDLE NewTokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterToken), 0, 6, ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, NewTokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterToken), (uint32_t)w32_NtFilterToken, 6, ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, NewTokenHandle);
#endif
    }

    NTSTATUS WINAPI NtFilterTokenEx(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS RestrictedSids, ULONG DisableUserClaimsCount, PUNICODE_STRING UserClaimsToDisable, ULONG DisableDeviceClaimsCount, PUNICODE_STRING DeviceClaimsToDisable, PTOKEN_GROUPS DeviceGroupsToDisable, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes, PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes, PTOKEN_GROUPS RestrictedDeviceGroups, PHANDLE NewTokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterTokenEx), 0, 14, ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, DisableUserClaimsCount, UserClaimsToDisable, DisableDeviceClaimsCount, DeviceClaimsToDisable, DeviceGroupsToDisable, RestrictedUserAttributes, RestrictedDeviceAttributes, RestrictedDeviceGroups, NewTokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFilterTokenEx), (uint32_t)w32_NtFilterTokenEx, 14, ExistingTokenHandle, Flags, SidsToDisable, PrivilegesToDelete, RestrictedSids, DisableUserClaimsCount, UserClaimsToDisable, DisableDeviceClaimsCount, DeviceClaimsToDisable, DeviceGroupsToDisable, RestrictedUserAttributes, RestrictedDeviceAttributes, RestrictedDeviceGroups, NewTokenHandle);
#endif
    }

    NTSTATUS WINAPI NtFindAtom(PWSTR AtomName, ULONG Length, PRTL_ATOM Atom) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFindAtom), 0, 3, AtomName, Length, Atom);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFindAtom), (uint32_t)w32_NtFindAtom, 3, AtomName, Length, Atom);
#endif
    }

    NTSTATUS WINAPI NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushBuffersFile), 0, 2, FileHandle, IoStatusBlock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushBuffersFile), (uint32_t)w32_NtFlushBuffersFile, 2, FileHandle, IoStatusBlock);
#endif
    }

    NTSTATUS WINAPI NtFlushBuffersFileEx(HANDLE FileHandle, ULONG Flags, PVOID Parameters, ULONG ParametersSize, PIO_STATUS_BLOCK IoStatusBlock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushBuffersFileEx), 0, 5, FileHandle, Flags, Parameters, ParametersSize, IoStatusBlock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushBuffersFileEx), (uint32_t)w32_NtFlushBuffersFileEx, 5, FileHandle, Flags, Parameters, ParametersSize, IoStatusBlock);
#endif
    }

    NTSTATUS WINAPI NtFlushInstallUILanguage(LANGID InstallUILanguage, ULONG SetComittedFlag) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushInstallUILanguage), 0, 2, InstallUILanguage, SetComittedFlag);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushInstallUILanguage), (uint32_t)w32_NtFlushInstallUILanguage, 2, InstallUILanguage, SetComittedFlag);
#endif
    }

    NTSTATUS WINAPI NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushInstructionCache), 0, 3, ProcessHandle, BaseAddress, Length);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushInstructionCache), (uint32_t)w32_NtFlushInstructionCache, 3, ProcessHandle, BaseAddress, Length);
#endif
    }

    NTSTATUS WINAPI NtFlushKey(HANDLE KeyHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushKey), 0, 1, KeyHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushKey), (uint32_t)w32_NtFlushKey, 1, KeyHandle);
#endif
    }

    void WINAPI NtFlushProcessWriteBuffers() {

        if (!is_syscall_table_initialized()) {
            return;
        }

#ifdef _M_AMD64
        cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushProcessWriteBuffers), 0, 0);
#else
        cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushProcessWriteBuffers), (uint32_t)w32_NtFlushProcessWriteBuffers, 0);
#endif
    }

    NTSTATUS WINAPI NtFlushVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, OUT PIO_STATUS_BLOCK IoStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushVirtualMemory), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushVirtualMemory), (uint32_t)w32_NtFlushVirtualMemory, 0);
#endif
    }

    NTSTATUS WINAPI NtFlushWriteBuffer() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushWriteBuffer), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFlushWriteBuffer), (uint32_t)w32_NtFlushWriteBuffer, 0);
#endif
    }

    NTSTATUS WINAPI NtFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreeUserPhysicalPages), 0, 3, ProcessHandle, NumberOfPages, UserPfnArray);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreeUserPhysicalPages), (uint32_t)w32_NtFreeUserPhysicalPages, 3, ProcessHandle, NumberOfPages, UserPfnArray);
#endif
    }

    NTSTATUS WINAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreeVirtualMemory), 0, 4, ProcessHandle, BaseAddress, RegionSize, FreeType);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreeVirtualMemory), (uint32_t)w32_NtFreeVirtualMemory, 4, ProcessHandle, BaseAddress, RegionSize, FreeType);
#endif
    }

    NTSTATUS WINAPI NtFreezeRegistry(ULONG TimeOutInSeconds) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreezeRegistry), 0, 1, TimeOutInSeconds);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreezeRegistry), (uint32_t)w32_NtFreezeRegistry, 1, TimeOutInSeconds);
#endif
    }

    NTSTATUS WINAPI NtFreezeTransactions(PLARGE_INTEGER FreezeTimeout, PLARGE_INTEGER ThawTimeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreezeTransactions), 0, 2, FreezeTimeout, ThawTimeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFreezeTransactions), (uint32_t)w32_NtFreezeTransactions, 2, FreezeTimeout, ThawTimeout);
#endif
    }

    NTSTATUS WINAPI NtFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFsControlFile), 0, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtFsControlFile), (uint32_t)w32_NtFsControlFile, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#endif
    }

    NTSTATUS WINAPI NtGetCachedSigningLevel(HANDLE File, PULONG Flags, PSE_SIGNING_LEVEL SigningLevel, PUCHAR Thumbprint, PULONG ThumbprintSize, PULONG ThumbprintAlgorithm) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCachedSigningLevel), 0, 6, File, Flags, SigningLevel, Thumbprint, ThumbprintSize, ThumbprintAlgorithm);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCachedSigningLevel), (uint32_t)w32_NtGetCachedSigningLevel, 6, File, Flags, SigningLevel, Thumbprint, ThumbprintSize, ThumbprintAlgorithm);
#endif
    }

    NTSTATUS WINAPI NtGetCompleteWnfStateSubscription(PWNF_STATE_NAME OldDescriptorStateName, ULONG64* OldSubscriptionId, ULONG OldDescriptorEventMask, ULONG OldDescriptorStatus, PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor, ULONG DescriptorSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCompleteWnfStateSubscription), 0, 6, OldDescriptorStateName, OldSubscriptionId, OldDescriptorEventMask, OldDescriptorStatus, NewDeliveryDescriptor, DescriptorSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCompleteWnfStateSubscription), (uint32_t)w32_NtGetCompleteWnfStateSubscription, 6, OldDescriptorStateName, OldSubscriptionId, OldDescriptorEventMask, OldDescriptorStatus, NewDeliveryDescriptor, DescriptorSize);
#endif
    }

    NTSTATUS WINAPI NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetContextThread), 0, 2, ThreadHandle, ThreadContext);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetContextThread), (uint32_t)w32_NtGetContextThread, 2, ThreadHandle, ThreadContext);
#endif
    }

    ULONG WINAPI NtGetCurrentProcessorNumber() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCurrentProcessorNumber), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetCurrentProcessorNumber), (uint32_t)w32_NtGetCurrentProcessorNumber, 0);
#endif
    }

    NTSTATUS WINAPI NtGetDevicePowerState(HANDLE Device, PDEVICE_POWER_STATE State) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetDevicePowerState), 0, 2, Device, State);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetDevicePowerState), (uint32_t)w32_NtGetDevicePowerState, 2, Device, State);
#endif
    }

    NTSTATUS WINAPI NtGetMUIRegistryInfo(ULONG Flags, PULONG DataSize, PVOID Data) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetMUIRegistryInfo), 0, 3, Flags, DataSize, Data);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetMUIRegistryInfo), (uint32_t)w32_NtGetMUIRegistryInfo, 3, Flags, DataSize, Data);
#endif
    }

    NTSTATUS WINAPI NtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNextProcess), 0, 5, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNextProcess), (uint32_t)w32_NtGetNextProcess, 5, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
#endif
    }

    NTSTATUS WINAPI NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNextThread), 0, 6, ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNextThread), (uint32_t)w32_NtGetNextThread, 6, ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
#endif
    }

    NTSTATUS WINAPI NtGetNlsSectionPtr(ULONG SectionType, ULONG SectionData, PVOID ContextData, PVOID* SectionPointer, PULONG SectionSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNlsSectionPtr), 0, 5, SectionType, SectionData, ContextData, SectionPointer, SectionSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNlsSectionPtr), (uint32_t)w32_NtGetNlsSectionPtr, 5, SectionType, SectionData, ContextData, SectionPointer, SectionSize);
#endif
    }

    NTSTATUS WINAPI NtGetNotificationResourceManager(HANDLE ResourceManagerHandle, PTRANSACTION_NOTIFICATION TransactionNotification, ULONG NotificationLength, PLARGE_INTEGER Timeout, PULONG ReturnLength, ULONG Asynchronous, ULONG_PTR AsynchronousContext) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNotificationResourceManager), 0, 7, ResourceManagerHandle, TransactionNotification, NotificationLength, Timeout, ReturnLength, Asynchronous, AsynchronousContext);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetNotificationResourceManager), (uint32_t)w32_NtGetNotificationResourceManager, 7, ResourceManagerHandle, TransactionNotification, NotificationLength, Timeout, ReturnLength, Asynchronous, AsynchronousContext);
#endif
    }

    NTSTATUS WINAPI NtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, SIZE_T RegionSize, PVOID* UserAddressArray, PULONG_PTR EntriesInUserAddressArray, PULONG Granularity) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetWriteWatch), 0, 7, ProcessHandle, Flags, BaseAddress, RegionSize, UserAddressArray, EntriesInUserAddressArray, Granularity);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtGetWriteWatch), (uint32_t)w32_NtGetWriteWatch, 7, ProcessHandle, Flags, BaseAddress, RegionSize, UserAddressArray, EntriesInUserAddressArray, Granularity);
#endif
    }

    NTSTATUS WINAPI NtImpersonateAnonymousToken(HANDLE ThreadHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateAnonymousToken), 0, 1, ThreadHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateAnonymousToken), (uint32_t)w32_NtImpersonateAnonymousToken, 1, ThreadHandle);
#endif
    }

    NTSTATUS WINAPI NtImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateClientOfPort), 0, 2, PortHandle, Message);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateClientOfPort), (uint32_t)w32_NtImpersonateClientOfPort, 2, PortHandle, Message);
#endif
    }

    NTSTATUS WINAPI NtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateThread), 0, 3, ServerThreadHandle, ClientThreadHandle, SecurityQos);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtImpersonateThread), (uint32_t)w32_NtImpersonateThread, 3, ServerThreadHandle, ClientThreadHandle, SecurityQos);
#endif
    }

    NTSTATUS WINAPI NtInitializeEnclave(HANDLE ProcessHandle, PVOID BaseAddress, PVOID EnclaveInformation, ULONG EnclaveInformationLength, PULONG EnclaveError) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeEnclave), 0, 5, ProcessHandle, BaseAddress, EnclaveInformation, EnclaveInformationLength, EnclaveError);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeEnclave), (uint32_t)w32_NtInitializeEnclave, 5, ProcessHandle, BaseAddress, EnclaveInformation, EnclaveInformationLength, EnclaveError);
#endif
    }

    NTSTATUS WINAPI NtInitializeNlsFiles(PVOID* BaseAddress, PLCID DefaultLocaleId, PLARGE_INTEGER DefaultCasingTableSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeNlsFiles), 0, 3, BaseAddress, DefaultLocaleId, DefaultCasingTableSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeNlsFiles), (uint32_t)w32_NtInitializeNlsFiles, 3, BaseAddress, DefaultLocaleId, DefaultCasingTableSize);
#endif
    }

    NTSTATUS WINAPI NtInitializeRegistry(USHORT BootCondition) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeRegistry), 0, 1, BootCondition);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitializeRegistry), (uint32_t)w32_NtInitializeRegistry, 1, BootCondition);
#endif
    }

    NTSTATUS WINAPI NtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitiatePowerAction), 0, 4, SystemAction, LightestSystemState, Flags, Asynchronous);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtInitiatePowerAction), (uint32_t)w32_NtInitiatePowerAction, 4, SystemAction, LightestSystemState, Flags, Asynchronous);
#endif
    }

    NTSTATUS WINAPI NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsProcessInJob), 0, 2, ProcessHandle, JobHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsProcessInJob), (uint32_t)w32_NtIsProcessInJob, 2, ProcessHandle, JobHandle);
#endif
    }

    BOOLEAN WINAPI NtIsSystemResumeAutomatic() {

        if (!is_syscall_table_initialized()) {
            return FALSE;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsSystemResumeAutomatic), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsSystemResumeAutomatic), (uint32_t)w32_NtIsSystemResumeAutomatic, 0);
#endif
    }

    NTSTATUS WINAPI NtIsUILanguageComitted() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsUILanguageComitted), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtIsUILanguageComitted), (uint32_t)w32_NtIsUILanguageComitted, 0);
#endif
    }

    NTSTATUS WINAPI NtListenPort(HANDLE PortHandle, PPORT_MESSAGE ConnectionRequest) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtListenPort), 0, 2, PortHandle, ConnectionRequest);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtListenPort), (uint32_t)w32_NtListenPort, 2, PortHandle, ConnectionRequest);
#endif
    }

    NTSTATUS WINAPI NtLoadDriver(PUNICODE_STRING DriverServiceName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadDriver), 0, 1, DriverServiceName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadDriver), (uint32_t)w32_NtLoadDriver, 1, DriverServiceName);
#endif
    }

    NTSTATUS WINAPI NtLoadEnclaveData(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, ULONG Protect, PVOID PageInformation, ULONG PageInformationLength, PSIZE_T NumberOfBytesWritten, PULONG EnclaveError) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadEnclaveData), 0, 9, ProcessHandle, BaseAddress, Buffer, BufferSize, Protect, PageInformation, PageInformationLength, NumberOfBytesWritten, EnclaveError);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadEnclaveData), (uint32_t)w32_NtLoadEnclaveData, 9, ProcessHandle, BaseAddress, Buffer, BufferSize, Protect, PageInformation, PageInformationLength, NumberOfBytesWritten, EnclaveError);
#endif
    }

    NTSTATUS WINAPI NtLoadKey(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKey), 0, 2, TargetKey, SourceFile);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKey), (uint32_t)w32_NtLoadKey, 2, TargetKey, SourceFile);
#endif
    }

    NTSTATUS WINAPI NtLoadKey2(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKey2), 0, 3, TargetKey, SourceFile, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKey2), (uint32_t)w32_NtLoadKey2, 3, TargetKey, SourceFile, Flags);
#endif
    }

    NTSTATUS WINAPI NtLoadKeyEx(POBJECT_ATTRIBUTES TargetKey, POBJECT_ATTRIBUTES SourceFile, ULONG Flags, HANDLE TrustClassKey, HANDLE Event, ACCESS_MASK DesiredAccess, PHANDLE RootHandle, PIO_STATUS_BLOCK IoStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKeyEx), 0, 8, TargetKey, SourceFile, Flags, TrustClassKey, Event, DesiredAccess, RootHandle, IoStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLoadKeyEx), (uint32_t)w32_NtLoadKeyEx, 8, TargetKey, SourceFile, Flags, TrustClassKey, Event, DesiredAccess, RootHandle, IoStatus);
#endif
    }

    NTSTATUS WINAPI NtLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockFile), 0, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockFile), (uint32_t)w32_NtLockFile, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
#endif
    }

    NTSTATUS WINAPI NtLockProductActivationKeys(ULONG* pPrivateVer, ULONG* pSafeMode) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockProductActivationKeys), 0, 2, pPrivateVer, pSafeMode);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockProductActivationKeys), (uint32_t)w32_NtLockProductActivationKeys, 2, pPrivateVer, pSafeMode);
#endif
    }

    NTSTATUS WINAPI NtLockRegistryKey(HANDLE KeyHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockRegistryKey), 0, 1, KeyHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockRegistryKey), (uint32_t)w32_NtLockRegistryKey, 1, KeyHandle);
#endif
    }

    NTSTATUS WINAPI NtLockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockVirtualMemory), 0, 4, ProcessHandle, BaseAddress, RegionSize, MapType);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtLockVirtualMemory), (uint32_t)w32_NtLockVirtualMemory, 4, ProcessHandle, BaseAddress, RegionSize, MapType);
#endif
    }

    NTSTATUS WINAPI NtMakePermanentObject(HANDLE Handle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMakePermanentObject), 0, 1, Handle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMakePermanentObject), (uint32_t)w32_NtMakePermanentObject, 1, Handle);
#endif
    }

    NTSTATUS WINAPI NtMakeTemporaryObject(HANDLE Handle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMakeTemporaryObject), 0, 1, Handle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMakeTemporaryObject), (uint32_t)w32_NtMakeTemporaryObject, 1, Handle);
#endif
    }

    NTSTATUS WINAPI NtManagePartition(MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass, PVOID PartitionInformation, ULONG PartitionInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtManagePartition), 0, 3, PartitionInformationClass, PartitionInformation, PartitionInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtManagePartition), (uint32_t)w32_NtManagePartition, 3, PartitionInformationClass, PartitionInformation, PartitionInformationLength);
#endif
    }

    NTSTATUS WINAPI NtMapCMFModule(ULONG What, ULONG Index, PULONG CacheIndexOut, PULONG CacheFlagsOut, PULONG ViewSizeOut, PVOID* BaseAddress) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapCMFModule), 0, 6, What, Index, CacheIndexOut, CacheFlagsOut, ViewSizeOut, BaseAddress);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapCMFModule), (uint32_t)w32_NtMapCMFModule, 6, What, Index, CacheIndexOut, CacheFlagsOut, ViewSizeOut, BaseAddress);
#endif
    }

    NTSTATUS WINAPI NtMapUserPhysicalPages(PVOID VirtualAddress, ULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapUserPhysicalPages), 0, 3, VirtualAddress, NumberOfPages, UserPfnArray);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapUserPhysicalPages), (uint32_t)w32_NtMapUserPhysicalPages, 3, VirtualAddress, NumberOfPages, UserPfnArray);
#endif
    }

    NTSTATUS WINAPI NtMapUserPhysicalPagesScatter(PVOID* VirtualAddresses, ULONG_PTR NumberOfPages, PULONG_PTR UserPfnArray) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapUserPhysicalPagesScatter), 0, 3, VirtualAddresses, NumberOfPages, UserPfnArray);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapUserPhysicalPagesScatter), (uint32_t)w32_NtMapUserPhysicalPagesScatter, 3, VirtualAddresses, NumberOfPages, UserPfnArray);
#endif
    }

    NTSTATUS WINAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapViewOfSection), 0, 10, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapViewOfSection), (uint32_t)w32_NtMapViewOfSection, 10, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
#endif
    }

    NTSTATUS WINAPI NtMapViewOfSectionEx(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType, ULONG Win32Protect, MEM_EXTENDED_PARAMETER* Parameters, ULONG ParameterCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapViewOfSectionEx), 0, 9, SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize, AllocationType, Win32Protect, Parameters, ParameterCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtMapViewOfSectionEx), (uint32_t)w32_NtMapViewOfSectionEx, 9, SectionHandle, ProcessHandle, BaseAddress, SectionOffset, ViewSize, AllocationType, Win32Protect, Parameters, ParameterCount);
#endif
    }

    NTSTATUS WINAPI NtModifyBootEntry(PBOOT_ENTRY BootEntry) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtModifyBootEntry), 0, 1, BootEntry);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtModifyBootEntry), (uint32_t)w32_NtModifyBootEntry, 1, BootEntry);
#endif
    }

    NTSTATUS WINAPI NtModifyDriverEntry(PEFI_DRIVER_ENTRY DriverEntry) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtModifyDriverEntry), 0, 1, DriverEntry);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtModifyDriverEntry), (uint32_t)w32_NtModifyDriverEntry, 1, DriverEntry);
#endif
    }

    NTSTATUS WINAPI NtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeDirectoryFile), 0, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, CompletionFilter, WatchTree);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeDirectoryFile), (uint32_t)w32_NtNotifyChangeDirectoryFile, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, CompletionFilter, WatchTree);
#endif
    }

    NTSTATUS WINAPI NtNotifyChangeDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, ULONG CompletionFilter, BOOLEAN WatchTree, DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeDirectoryFileEx), 0, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, CompletionFilter, WatchTree, DirectoryNotifyInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeDirectoryFileEx), (uint32_t)w32_NtNotifyChangeDirectoryFileEx, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, CompletionFilter, WatchTree, DirectoryNotifyInformationClass);
#endif
    }

    NTSTATUS WINAPI NtNotifyChangeKey(HANDLE KeyHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeKey), 0, 10, KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeKey), (uint32_t)w32_NtNotifyChangeKey, 10, KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
#endif
    }

    NTSTATUS WINAPI NtNotifyChangeMultipleKeys(HANDLE MasterKeyHandle, ULONG Count, OBJECT_ATTRIBUTES* SubordinateObjects, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG CompletionFilter, BOOLEAN WatchTree, PVOID Buffer, ULONG BufferSize, BOOLEAN Asynchronous) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeMultipleKeys), 0, 12, MasterKeyHandle, Count, SubordinateObjects, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeMultipleKeys), (uint32_t)w32_NtNotifyChangeMultipleKeys, 12, MasterKeyHandle, Count, SubordinateObjects, Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous);
#endif
    }

    NTSTATUS WINAPI NtNotifyChangeSession(HANDLE SessionHandle, ULONG ChangeSequenceNumber, PLARGE_INTEGER ChangeTimeStamp, IO_SESSION_EVENT Event, IO_SESSION_STATE NewState, IO_SESSION_STATE PreviousState, PVOID Payload, ULONG PayloadSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeSession), 0, 8, SessionHandle, ChangeSequenceNumber, ChangeTimeStamp, Event, NewState, PreviousState, Payload, PayloadSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtNotifyChangeSession), (uint32_t)w32_NtNotifyChangeSession, 8, SessionHandle, ChangeSequenceNumber, ChangeTimeStamp, Event, NewState, PreviousState, Payload, PayloadSize);
#endif
    }

    NTSTATUS WINAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenDirectoryObject), 0, 3, DirectoryHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenDirectoryObject), (uint32_t)w32_NtOpenDirectoryObject, 3, DirectoryHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenEnlistment(PHANDLE EnlistmentHandle, ACCESS_MASK DesiredAccess, HANDLE ResourceManagerHandle, LPGUID EnlistmentGuid, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEnlistment), 0, 5, EnlistmentHandle, DesiredAccess, ResourceManagerHandle, EnlistmentGuid, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEnlistment), (uint32_t)w32_NtOpenEnlistment, 5, EnlistmentHandle, DesiredAccess, ResourceManagerHandle, EnlistmentGuid, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEvent), 0, 3, EventHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEvent), (uint32_t)w32_NtOpenEvent, 3, EventHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEventPair), 0, 3, EventPairHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenEventPair), (uint32_t)w32_NtOpenEventPair, 3, EventPairHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenFile), 0, 6, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenFile), (uint32_t)w32_NtOpenFile, 6, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
#endif
    }

    NTSTATUS WINAPI NtOpenIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenIoCompletion), 0, 3, IoCompletionHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenIoCompletion), (uint32_t)w32_NtOpenIoCompletion, 3, IoCompletionHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenJobObject), 0, 3, JobHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenJobObject), (uint32_t)w32_NtOpenJobObject, 3, JobHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKey), 0, 3, KeyHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKey), (uint32_t)w32_NtOpenKey, 3, KeyHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyEx), 0, 4, KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyEx), (uint32_t)w32_NtOpenKeyEx, 4, KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
#endif
    }

    NTSTATUS WINAPI NtOpenKeyTransacted(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE TransactionHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyTransacted), 0, 4, KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyTransacted), (uint32_t)w32_NtOpenKeyTransacted, 4, KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenKeyTransactedEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions, HANDLE TransactionHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyTransactedEx), 0, 5, KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions, TransactionHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyTransactedEx), (uint32_t)w32_NtOpenKeyTransactedEx, 5, KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions, TransactionHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyedEvent), 0, 3, KeyedEventHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenKeyedEvent), (uint32_t)w32_NtOpenKeyedEvent, 3, KeyedEventHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenMutant), 0, 3, MutantHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenMutant), (uint32_t)w32_NtOpenMutant, 3, MutantHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE ClientToken, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenObjectAuditAlarm), 0, 12, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, ClientToken, DesiredAccess, GrantedAccess, Privileges, ObjectCreation, AccessGranted, GenerateOnClose);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenObjectAuditAlarm), (uint32_t)w32_NtOpenObjectAuditAlarm, 12, SubsystemName, HandleId, ObjectTypeName, ObjectName, SecurityDescriptor, ClientToken, DesiredAccess, GrantedAccess, Privileges, ObjectCreation, AccessGranted, GenerateOnClose);
#endif
    }

    NTSTATUS WINAPI NtOpenPartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenPartition), 0, 3, PartitionHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenPartition), (uint32_t)w32_NtOpenPartition, 3, PartitionHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenPrivateNamespace(PHANDLE NamespaceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID BoundaryDescriptor) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenPrivateNamespace), 0, 4, NamespaceHandle, DesiredAccess, ObjectAttributes, BoundaryDescriptor);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenPrivateNamespace), (uint32_t)w32_NtOpenPrivateNamespace, 4, NamespaceHandle, DesiredAccess, ObjectAttributes, BoundaryDescriptor);
#endif
    }

    NTSTATUS WINAPI NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcess), 0, 4, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcess), (uint32_t)w32_NtOpenProcess, 4, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#endif
    }

    NTSTATUS WINAPI NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcessToken), 0, 3, ProcessHandle, DesiredAccess, TokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcessToken), (uint32_t)w32_NtOpenProcessToken, 3, ProcessHandle, DesiredAccess, TokenHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcessTokenEx), 0, 4, ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenProcessTokenEx), (uint32_t)w32_NtOpenProcessTokenEx, 4, ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenResourceManager(PHANDLE ResourceManagerHandle, ACCESS_MASK DesiredAccess, HANDLE TmHandle, LPGUID ResourceManagerGuid, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenResourceManager), 0, 5, ResourceManagerHandle, DesiredAccess, TmHandle, ResourceManagerGuid, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenResourceManager), (uint32_t)w32_NtOpenResourceManager, 5, ResourceManagerHandle, DesiredAccess, TmHandle, ResourceManagerGuid, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSection), 0, 3, SectionHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSection), (uint32_t)w32_NtOpenSection, 3, SectionHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSemaphore), 0, 3, SemaphoreHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSemaphore), (uint32_t)w32_NtOpenSemaphore, 3, SemaphoreHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenSession(PHANDLE SessionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSession), 0, 3, SessionHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSession), (uint32_t)w32_NtOpenSession, 3, SessionHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenSymbolicLinkObject(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSymbolicLinkObject), 0, 3, LinkHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenSymbolicLinkObject), (uint32_t)w32_NtOpenSymbolicLinkObject, 3, LinkHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThread), 0, 4, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThread), (uint32_t)w32_NtOpenThread, 4, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
#endif
    }

    NTSTATUS WINAPI NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThreadToken), 0, 4, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThreadToken), (uint32_t)w32_NtOpenThreadToken, 4, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThreadTokenEx), 0, 5, ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenThreadTokenEx), (uint32_t)w32_NtOpenThreadTokenEx, 5, ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTimer), 0, 3, TimerHandle, DesiredAccess, ObjectAttributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTimer), (uint32_t)w32_NtOpenTimer, 3, TimerHandle, DesiredAccess, ObjectAttributes);
#endif
    }

    NTSTATUS WINAPI NtOpenTransaction(PHANDLE TransactionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LPGUID Uow, HANDLE TmHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTransaction), 0, 5, TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTransaction), (uint32_t)w32_NtOpenTransaction, 5, TransactionHandle, DesiredAccess, ObjectAttributes, Uow, TmHandle);
#endif
    }

    NTSTATUS WINAPI NtOpenTransactionManager(PHANDLE TmHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING LogFileName, LPGUID TmIdentity, ULONG OpenOptions) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTransactionManager), 0, 6, TmHandle, DesiredAccess, ObjectAttributes, LogFileName, TmIdentity, OpenOptions);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtOpenTransactionManager), (uint32_t)w32_NtOpenTransactionManager, 6, TmHandle, DesiredAccess, ObjectAttributes, LogFileName, TmIdentity, OpenOptions);
#endif
    }

    NTSTATUS WINAPI NtPlugPlayControl(PLUGPLAY_CONTROL_CLASS PnPControlClass, PVOID PnPControlData, ULONG PnPControlDataLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPlugPlayControl), 0, 3, PnPControlClass, PnPControlData, PnPControlDataLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPlugPlayControl), (uint32_t)w32_NtPlugPlayControl, 3, PnPControlClass, PnPControlData, PnPControlDataLength);
#endif
    }

    NTSTATUS WINAPI NtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPowerInformation), 0, 5, InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPowerInformation), (uint32_t)w32_NtPowerInformation, 5, InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
#endif
    }

    NTSTATUS WINAPI NtPrePrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrePrepareComplete), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrePrepareComplete), (uint32_t)w32_NtPrePrepareComplete, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtPrePrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrePrepareEnlistment), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrePrepareEnlistment), (uint32_t)w32_NtPrePrepareEnlistment, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtPrepareComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrepareComplete), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrepareComplete), (uint32_t)w32_NtPrepareComplete, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtPrepareEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrepareEnlistment), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrepareEnlistment), (uint32_t)w32_NtPrepareEnlistment, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtPrivilegeCheck(HANDLE ClientToken, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegeCheck), 0, 3, ClientToken, RequiredPrivileges, Result);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegeCheck), (uint32_t)w32_NtPrivilegeCheck, 3, ClientToken, RequiredPrivileges, Result);
#endif
    }

    NTSTATUS WINAPI NtPrivilegeObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE ClientToken, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegeObjectAuditAlarm), 0, 6, SubsystemName, HandleId, ClientToken, DesiredAccess, Privileges, AccessGranted);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegeObjectAuditAlarm), (uint32_t)w32_NtPrivilegeObjectAuditAlarm, 6, SubsystemName, HandleId, ClientToken, DesiredAccess, Privileges, AccessGranted);
#endif
    }

    NTSTATUS WINAPI NtPrivilegedServiceAuditAlarm(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE ClientToken, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegedServiceAuditAlarm), 0, 5, SubsystemName, ServiceName, ClientToken, Privileges, AccessGranted);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPrivilegedServiceAuditAlarm), (uint32_t)w32_NtPrivilegedServiceAuditAlarm, 5, SubsystemName, ServiceName, ClientToken, Privileges, AccessGranted);
#endif
    }

    NTSTATUS WINAPI NtPropagationComplete(HANDLE ResourceManagerHandle, ULONG RequestCookie, ULONG BufferLength, PVOID Buffer) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPropagationComplete), 0, 4, ResourceManagerHandle, RequestCookie, BufferLength, Buffer);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPropagationComplete), (uint32_t)w32_NtPropagationComplete, 4, ResourceManagerHandle, RequestCookie, BufferLength, Buffer);
#endif
    }

    NTSTATUS WINAPI NtPropagationFailed(HANDLE ResourceManagerHandle, ULONG RequestCookie, NTSTATUS PropStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPropagationFailed), 0, 3, ResourceManagerHandle, RequestCookie, PropStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPropagationFailed), (uint32_t)w32_NtPropagationFailed, 3, ResourceManagerHandle, RequestCookie, PropStatus);
#endif
    }

    NTSTATUS WINAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtProtectVirtualMemory), 0, 5, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtProtectVirtualMemory), (uint32_t)w32_NtProtectVirtualMemory, 5, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
#endif
    }

    NTSTATUS WINAPI NtPulseEvent(HANDLE EventHandle, PLONG PreviousState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPulseEvent), 0, 2, EventHandle, PreviousState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtPulseEvent), (uint32_t)w32_NtPulseEvent, 2, EventHandle, PreviousState);
#endif
    }

    NTSTATUS WINAPI NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryAttributesFile), 0, 2, ObjectAttributes, FileInformation);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryAttributesFile), (uint32_t)w32_NtQueryAttributesFile, 2, ObjectAttributes, FileInformation);
#endif
    }

    NTSTATUS WINAPI NtQueryBootEntryOrder(PULONG Ids, PULONG Count) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryBootEntryOrder), 0, 2, Ids, Count);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryBootEntryOrder), (uint32_t)w32_NtQueryBootEntryOrder, 2, Ids, Count);
#endif
    }

    NTSTATUS WINAPI NtQueryBootOptions(PBOOT_OPTIONS BootOptions, PULONG BootOptionsLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryBootOptions), 0, 2, BootOptions, BootOptionsLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryBootOptions), (uint32_t)w32_NtQueryBootOptions, 2, BootOptions, BootOptionsLength);
#endif
    }

    NTSTATUS WINAPI NtQueryDebugFilterState(ULONG ComponentId, ULONG Level) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDebugFilterState), 0, 2, ComponentId, Level);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDebugFilterState), (uint32_t)w32_NtQueryDebugFilterState, 2, ComponentId, Level);
#endif
    }

    NTSTATUS WINAPI NtQueryDefaultLocale(BOOLEAN UserProfile, PLCID DefaultLocaleId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDefaultLocale), 0, 2, UserProfile, DefaultLocaleId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDefaultLocale), (uint32_t)w32_NtQueryDefaultLocale, 2, UserProfile, DefaultLocaleId);
#endif
    }

    NTSTATUS WINAPI NtQueryDefaultUILanguage(LANGID* DefaultUILanguageId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDefaultUILanguage), 0, 1, DefaultUILanguageId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDefaultUILanguage), (uint32_t)w32_NtQueryDefaultUILanguage, 1, DefaultUILanguageId);
#endif
    }

    NTSTATUS WINAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryFile), 0, 11, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryFile), (uint32_t)w32_NtQueryDirectoryFile, 11, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
#endif
    }

    NTSTATUS WINAPI NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryFileEx), 0, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryFileEx), (uint32_t)w32_NtQueryDirectoryFileEx, 10, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
#endif
    }

    NTSTATUS WINAPI NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryObject), 0, 7, DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDirectoryObject), (uint32_t)w32_NtQueryDirectoryObject, 7, DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryDriverEntryOrder(PULONG Ids, PULONG Count) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDriverEntryOrder), 0, 2, Ids, Count);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryDriverEntryOrder), (uint32_t)w32_NtQueryDriverEntryOrder, 2, Ids, Count);
#endif
    }

    NTSTATUS WINAPI NtQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PVOID EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryEaFile), 0, 9, FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryEaFile), (uint32_t)w32_NtQueryEaFile, 9, FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan);
#endif
    }

    NTSTATUS WINAPI NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryEvent), 0, 5, EventHandle, EventInformationClass, EventInformation, EventInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryEvent), (uint32_t)w32_NtQueryEvent, 5, EventHandle, EventInformationClass, EventInformation, EventInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryFullAttributesFile), 0, 2, ObjectAttributes, FileInformation);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryFullAttributesFile), (uint32_t)w32_NtQueryFullAttributesFile, 2, ObjectAttributes, FileInformation);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationAtom(RTL_ATOM Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationAtom), 0, 5, Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationAtom), (uint32_t)w32_NtQueryInformationAtom, 5, Atom, AtomInformationClass, AtomInformation, AtomInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationByName(POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationByName), 0, 5, ObjectAttributes, IoStatusBlock, FileInformation, Length, FileInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationByName), (uint32_t)w32_NtQueryInformationByName, 5, ObjectAttributes, IoStatusBlock, FileInformation, Length, FileInformationClass);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationEnlistment), 0, 5, EnlistmentHandle, EnlistmentInformationClass, EnlistmentInformation, EnlistmentInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationEnlistment), (uint32_t)w32_NtQueryInformationEnlistment, 5, EnlistmentHandle, EnlistmentInformationClass, EnlistmentInformation, EnlistmentInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationFile), 0, 5, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationFile), (uint32_t)w32_NtQueryInformationFile, 5, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationJobObject), 0, 5, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationJobObject), (uint32_t)w32_NtQueryInformationJobObject, 5, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationPort(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG Length, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationPort), 0, 5, PortHandle, PortInformationClass, PortInformation, Length, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationPort), (uint32_t)w32_NtQueryInformationPort, 5, PortHandle, PortInformationClass, PortInformation, Length, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationProcess), 0, 5, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationProcess), (uint32_t)w32_NtQueryInformationProcess, 5, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationResourceManager), 0, 5, ResourceManagerHandle, ResourceManagerInformationClass, ResourceManagerInformation, ResourceManagerInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationResourceManager), (uint32_t)w32_NtQueryInformationResourceManager, 5, ResourceManagerHandle, ResourceManagerInformationClass, ResourceManagerInformation, ResourceManagerInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationThread), 0, 5, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationThread), (uint32_t)w32_NtQueryInformationThread, 5, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationToken), 0, 5, TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationToken), (uint32_t)w32_NtQueryInformationToken, 5, TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationTransaction(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationTransaction), 0, 5, TransactionHandle, TransactionInformationClass, TransactionInformation, TransactionInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationTransaction), (uint32_t)w32_NtQueryInformationTransaction, 5, TransactionHandle, TransactionInformationClass, TransactionInformation, TransactionInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationTransactionManager(HANDLE TransactionManagerHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, PVOID TransactionManagerInformation, ULONG TransactionManagerInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationTransactionManager), 0, 5, TransactionManagerHandle, TransactionManagerInformationClass, TransactionManagerInformation, TransactionManagerInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationTransactionManager), (uint32_t)w32_NtQueryInformationTransactionManager, 5, TransactionManagerHandle, TransactionManagerInformationClass, TransactionManagerInformation, TransactionManagerInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationWorkerFactory), 0, 5, WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInformationWorkerFactory), (uint32_t)w32_NtQueryInformationWorkerFactory, 5, WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryInstallUILanguage(LANGID* InstallUILanguageId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInstallUILanguage), 0, 1, InstallUILanguageId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryInstallUILanguage), (uint32_t)w32_NtQueryInstallUILanguage, 1, InstallUILanguageId);
#endif
    }

    NTSTATUS WINAPI NtQueryIntervalProfile(KPROFILE_SOURCE ProfileSource, PULONG Interval) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryIntervalProfile), 0, 2, ProfileSource, Interval);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryIntervalProfile), (uint32_t)w32_NtQueryIntervalProfile, 2, ProfileSource, Interval);
#endif
    }

    NTSTATUS WINAPI NtQueryIoCompletion(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryIoCompletion), 0, 5, IoCompletionHandle, IoCompletionInformationClass, IoCompletionInformation, IoCompletionInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryIoCompletion), (uint32_t)w32_NtQueryIoCompletion, 5, IoCompletionHandle, IoCompletionInformationClass, IoCompletionInformation, IoCompletionInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryKey), 0, 5, KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryKey), (uint32_t)w32_NtQueryKey, 5, KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
#endif
    }

    NTSTATUS WINAPI NtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID Data, ULONG DataSize, PULONG ResultDataSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryLicenseValue), 0, 5, ValueName, Type, Data, DataSize, ResultDataSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryLicenseValue), (uint32_t)w32_NtQueryLicenseValue, 5, ValueName, Type, Data, DataSize, ResultDataSize);
#endif
    }

    NTSTATUS WINAPI NtQueryMultipleValueKey(HANDLE KeyHandle, PKEY_VALUE_ENTRY ValueEntries, ULONG EntryCount, PVOID ValueBuffer, PULONG BufferLength, PULONG RequiredBufferLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryMultipleValueKey), 0, 6, KeyHandle, ValueEntries, EntryCount, ValueBuffer, BufferLength, RequiredBufferLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryMultipleValueKey), (uint32_t)w32_NtQueryMultipleValueKey, 6, KeyHandle, ValueEntries, EntryCount, ValueBuffer, BufferLength, RequiredBufferLength);
#endif
    }

    NTSTATUS WINAPI NtQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryMutant), 0, 5, MutantHandle, MutantInformationClass, MutantInformation, MutantInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryMutant), (uint32_t)w32_NtQueryMutant, 5, MutantHandle, MutantInformationClass, MutantInformation, MutantInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryObject), 0, 5, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryObject), (uint32_t)w32_NtQueryObject, 5, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryOpenSubKeys(POBJECT_ATTRIBUTES TargetKey, PULONG HandleCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryOpenSubKeys), 0, 2, TargetKey, HandleCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryOpenSubKeys), (uint32_t)w32_NtQueryOpenSubKeys, 2, TargetKey, HandleCount);
#endif
    }

    NTSTATUS WINAPI NtQueryOpenSubKeysEx(POBJECT_ATTRIBUTES TargetKey, ULONG BufferLength, PVOID Buffer, PULONG RequiredSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryOpenSubKeysEx), 0, 4, TargetKey, BufferLength, Buffer, RequiredSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryOpenSubKeysEx), (uint32_t)w32_NtQueryOpenSubKeysEx, 4, TargetKey, BufferLength, Buffer, RequiredSize);
#endif
    }

    NTSTATUS WINAPI NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryPerformanceCounter), 0, 2, PerformanceCounter, PerformanceFrequency);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryPerformanceCounter), (uint32_t)w32_NtQueryPerformanceCounter, 2, PerformanceCounter, PerformanceFrequency);
#endif
    }

    NTSTATUS WINAPI NtQueryPortInformationProcess() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryPortInformationProcess), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryPortInformationProcess), (uint32_t)w32_NtQueryPortInformationProcess, 0);
#endif
    }

    NTSTATUS WINAPI NtQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, PVOID SidList, ULONG SidListLength, PSID StartSid, BOOLEAN RestartScan) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryQuotaInformationFile), 0, 9, FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, SidList, SidListLength, StartSid, RestartScan);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryQuotaInformationFile), (uint32_t)w32_NtQueryQuotaInformationFile, 9, FileHandle, IoStatusBlock, Buffer, Length, ReturnSingleEntry, SidList, SidListLength, StartSid, RestartScan);
#endif
    }

    NTSTATUS WINAPI NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, SIZE_T SectionInformationLength, PSIZE_T ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySection), 0, 5, SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySection), (uint32_t)w32_NtQuerySection, 5, SectionHandle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySecurityAttributesToken(HANDLE TokenHandle, PUNICODE_STRING Attributes, ULONG NumberOfAttributes, PVOID Buffer, ULONG Length, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySecurityAttributesToken), 0, 6, TokenHandle, Attributes, NumberOfAttributes, Buffer, Length, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySecurityAttributesToken), (uint32_t)w32_NtQuerySecurityAttributesToken, 6, TokenHandle, Attributes, NumberOfAttributes, Buffer, Length, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySecurityObject), 0, 5, Handle, SecurityInformation, SecurityDescriptor, Length, LengthNeeded);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySecurityObject), (uint32_t)w32_NtQuerySecurityObject, 5, Handle, SecurityInformation, SecurityDescriptor, Length, LengthNeeded);
#endif
    }

    NTSTATUS WINAPI NtQuerySemaphore(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySemaphore), 0, 5, SemaphoreHandle, SemaphoreInformationClass, SemaphoreInformation, SemaphoreInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySemaphore), (uint32_t)w32_NtQuerySemaphore, 5, SemaphoreHandle, SemaphoreInformationClass, SemaphoreInformation, SemaphoreInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySymbolicLinkObject), 0, 3, LinkHandle, LinkTarget, ReturnedLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySymbolicLinkObject), (uint32_t)w32_NtQuerySymbolicLinkObject, 3, LinkHandle, LinkTarget, ReturnedLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySystemEnvironmentValue(PUNICODE_STRING VariableName, PWSTR VariableValue, USHORT ValueLength, PUSHORT ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemEnvironmentValue), 0, 4, VariableName, VariableValue, ValueLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemEnvironmentValue), (uint32_t)w32_NtQuerySystemEnvironmentValue, 4, VariableName, VariableValue, ValueLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemEnvironmentValueEx), 0, 5, VariableName, VendorGuid, Value, ValueLength, Attributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemEnvironmentValueEx), (uint32_t)w32_NtQuerySystemEnvironmentValueEx, 5, VariableName, VendorGuid, Value, ValueLength, Attributes);
#endif
    }

    NTSTATUS WINAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemInformation), 0, 4, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemInformation), (uint32_t)w32_NtQuerySystemInformation, 4, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemInformationEx), 0, 6, SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQuerySystemInformationEx), (uint32_t)w32_NtQuerySystemInformationEx, 6, SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryTimer), 0, 5, TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryTimer), (uint32_t)w32_NtQueryTimer, 5, TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryTimerResolution(PULONG MaximumTime, PULONG MinimumTime, PULONG CurrentTime) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryTimerResolution), 0, 3, MaximumTime, MinimumTime, CurrentTime);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryTimerResolution), (uint32_t)w32_NtQueryTimerResolution, 3, MaximumTime, MinimumTime, CurrentTime);
#endif
    }

    NTSTATUS WINAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryValueKey), 0, 6, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryValueKey), (uint32_t)w32_NtQueryValueKey, 6, KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
#endif
    }

    NTSTATUS WINAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryVirtualMemory), 0, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryVirtualMemory), (uint32_t)w32_NtQueryVirtualMemory, 6, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryVolumeInformationFile), 0, 5, FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryVolumeInformationFile), (uint32_t)w32_NtQueryVolumeInformationFile, 5, FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
#endif
    }

    NTSTATUS WINAPI NtQueryWnfStateData(PCWNF_STATE_NAME StateName, PCWNF_TYPE_ID TypeId, void const* ExplicitScope, PWNF_CHANGE_STAMP ChangeStamp, PVOID Buffer, PULONG BufferSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryWnfStateData), 0, 6, StateName, TypeId, ExplicitScope, ChangeStamp, Buffer, BufferSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryWnfStateData), (uint32_t)w32_NtQueryWnfStateData, 6, StateName, TypeId, ExplicitScope, ChangeStamp, Buffer, BufferSize);
#endif
    }

    NTSTATUS WINAPI NtQueryWnfStateNameInformation(PCWNF_STATE_NAME StateName, WNF_STATE_NAME_INFORMATION NameInfoClass, void const* ExplicitScope, PVOID InfoBuffer, ULONG InfoBufferSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryWnfStateNameInformation), 0, 5, StateName, NameInfoClass, ExplicitScope, InfoBuffer, InfoBufferSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueryWnfStateNameInformation), (uint32_t)w32_NtQueryWnfStateNameInformation, 5, StateName, NameInfoClass, ExplicitScope, InfoBuffer, InfoBufferSize);
#endif
    }

    NTSTATUS WINAPI NtQueueApcThread(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueueApcThread), 0, 5, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueueApcThread), (uint32_t)w32_NtQueueApcThread, 5, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
#endif
    }

    NTSTATUS WINAPI NtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueueApcThreadEx), 0, 6, ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtQueueApcThreadEx), (uint32_t)w32_NtQueueApcThreadEx, 6, ThreadHandle, UserApcReserveHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
#endif
    }

    NTSTATUS WINAPI NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOLEAN FirstChance) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRaiseException), 0, 3, ExceptionRecord, ContextRecord, FirstChance);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRaiseException), (uint32_t)w32_NtRaiseException, 3, ExceptionRecord, ContextRecord, FirstChance);
#endif
    }

    NTSTATUS WINAPI NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRaiseHardError), 0, 6, ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRaiseHardError), (uint32_t)w32_NtRaiseHardError, 6, ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response);
#endif
    }

    NTSTATUS WINAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadFile), 0, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadFile), (uint32_t)w32_NtReadFile, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
#endif
    }

    NTSTATUS WINAPI NtReadFileScatter(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadFileScatter), 0, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, SegmentArray, Length, ByteOffset, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadFileScatter), (uint32_t)w32_NtReadFileScatter, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, SegmentArray, Length, ByteOffset, Key);
#endif
    }

    NTSTATUS WINAPI NtReadOnlyEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadOnlyEnlistment), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadOnlyEnlistment), (uint32_t)w32_NtReadOnlyEnlistment, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtReadRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG DataEntryIndex, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadRequestData), 0, 6, PortHandle, Message, DataEntryIndex, Buffer, BufferSize, NumberOfBytesRead);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadRequestData), (uint32_t)w32_NtReadRequestData, 6, PortHandle, Message, DataEntryIndex, Buffer, BufferSize, NumberOfBytesRead);
#endif
    }

    NTSTATUS WINAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadVirtualMemory), 0, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReadVirtualMemory), (uint32_t)w32_NtReadVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
#endif
    }

    NTSTATUS WINAPI NtRecoverEnlistment(HANDLE EnlistmentHandle, PVOID EnlistmentKey) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverEnlistment), 0, 2, EnlistmentHandle, EnlistmentKey);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverEnlistment), (uint32_t)w32_NtRecoverEnlistment, 2, EnlistmentHandle, EnlistmentKey);
#endif
    }

    NTSTATUS WINAPI NtRecoverResourceManager(HANDLE ResourceManagerHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverResourceManager), 0, 1, ResourceManagerHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverResourceManager), (uint32_t)w32_NtRecoverResourceManager, 1, ResourceManagerHandle);
#endif
    }

    NTSTATUS WINAPI NtRecoverTransactionManager(HANDLE TransactionManagerHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverTransactionManager), 0, 1, TransactionManagerHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRecoverTransactionManager), (uint32_t)w32_NtRecoverTransactionManager, 1, TransactionManagerHandle);
#endif
    }

    NTSTATUS WINAPI NtRegisterProtocolAddressInformation(HANDLE ResourceManager, PCRM_PROTOCOL_ID ProtocolId, ULONG ProtocolInformationSize, PVOID ProtocolInformation, ULONG CreateOptions) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRegisterProtocolAddressInformation), 0, 5, ResourceManager, ProtocolId, ProtocolInformationSize, ProtocolInformation, CreateOptions);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRegisterProtocolAddressInformation), (uint32_t)w32_NtRegisterProtocolAddressInformation, 5, ResourceManager, ProtocolId, ProtocolInformationSize, ProtocolInformation, CreateOptions);
#endif
    }

    NTSTATUS WINAPI NtRegisterThreadTerminatePort(HANDLE PortHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRegisterThreadTerminatePort), 0, 1, PortHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRegisterThreadTerminatePort), (uint32_t)w32_NtRegisterThreadTerminatePort, 1, PortHandle);
#endif
    }

    NTSTATUS WINAPI NtReleaseKeyedEvent(HANDLE KeyedEventHandle, PVOID KeyValue, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseKeyedEvent), 0, 4, KeyedEventHandle, KeyValue, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseKeyedEvent), (uint32_t)w32_NtReleaseKeyedEvent, 4, KeyedEventHandle, KeyValue, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseMutant), 0, 2, MutantHandle, PreviousCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseMutant), (uint32_t)w32_NtReleaseMutant, 2, MutantHandle, PreviousCount);
#endif
    }

    NTSTATUS WINAPI NtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseSemaphore), 0, 3, SemaphoreHandle, ReleaseCount, PreviousCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseSemaphore), (uint32_t)w32_NtReleaseSemaphore, 3, SemaphoreHandle, ReleaseCount, PreviousCount);
#endif
    }

    NTSTATUS WINAPI NtReleaseWorkerFactoryWorker(HANDLE WorkerFactoryHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseWorkerFactoryWorker), 0, 1, WorkerFactoryHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReleaseWorkerFactoryWorker), (uint32_t)w32_NtReleaseWorkerFactoryWorker, 1, WorkerFactoryHandle);
#endif
    }

    NTSTATUS WINAPI NtRemoveIoCompletion(HANDLE IoCompletionHandle, PVOID* KeyContext, PVOID* ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveIoCompletion), 0, 5, IoCompletionHandle, KeyContext, ApcContext, IoStatusBlock, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveIoCompletion), (uint32_t)w32_NtRemoveIoCompletion, 5, IoCompletionHandle, KeyContext, ApcContext, IoStatusBlock, Timeout);
#endif
    }

    NTSTATUS WINAPI NtRemoveIoCompletionEx(HANDLE IoCompletionHandle, PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation, ULONG Count, PULONG NumEntriesRemoved, PLARGE_INTEGER Timeout, BOOLEAN Alertable) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveIoCompletionEx), 0, 6, IoCompletionHandle, IoCompletionInformation, Count, NumEntriesRemoved, Timeout, Alertable);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveIoCompletionEx), (uint32_t)w32_NtRemoveIoCompletionEx, 6, IoCompletionHandle, IoCompletionInformation, Count, NumEntriesRemoved, Timeout, Alertable);
#endif
    }

    NTSTATUS WINAPI NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveProcessDebug), 0, 2, ProcessHandle, DebugObjectHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRemoveProcessDebug), (uint32_t)w32_NtRemoveProcessDebug, 2, ProcessHandle, DebugObjectHandle);
#endif
    }

    NTSTATUS WINAPI NtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRenameKey), 0, 2, KeyHandle, NewName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRenameKey), (uint32_t)w32_NtRenameKey, 2, KeyHandle, NewName);
#endif
    }

    NTSTATUS WINAPI NtRenameTransactionManager(PUNICODE_STRING LogFileName, LPGUID ExistingTransactionManagerGuid) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRenameTransactionManager), 0, 2, LogFileName, ExistingTransactionManagerGuid);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRenameTransactionManager), (uint32_t)w32_NtRenameTransactionManager, 2, LogFileName, ExistingTransactionManagerGuid);
#endif
    }

    NTSTATUS WINAPI NtReplaceKey(POBJECT_ATTRIBUTES NewFile, HANDLE TargetHandle, POBJECT_ATTRIBUTES OldFile) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplaceKey), 0, 3, NewFile, TargetHandle, OldFile);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplaceKey), (uint32_t)w32_NtReplaceKey, 3, NewFile, TargetHandle, OldFile);
#endif
    }

    NTSTATUS WINAPI NtReplacePartitionUnit(PUNICODE_STRING TargetInstancePath, PUNICODE_STRING SpareInstancePath, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplacePartitionUnit), 0, 3, TargetInstancePath, SpareInstancePath, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplacePartitionUnit), (uint32_t)w32_NtReplacePartitionUnit, 3, TargetInstancePath, SpareInstancePath, Flags);
#endif
    }

    NTSTATUS WINAPI NtReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyPort), 0, 2, PortHandle, ReplyMessage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyPort), (uint32_t)w32_NtReplyPort, 2, PortHandle, ReplyMessage);
#endif
    }

    NTSTATUS WINAPI NtReplyWaitReceivePort(HANDLE PortHandle, PVOID* PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReceivePort), 0, 4, PortHandle, PortContext, ReplyMessage, ReceiveMessage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReceivePort), (uint32_t)w32_NtReplyWaitReceivePort, 4, PortHandle, PortContext, ReplyMessage, ReceiveMessage);
#endif
    }

    NTSTATUS WINAPI NtReplyWaitReceivePortEx(HANDLE PortHandle, PVOID* PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReceivePortEx), 0, 5, PortHandle, PortContext, ReplyMessage, ReceiveMessage, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReceivePortEx), (uint32_t)w32_NtReplyWaitReceivePortEx, 5, PortHandle, PortContext, ReplyMessage, ReceiveMessage, Timeout);
#endif
    }

    NTSTATUS WINAPI NtReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReplyPort), 0, 2, PortHandle, ReplyMessage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtReplyWaitReplyPort), (uint32_t)w32_NtReplyWaitReplyPort, 2, PortHandle, ReplyMessage);
#endif
    }

    NTSTATUS WINAPI NtRequestPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRequestPort), 0, 2, PortHandle, RequestMessage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRequestPort), (uint32_t)w32_NtRequestPort, 2, PortHandle, RequestMessage);
#endif
    }

    NTSTATUS WINAPI NtRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRequestWaitReplyPort), 0, 3, PortHandle, RequestMessage, ReplyMessage);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRequestWaitReplyPort), (uint32_t)w32_NtRequestWaitReplyPort, 3, PortHandle, RequestMessage, ReplyMessage);
#endif
    }

    NTSTATUS WINAPI NtResetEvent(HANDLE EventHandle, PLONG PreviousState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResetEvent), 0, 2, EventHandle, PreviousState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResetEvent), (uint32_t)w32_NtResetEvent, 2, EventHandle, PreviousState);
#endif
    }

    NTSTATUS WINAPI NtResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResetWriteWatch), 0, 3, ProcessHandle, BaseAddress, RegionSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResetWriteWatch), (uint32_t)w32_NtResetWriteWatch, 3, ProcessHandle, BaseAddress, RegionSize);
#endif
    }

    NTSTATUS WINAPI NtRestoreKey(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRestoreKey), 0, 3, KeyHandle, FileHandle, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRestoreKey), (uint32_t)w32_NtRestoreKey, 3, KeyHandle, FileHandle, Flags);
#endif
    }

    NTSTATUS WINAPI NtResumeProcess(HANDLE ProcessHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResumeProcess), 0, 1, ProcessHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResumeProcess), (uint32_t)w32_NtResumeProcess, 1, ProcessHandle);
#endif
    }

    NTSTATUS WINAPI NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResumeThread), 0, 2, ThreadHandle, PreviousSuspendCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtResumeThread), (uint32_t)w32_NtResumeThread, 2, ThreadHandle, PreviousSuspendCount);
#endif
    }

    NTSTATUS WINAPI NtRevertContainerImpersonation() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRevertContainerImpersonation), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRevertContainerImpersonation), (uint32_t)w32_NtRevertContainerImpersonation, 0);
#endif
    }

    NTSTATUS WINAPI NtRollbackComplete(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackComplete), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackComplete), (uint32_t)w32_NtRollbackComplete, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtRollbackEnlistment(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackEnlistment), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackEnlistment), (uint32_t)w32_NtRollbackEnlistment, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtRollbackTransaction(HANDLE TransactionHandle, BOOLEAN Wait) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackTransaction), 0, 2, TransactionHandle, Wait);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollbackTransaction), (uint32_t)w32_NtRollbackTransaction, 2, TransactionHandle, Wait);
#endif
    }

    NTSTATUS WINAPI NtRollforwardTransactionManager(HANDLE TransactionManagerHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollforwardTransactionManager), 0, 2, TransactionManagerHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtRollforwardTransactionManager), (uint32_t)w32_NtRollforwardTransactionManager, 2, TransactionManagerHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveKey), 0, 2, KeyHandle, FileHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveKey), (uint32_t)w32_NtSaveKey, 2, KeyHandle, FileHandle);
#endif
    }

    NTSTATUS WINAPI NtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveKeyEx), 0, 3, KeyHandle, FileHandle, Format);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveKeyEx), (uint32_t)w32_NtSaveKeyEx, 3, KeyHandle, FileHandle, Format);
#endif
    }

    NTSTATUS WINAPI NtSaveMergedKeys(HANDLE HighPrecedenceKeyHandle, HANDLE LowPrecedenceKeyHandle, HANDLE FileHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveMergedKeys), 0, 3, HighPrecedenceKeyHandle, LowPrecedenceKeyHandle, FileHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSaveMergedKeys), (uint32_t)w32_NtSaveMergedKeys, 3, HighPrecedenceKeyHandle, LowPrecedenceKeyHandle, FileHandle);
#endif
    }

    NTSTATUS WINAPI NtSecureConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PSID RequiredServerSid, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSecureConnectPort), 0, 9, PortHandle, PortName, SecurityQos, ClientView, RequiredServerSid, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSecureConnectPort), (uint32_t)w32_NtSecureConnectPort, 9, PortHandle, PortName, SecurityQos, ClientView, RequiredServerSid, ServerView, MaxMessageLength, ConnectionInformation, ConnectionInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSerializeBoot() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSerializeBoot), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSerializeBoot), (uint32_t)w32_NtSerializeBoot, 0);
#endif
    }

    NTSTATUS WINAPI NtSetBootEntryOrder(PULONG Ids, ULONG Count) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetBootEntryOrder), 0, 2, Ids, Count);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetBootEntryOrder), (uint32_t)w32_NtSetBootEntryOrder, 2, Ids, Count);
#endif
    }

    NTSTATUS WINAPI NtSetBootOptions(PBOOT_OPTIONS BootOptions, ULONG FieldsToChange) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetBootOptions), 0, 2, BootOptions, FieldsToChange);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetBootOptions), (uint32_t)w32_NtSetBootOptions, 2, BootOptions, FieldsToChange);
#endif
    }

    NTSTATUS WINAPI NtSetCachedSigningLevel(ULONG Flags, SE_SIGNING_LEVEL InputSigningLevel, PHANDLE SourceFiles, ULONG SourceFileCount, HANDLE TargetFile) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetCachedSigningLevel), 0, 5, Flags, InputSigningLevel, SourceFiles, SourceFileCount, TargetFile);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetCachedSigningLevel), (uint32_t)w32_NtSetCachedSigningLevel, 5, Flags, InputSigningLevel, SourceFiles, SourceFileCount, TargetFile);
#endif
    }

    NTSTATUS WINAPI NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetContextThread), 0, 2, ThreadHandle, ThreadContext);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetContextThread), (uint32_t)w32_NtSetContextThread, 2, ThreadHandle, ThreadContext);
#endif
    }

    NTSTATUS WINAPI NtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDebugFilterState), 0, 3, ComponentId, Level, State);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDebugFilterState), (uint32_t)w32_NtSetDebugFilterState, 3, ComponentId, Level, State);
#endif
    }

    NTSTATUS WINAPI NtSetDefaultHardErrorPort(HANDLE DefaultHardErrorPort) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultHardErrorPort), 0, 1, DefaultHardErrorPort);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultHardErrorPort), (uint32_t)w32_NtSetDefaultHardErrorPort, 1, DefaultHardErrorPort);
#endif
    }

    NTSTATUS WINAPI NtSetDefaultLocale(BOOLEAN UserProfile, LCID DefaultLocaleId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultLocale), 0, 2, UserProfile, DefaultLocaleId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultLocale), (uint32_t)w32_NtSetDefaultLocale, 2, UserProfile, DefaultLocaleId);
#endif
    }

    NTSTATUS WINAPI NtSetDefaultUILanguage(LANGID DefaultUILanguageId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultUILanguage), 0, 1, DefaultUILanguageId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDefaultUILanguage), (uint32_t)w32_NtSetDefaultUILanguage, 1, DefaultUILanguageId);
#endif
    }

    NTSTATUS WINAPI NtSetDriverEntryOrder(PULONG Ids, ULONG Count) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDriverEntryOrder), 0, 2, Ids, Count);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetDriverEntryOrder), (uint32_t)w32_NtSetDriverEntryOrder, 2, Ids, Count);
#endif
    }

    NTSTATUS WINAPI NtSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEaFile), 0, 4, FileHandle, IoStatusBlock, Buffer, Length);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEaFile), (uint32_t)w32_NtSetEaFile, 4, FileHandle, IoStatusBlock, Buffer, Length);
#endif
    }

    NTSTATUS WINAPI NtSetEvent(HANDLE EventHandle, PLONG PreviousState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEvent), 0, 2, EventHandle, PreviousState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEvent), (uint32_t)w32_NtSetEvent, 2, EventHandle, PreviousState);
#endif
    }

    NTSTATUS WINAPI NtSetEventBoostPriority(HANDLE EventHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEventBoostPriority), 0, 1, EventHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetEventBoostPriority), (uint32_t)w32_NtSetEventBoostPriority, 1, EventHandle);
#endif
    }

    NTSTATUS WINAPI NtSetHighEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetHighEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetHighEventPair), (uint32_t)w32_NtSetHighEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtSetHighWaitLowEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetHighWaitLowEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetHighWaitLowEventPair), (uint32_t)w32_NtSetHighWaitLowEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtSetIRTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIRTimer), 0, 2, TimerHandle, DueTime);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIRTimer), (uint32_t)w32_NtSetIRTimer, 2, TimerHandle, DueTime);
#endif
    }

    NTSTATUS WINAPI NtSetInformationDebugObject(HANDLE DebugObjectHandle, DEBUGOBJECTINFOCLASS DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationDebugObject), 0, 5, DebugObjectHandle, DebugObjectInformationClass, DebugInformation, DebugInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationDebugObject), (uint32_t)w32_NtSetInformationDebugObject, 5, DebugObjectHandle, DebugObjectInformationClass, DebugInformation, DebugInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationEnlistment(HANDLE EnlistmentHandle, ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass, PVOID EnlistmentInformation, ULONG EnlistmentInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationEnlistment), 0, 4, EnlistmentHandle, EnlistmentInformationClass, EnlistmentInformation, EnlistmentInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationEnlistment), (uint32_t)w32_NtSetInformationEnlistment, 4, EnlistmentHandle, EnlistmentInformationClass, EnlistmentInformation, EnlistmentInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationFile), 0, 5, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationFile), (uint32_t)w32_NtSetInformationFile, 5, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
#endif
    }

    NTSTATUS WINAPI NtSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobObjectInformationClass, PVOID JobObjectInformation, ULONG JobObjectInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationJobObject), 0, 4, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationJobObject), (uint32_t)w32_NtSetInformationJobObject, 4, JobHandle, JobObjectInformationClass, JobObjectInformation, JobObjectInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeySetInformationClass, PVOID KeySetInformation, ULONG KeySetInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationKey), 0, 4, KeyHandle, KeySetInformationClass, KeySetInformation, KeySetInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationKey), (uint32_t)w32_NtSetInformationKey, 4, KeyHandle, KeySetInformationClass, KeySetInformation, KeySetInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationObject), 0, 4, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationObject), (uint32_t)w32_NtSetInformationObject, 4, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationProcess), 0, 4, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationProcess), (uint32_t)w32_NtSetInformationProcess, 4, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationResourceManager(HANDLE ResourceManagerHandle, RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass, PVOID ResourceManagerInformation, ULONG ResourceManagerInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationResourceManager), 0, 4, ResourceManagerHandle, ResourceManagerInformationClass, ResourceManagerInformation, ResourceManagerInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationResourceManager), (uint32_t)w32_NtSetInformationResourceManager, 4, ResourceManagerHandle, ResourceManagerInformationClass, ResourceManagerInformation, ResourceManagerInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationThread), 0, 4, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationThread), (uint32_t)w32_NtSetInformationThread, 4, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationToken), 0, 4, TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationToken), (uint32_t)w32_NtSetInformationToken, 4, TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationTransaction(HANDLE TransactionHandle, TRANSACTION_INFORMATION_CLASS TransactionInformationClass, PVOID TransactionInformation, ULONG TransactionInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationTransaction), 0, 4, TransactionHandle, TransactionInformationClass, TransactionInformation, TransactionInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationTransaction), (uint32_t)w32_NtSetInformationTransaction, 4, TransactionHandle, TransactionInformationClass, TransactionInformation, TransactionInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationTransactionManager(HANDLE TmHandle, TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass, PVOID TransactionManagerInformation, ULONG TransactionManagerInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationTransactionManager), 0, 4, TmHandle, TransactionManagerInformationClass, TransactionManagerInformation, TransactionManagerInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationTransactionManager), (uint32_t)w32_NtSetInformationTransactionManager, 4, TmHandle, TransactionManagerInformationClass, TransactionManagerInformation, TransactionManagerInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationVirtualMemory(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, ULONG_PTR NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationVirtualMemory), 0, 6, ProcessHandle, VmInformationClass, NumberOfEntries, VirtualAddresses, VmInformation, VmInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationVirtualMemory), (uint32_t)w32_NtSetInformationVirtualMemory, 6, ProcessHandle, VmInformationClass, NumberOfEntries, VirtualAddresses, VmInformation, VmInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetInformationWorkerFactory(HANDLE WorkerFactoryHandle, WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationWorkerFactory), 0, 4, WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetInformationWorkerFactory), (uint32_t)w32_NtSetInformationWorkerFactory, 4, WorkerFactoryHandle, WorkerFactoryInformationClass, WorkerFactoryInformation, WorkerFactoryInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIntervalProfile), 0, 2, Interval, Source);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIntervalProfile), (uint32_t)w32_NtSetIntervalProfile, 2, Interval, Source);
#endif
    }

    NTSTATUS WINAPI NtSetIoCompletion(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIoCompletion), 0, 5, IoCompletionHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIoCompletion), (uint32_t)w32_NtSetIoCompletion, 5, IoCompletionHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
#endif
    }

    NTSTATUS WINAPI NtSetIoCompletionEx(HANDLE IoCompletionHandle, HANDLE IoCompletionPacketHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIoCompletionEx), 0, 6, IoCompletionHandle, IoCompletionPacketHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetIoCompletionEx), (uint32_t)w32_NtSetIoCompletionEx, 6, IoCompletionHandle, IoCompletionPacketHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation);
#endif
    }

    NTSTATUS WINAPI NtSetLdtEntries(ULONG Selector0, ULONG Entry0Low, ULONG Entry0Hi, ULONG Selector1, ULONG Entry1Low, ULONG Entry1Hi) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLdtEntries), 0, 6, Selector0, Entry0Low, Entry0Hi, Selector1, Entry1Low, Entry1Hi);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLdtEntries), (uint32_t)w32_NtSetLdtEntries, 6, Selector0, Entry0Low, Entry0Hi, Selector1, Entry1Low, Entry1Hi);
#endif
    }

    NTSTATUS WINAPI NtSetLowEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLowEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLowEventPair), (uint32_t)w32_NtSetLowEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtSetLowWaitHighEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLowWaitHighEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetLowWaitHighEventPair), (uint32_t)w32_NtSetLowWaitHighEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetQuotaInformationFile), 0, 4, FileHandle, IoStatusBlock, Buffer, Length);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetQuotaInformationFile), (uint32_t)w32_NtSetQuotaInformationFile, 4, FileHandle, IoStatusBlock, Buffer, Length);
#endif
    }

    NTSTATUS WINAPI NtSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSecurityObject), 0, 3, Handle, SecurityInformation, SecurityDescriptor);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSecurityObject), (uint32_t)w32_NtSetSecurityObject, 3, Handle, SecurityInformation, SecurityDescriptor);
#endif
    }

    NTSTATUS WINAPI NtSetSystemEnvironmentValue(PUNICODE_STRING VariableName, PUNICODE_STRING VariableValue) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemEnvironmentValue), 0, 2, VariableName, VariableValue);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemEnvironmentValue), (uint32_t)w32_NtSetSystemEnvironmentValue, 2, VariableName, VariableValue);
#endif
    }

    NTSTATUS WINAPI NtSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemEnvironmentValueEx), 0, 5, VariableName, VendorGuid, Value, ValueLength, Attributes);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemEnvironmentValueEx), (uint32_t)w32_NtSetSystemEnvironmentValueEx, 5, VariableName, VendorGuid, Value, ValueLength, Attributes);
#endif
    }

    NTSTATUS WINAPI NtSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemInformation), 0, 3, SystemInformationClass, SystemInformation, SystemInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemInformation), (uint32_t)w32_NtSetSystemInformation, 3, SystemInformationClass, SystemInformation, SystemInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetSystemPowerState(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemPowerState), 0, 3, SystemAction, LightestSystemState, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemPowerState), (uint32_t)w32_NtSetSystemPowerState, 3, SystemAction, LightestSystemState, Flags);
#endif
    }

    NTSTATUS WINAPI NtSetSystemTime(PLARGE_INTEGER SystemTime, PLARGE_INTEGER PreviousTime) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemTime), 0, 2, SystemTime, PreviousTime);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetSystemTime), (uint32_t)w32_NtSetSystemTime, 2, SystemTime, PreviousTime);
#endif
    }

    NTSTATUS WINAPI NtSetThreadExecutionState(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetThreadExecutionState), 0, 2, NewFlags, PreviousFlags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetThreadExecutionState), (uint32_t)w32_NtSetThreadExecutionState, 2, NewFlags, PreviousFlags);
#endif
    }

    NTSTATUS WINAPI NtSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext, BOOLEAN ResumeTimer, LONG Period, PBOOLEAN PreviousState) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimer), 0, 7, TimerHandle, DueTime, TimerApcRoutine, TimerContext, ResumeTimer, Period, PreviousState);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimer), (uint32_t)w32_NtSetTimer, 7, TimerHandle, DueTime, TimerApcRoutine, TimerContext, ResumeTimer, Period, PreviousState);
#endif
    }

    NTSTATUS WINAPI NtSetTimer2(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimer2), 0, 4, TimerHandle, DueTime, Period, Parameters);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimer2), (uint32_t)w32_NtSetTimer2, 4, TimerHandle, DueTime, Period, Parameters);
#endif
    }

    NTSTATUS WINAPI NtSetTimerEx(HANDLE TimerHandle, TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, PVOID TimerSetInformation, ULONG TimerSetInformationLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimerEx), 0, 4, TimerHandle, TimerSetInformationClass, TimerSetInformation, TimerSetInformationLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimerEx), (uint32_t)w32_NtSetTimerEx, 4, TimerHandle, TimerSetInformationClass, TimerSetInformation, TimerSetInformationLength);
#endif
    }

    NTSTATUS WINAPI NtSetTimerResolution(ULONG DesiredTime, BOOLEAN SetResolution, PULONG ActualTime) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimerResolution), 0, 3, DesiredTime, SetResolution, ActualTime);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetTimerResolution), (uint32_t)w32_NtSetTimerResolution, 3, DesiredTime, SetResolution, ActualTime);
#endif
    }

    NTSTATUS WINAPI NtSetUuidSeed(PCHAR Seed) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetUuidSeed), 0, 1, Seed);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetUuidSeed), (uint32_t)w32_NtSetUuidSeed, 1, Seed);
#endif
    }

    NTSTATUS WINAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetValueKey), 0, 6, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetValueKey), (uint32_t)w32_NtSetValueKey, 6, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
#endif
    }

    NTSTATUS WINAPI NtSetVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetVolumeInformationFile), 0, 5, FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetVolumeInformationFile), (uint32_t)w32_NtSetVolumeInformationFile, 5, FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
#endif
    }

    NTSTATUS WINAPI NtSetWnfProcessNotificationEvent(HANDLE NotificationEvent) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetWnfProcessNotificationEvent), 0, 1, NotificationEvent);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSetWnfProcessNotificationEvent), (uint32_t)w32_NtSetWnfProcessNotificationEvent, 1, NotificationEvent);
#endif
    }

    NTSTATUS WINAPI NtShutdownSystem(SHUTDOWN_ACTION Action) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtShutdownSystem), 0, 1, Action);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtShutdownSystem), (uint32_t)w32_NtShutdownSystem, 1, Action);
#endif
    }

    NTSTATUS WINAPI NtShutdownWorkerFactory(HANDLE WorkerFactoryHandle, LONG volatile* PendingWorkerCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtShutdownWorkerFactory), 0, 2, WorkerFactoryHandle, PendingWorkerCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtShutdownWorkerFactory), (uint32_t)w32_NtShutdownWorkerFactory, 2, WorkerFactoryHandle, PendingWorkerCount);
#endif
    }

    NTSTATUS WINAPI NtSignalAndWaitForSingleObject(HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSignalAndWaitForSingleObject), 0, 4, SignalHandle, WaitHandle, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSignalAndWaitForSingleObject), (uint32_t)w32_NtSignalAndWaitForSingleObject, 4, SignalHandle, WaitHandle, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtSinglePhaseReject(HANDLE EnlistmentHandle, PLARGE_INTEGER TmVirtualClock) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSinglePhaseReject), 0, 2, EnlistmentHandle, TmVirtualClock);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSinglePhaseReject), (uint32_t)w32_NtSinglePhaseReject, 2, EnlistmentHandle, TmVirtualClock);
#endif
    }

    NTSTATUS WINAPI NtStartProfile(HANDLE ProfileHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtStartProfile), 0, 1, ProfileHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtStartProfile), (uint32_t)w32_NtStartProfile, 1, ProfileHandle);
#endif
    }

    NTSTATUS WINAPI NtStopProfile(HANDLE ProfileHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtStopProfile), 0, 1, ProfileHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtStopProfile), (uint32_t)w32_NtStopProfile, 1, ProfileHandle);
#endif
    }

    NTSTATUS WINAPI NtSubscribeWnfStateChange(PCWNF_STATE_NAME StateName, WNF_CHANGE_STAMP ChangeStamp, ULONG EventMask, PULONG64 SubscriptionId) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSubscribeWnfStateChange), 0, 4, StateName, ChangeStamp, EventMask, SubscriptionId);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSubscribeWnfStateChange), (uint32_t)w32_NtSubscribeWnfStateChange, 4, StateName, ChangeStamp, EventMask, SubscriptionId);
#endif
    }

    NTSTATUS WINAPI NtSuspendProcess(HANDLE ProcessHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSuspendProcess), 0, 1, ProcessHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSuspendProcess), (uint32_t)w32_NtSuspendProcess, 1, ProcessHandle);
#endif
    }

    NTSTATUS WINAPI NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSuspendThread), 0, 2, ThreadHandle, PreviousSuspendCount);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSuspendThread), (uint32_t)w32_NtSuspendThread, 2, ThreadHandle, PreviousSuspendCount);
#endif
    }

    NTSTATUS WINAPI NtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSystemDebugControl), 0, 6, Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtSystemDebugControl), (uint32_t)w32_NtSystemDebugControl, 6, Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtTerminateEnclave(PVOID BaseAddress, BOOLEAN WaitForThread) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateEnclave), 0, 2, BaseAddress, WaitForThread);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateEnclave), (uint32_t)w32_NtTerminateEnclave, 2, BaseAddress, WaitForThread);
#endif
    }

    NTSTATUS WINAPI NtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateJobObject), 0, 2, JobHandle, ExitStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateJobObject), (uint32_t)w32_NtTerminateJobObject, 2, JobHandle, ExitStatus);
#endif
    }

    NTSTATUS WINAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateProcess), 0, 2, ProcessHandle, ExitStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateProcess), (uint32_t)w32_NtTerminateProcess, 2, ProcessHandle, ExitStatus);
#endif
    }

    NTSTATUS WINAPI NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateThread), 0, 2, ThreadHandle, ExitStatus);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTerminateThread), (uint32_t)w32_NtTerminateThread, 2, ThreadHandle, ExitStatus);
#endif
    }

    NTSTATUS WINAPI NtTestAlert() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTestAlert), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTestAlert), (uint32_t)w32_NtTestAlert, 0);
#endif
    }

    NTSTATUS WINAPI NtThawRegistry() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtThawRegistry), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtThawRegistry), (uint32_t)w32_NtThawRegistry, 0);
#endif
    }

    NTSTATUS WINAPI NtThawTransactions() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtThawTransactions), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtThawTransactions), (uint32_t)w32_NtThawTransactions, 0);
#endif
    }

    NTSTATUS WINAPI NtTraceControl(TRACE_CONTROL_INFORMATION_CLASS TraceInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID TraceInformation, ULONG TraceInformationLength, PULONG ReturnLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTraceControl), 0, 6, TraceInformationClass, InputBuffer, InputBufferLength, TraceInformation, TraceInformationLength, ReturnLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTraceControl), (uint32_t)w32_NtTraceControl, 6, TraceInformationClass, InputBuffer, InputBufferLength, TraceInformation, TraceInformationLength, ReturnLength);
#endif
    }

    NTSTATUS WINAPI NtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTraceEvent), 0, 4, TraceHandle, Flags, FieldSize, Fields);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTraceEvent), (uint32_t)w32_NtTraceEvent, 4, TraceHandle, Flags, FieldSize, Fields);
#endif
    }

    NTSTATUS WINAPI NtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, PULONG OutputFilePathLength) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTranslateFilePath), 0, 4, InputFilePath, OutputType, OutputFilePath, OutputFilePathLength);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtTranslateFilePath), (uint32_t)w32_NtTranslateFilePath, 4, InputFilePath, OutputType, OutputFilePath, OutputFilePathLength);
#endif
    }

    NTSTATUS WINAPI NtUmsThreadYield(PVOID SchedulerParam) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUmsThreadYield), 0, 1, SchedulerParam);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUmsThreadYield), (uint32_t)w32_NtUmsThreadYield, 1, SchedulerParam);
#endif
    }

    NTSTATUS WINAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadDriver), 0, 1, DriverServiceName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadDriver), (uint32_t)w32_NtUnloadDriver, 1, DriverServiceName);
#endif
    }

    NTSTATUS WINAPI NtUnloadKey(POBJECT_ATTRIBUTES TargetKey) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKey), 0, 1, TargetKey);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKey), (uint32_t)w32_NtUnloadKey, 1, TargetKey);
#endif
    }

    NTSTATUS WINAPI NtUnloadKey2(POBJECT_ATTRIBUTES TargetKey, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKey2), 0, 2, TargetKey, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKey2), (uint32_t)w32_NtUnloadKey2, 2, TargetKey, Flags);
#endif
    }

    NTSTATUS WINAPI NtUnloadKeyEx(POBJECT_ATTRIBUTES TargetKey, HANDLE Event) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKeyEx), 0, 2, TargetKey, Event);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnloadKeyEx), (uint32_t)w32_NtUnloadKeyEx, 2, TargetKey, Event);
#endif
    }

    NTSTATUS WINAPI NtUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnlockFile), 0, 5, FileHandle, IoStatusBlock, ByteOffset, Length, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnlockFile), (uint32_t)w32_NtUnlockFile, 5, FileHandle, IoStatusBlock, ByteOffset, Length, Key);
#endif
    }

    NTSTATUS WINAPI NtUnlockVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG MapType) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnlockVirtualMemory), 0, 4, ProcessHandle, BaseAddress, RegionSize, MapType);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnlockVirtualMemory), (uint32_t)w32_NtUnlockVirtualMemory, 4, ProcessHandle, BaseAddress, RegionSize, MapType);
#endif
    }

    NTSTATUS WINAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnmapViewOfSection), 0, 2, ProcessHandle, BaseAddress);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnmapViewOfSection), (uint32_t)w32_NtUnmapViewOfSection, 2, ProcessHandle, BaseAddress);
#endif
    }

    NTSTATUS WINAPI NtUnmapViewOfSectionEx(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnmapViewOfSectionEx), 0, 3, ProcessHandle, BaseAddress, Flags);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnmapViewOfSectionEx), (uint32_t)w32_NtUnmapViewOfSectionEx, 3, ProcessHandle, BaseAddress, Flags);
#endif
    }

    NTSTATUS WINAPI NtUnsubscribeWnfStateChange(PCWNF_STATE_NAME StateName) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnsubscribeWnfStateChange), 0, 1, StateName);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUnsubscribeWnfStateChange), (uint32_t)w32_NtUnsubscribeWnfStateChange, 1, StateName);
#endif
    }

    NTSTATUS WINAPI NtUpdateWnfStateData(PCWNF_STATE_NAME StateName, void const* Buffer, ULONG Length, PCWNF_TYPE_ID TypeId, void const* ExplicitScope, WNF_CHANGE_STAMP MatchingChangeStamp, LOGICAL CheckStamp) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUpdateWnfStateData), 0, 7, StateName, Buffer, Length, TypeId, ExplicitScope, MatchingChangeStamp, CheckStamp);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtUpdateWnfStateData), (uint32_t)w32_NtUpdateWnfStateData, 7, StateName, Buffer, Length, TypeId, ExplicitScope, MatchingChangeStamp, CheckStamp);
#endif
    }

    NTSTATUS WINAPI NtVdmControl(VDMSERVICECLASS Service, PVOID ServiceData) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtVdmControl), 0, 2, Service, ServiceData);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtVdmControl), (uint32_t)w32_NtVdmControl, 2, Service, ServiceData);
#endif
    }

    NTSTATUS WINAPI NtWaitForAlertByThreadId(PVOID Address, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForAlertByThreadId), 0, 2, Address, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForAlertByThreadId), (uint32_t)w32_NtWaitForAlertByThreadId, 2, Address, Timeout);
#endif
    }

    NTSTATUS WINAPI NtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PDBGUI_WAIT_STATE_CHANGE WaitStateChange) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForDebugEvent), 0, 4, DebugObjectHandle, Alertable, Timeout, WaitStateChange);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForDebugEvent), (uint32_t)w32_NtWaitForDebugEvent, 4, DebugObjectHandle, Alertable, Timeout, WaitStateChange);
#endif
    }

    NTSTATUS WINAPI NtWaitForKeyedEvent(HANDLE KeyedEventHandle, PVOID KeyValue, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForKeyedEvent), 0, 4, KeyedEventHandle, KeyValue, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForKeyedEvent), (uint32_t)w32_NtWaitForKeyedEvent, 4, KeyedEventHandle, KeyValue, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtWaitForMultipleObjects(ULONG Count, HANDLE* Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForMultipleObjects), 0, 5, Count, Handles, WaitType, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForMultipleObjects), (uint32_t)w32_NtWaitForMultipleObjects, 5, Count, Handles, WaitType, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtWaitForMultipleObjects32(ULONG Count, LONG* Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForMultipleObjects32), 0, 5, Count, Handles, WaitType, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForMultipleObjects32), (uint32_t)w32_NtWaitForMultipleObjects32, 5, Count, Handles, WaitType, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForSingleObject), 0, 3, Handle, Alertable, Timeout);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForSingleObject), (uint32_t)w32_NtWaitForSingleObject, 3, Handle, Alertable, Timeout);
#endif
    }

    NTSTATUS WINAPI NtWaitForWorkViaWorkerFactory(HANDLE WorkerFactoryHandle, _FILE_IO_COMPLETION_INFORMATION* MiniPacket) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForWorkViaWorkerFactory), 0, 2, WorkerFactoryHandle, MiniPacket);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitForWorkViaWorkerFactory), (uint32_t)w32_NtWaitForWorkViaWorkerFactory, 2, WorkerFactoryHandle, MiniPacket);
#endif
    }

    NTSTATUS WINAPI NtWaitHighEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitHighEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitHighEventPair), (uint32_t)w32_NtWaitHighEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtWaitLowEventPair(HANDLE EventPairHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitLowEventPair), 0, 1, EventPairHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWaitLowEventPair), (uint32_t)w32_NtWaitLowEventPair, 1, EventPairHandle);
#endif
    }

    NTSTATUS WINAPI NtWorkerFactoryWorkerReady(HANDLE WorkerFactoryHandle) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWorkerFactoryWorkerReady), 0, 1, WorkerFactoryHandle);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWorkerFactoryWorkerReady), (uint32_t)w32_NtWorkerFactoryWorkerReady, 1, WorkerFactoryHandle);
#endif
    }

    NTSTATUS WINAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteFile), 0, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteFile), (uint32_t)w32_NtWriteFile, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
#endif
    }

    NTSTATUS WINAPI NtWriteFileGather(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT SegmentArray, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteFileGather), 0, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, SegmentArray, Length, ByteOffset, Key);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteFileGather), (uint32_t)w32_NtWriteFileGather, 9, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, SegmentArray, Length, ByteOffset, Key);
#endif
    }

    NTSTATUS WINAPI NtWriteRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG DataEntryIndex, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteRequestData), 0, 6, PortHandle, Message, DataEntryIndex, Buffer, BufferSize, NumberOfBytesWritten);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteRequestData), (uint32_t)w32_NtWriteRequestData, 6, PortHandle, Message, DataEntryIndex, Buffer, BufferSize, NumberOfBytesWritten);
#endif
    }

    NTSTATUS WINAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteVirtualMemory), 0, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtWriteVirtualMemory), (uint32_t)w32_NtWriteVirtualMemory, 5, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
#endif
    }

    NTSTATUS WINAPI NtYieldExecution() {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

#ifdef _M_AMD64
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtYieldExecution), 0, 0);
#else
        return cleancall::call(get_syscall_by_idx(SYSCALL_NtYieldExecution), (uint32_t)w32_NtYieldExecution, 0);
#endif
    }



#ifdef _M_IX86
    NTSTATUS WINAPI NtWow64NtAllocateVirtualMemory64(HANDLE ProcessHandle, PULONGLONG BaseAddress, ULONGLONG ZeroBits, PULONGLONG RegionSize, ULONG AllocationType, ULONG Protect) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return cleancall::call64(get_syscall_by_idx(SYSCALL_NtAllocateVirtualMemory), (uint32_t)w64_NtAllocateVirtualMemory, 6, (ULONGLONG)ProcessHandle, (ULONGLONG)BaseAddress, (ULONGLONG)ZeroBits, (ULONGLONG)RegionSize, (ULONGLONG)AllocationType, (ULONGLONG)Protect);
    }

    NTSTATUS WINAPI NtWow64NtFreeVirtualMemory64(HANDLE ProcessHandle, ULONGLONG BaseAddress, PULONGLONG RegionSize, ULONG FreeType) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return cleancall::call64(get_syscall_by_idx(SYSCALL_NtFreeVirtualMemory), (uint32_t)w64_NtFreeVirtualMemory, 4, (ULONGLONG)ProcessHandle, (ULONGLONG)BaseAddress, (ULONGLONG)RegionSize, (ULONGLONG)FreeType);
    }

    NTSTATUS WINAPI NtWow64ReadVirtualMemory64(HANDLE ProcessHandle, ULONGLONG BaseAddress, ULONGLONG Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return cleancall::call64(get_syscall_by_idx(SYSCALL_NtReadVirtualMemory), (uint32_t)w64_NtReadVirtualMemory, 5, (ULONGLONG)ProcessHandle, (ULONGLONG)BaseAddress, (ULONGLONG)Buffer, (ULONGLONG)BufferSize, (ULONGLONG)NumberOfBytesRead);
    }

    NTSTATUS WINAPI NtWow64WriteVirtualMemory64(HANDLE ProcessHandle, ULONGLONG BaseAddress, ULONGLONG Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesWritten) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return cleancall::call64(get_syscall_by_idx(SYSCALL_NtWriteVirtualMemory), (uint32_t)w64_NtWriteVirtualMemory, 5, (ULONGLONG)ProcessHandle, (ULONGLONG)BaseAddress, (ULONGLONG)Buffer, (ULONGLONG)BufferSize, (ULONGLONG)NumberOfBytesWritten);
    }

    NTSTATUS WINAPI NtWow64NtProtectVirtualMemory64(HANDLE ProcessHandle, ULONGLONG BaseAddress, PULONGLONG RegionSize, ULONG NewProtect, PULONG OldProtect) {

        if (!is_syscall_table_initialized()) {
            return STATUS_NOT_IMPLEMENTED;
        }

        return cleancall::call64(get_syscall_by_idx(SYSCALL_NtProtectVirtualMemory), (uint32_t)w64_NtProtectVirtualMemory, 5, (ULONGLONG)ProcessHandle, (ULONGLONG)BaseAddress, (ULONGLONG)RegionSize, (ULONGLONG)NewProtect, (ULONGLONG)OldProtect);
    }
#endif

#pragma warning(pop)

};