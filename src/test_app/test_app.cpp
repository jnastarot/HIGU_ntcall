#include <higu_ntcall.h>


int main() {

    initialize_syscall_table_auto();

    HANDLE handle1;
    NtCreateEvent(&handle1, EVENT_ALL_ACCESS, 0, EVENT_TYPE::NotificationEvent, 0);
    HANDLE handle2;
    NtCreateEvent(&handle2, EVENT_ALL_ACCESS, 0, EVENT_TYPE::NotificationEvent, 0);
    HANDLE handle3;
    NtCreateEvent(&handle3, EVENT_ALL_ACCESS, 0, EVENT_TYPE::NotificationEvent, 0);
    HANDLE handle4;
    NtCreateEvent(&handle4, EVENT_ALL_ACCESS, 0, EVENT_TYPE::NotificationEvent, 0);

    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING Name;
    HANDLE Handle;

    RtlInitUnicodeString(&Name, L"\\KernelObjects\\CritSecOutOfMemoryEvent");
    InitializeObjectAttributes(&oa, &Name, 0, NULL, NULL);

    auto Status = NtOpenKeyedEvent(&Handle, MAXIMUM_ALLOWED, &oa);
}
