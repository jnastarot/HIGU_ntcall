NtCall
===

Library for using direct system calls
It automatically detect type of gate for call system call (`WOW64` \ `custom WOW64` \ `Int2E` \ `Sysenter` \ `Syscall` )

Checked Support on Windows
---

|Tested|Status|
|---|---|
|Windows 11 x64| OK |
|Windows 10 x64| OK |
|Windows 7 x86| OK |

How it works
---
By using `TEB` and `KUSER_SHARED_DATA` strucures we can determine what must use for make call to kernel.

On x86 we check `WOW32Reserved` in `TEB` for detect used `wow64` wrapper, and `SystemCall` in `KUSER_SHARED_DATA` for detect what's used `int2e` or direct call.
On x64 we check only `SystemCall` in `KUSER_SHARED_DATA` because it doesnt use any wow64.

So we detect used call type, next we need somehow use it.
Use it on x86 can be in 4 kinds

1. Int2E
2. sysenter - default on windows x86 for ntdll
3. Original Wow64 - default on windows x64 in wow64 for ntdll
4. Custom Wow64 - custom wow64 wrapper to convert x86 call parameters to x64 representation and vice versa

In x64 this used shared methods so it notinteresting :)

1. Int2E
2. syscall - default on windows x64

For comfortable use it (wow64 custom wrapper), project depend on `object_cvt64to32` what can convert object file with arch x64 to use it in arch x86 build


Why
---

Custom wow64 basically supports almost all, except ENUM functions such as `NtQuerySystemInformaton`. Functions with ENUM are also supported, but most of them crash the process at the stage of calling the parameter conversion.
It takes a lot of hours to debug and fix. So if anyone wants to help with a fix, I welcome all contributions to this project :)

Example Use
----
```
#include <higu_ntcall.h>

int main() {
  /*
     initialize syscall indexes in the start
  */
  initialize_syscall_table_auto(); 
  ...
  
  ...
  /*
     use Nt functions like staticly imported
  */
  HANDLE handle;
  NTSTATUS nt_status = NtCreateEvent(&handle, EVENT_ALL_ACCESS, 0, EVENT_TYPE::NotificationEvent, 0);
  ...
}

```

Authors
---
Founder of project [JNA](https://github.com/jnastarot)