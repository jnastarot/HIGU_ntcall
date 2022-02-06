
typedef enum _RTL_PATH_TYPE {
    RtlPathTypeUnknown,         // 0
    RtlPathTypeUncAbsolute,     // 1
    RtlPathTypeDriveAbsolute,   // 2
    RtlPathTypeDriveRelative,   // 3
    RtlPathTypeRooted,          // 4
    RtlPathTypeRelative,        // 5
    RtlPathTypeLocalDevice,     // 6
    RtlPathTypeRootLocalDevice  // 7
} RTL_PATH_TYPE;

#pragma warning(push)
#pragma warning(disable: 4005 4201)

#include <phnt_windows.h>
#include <phnt.h>

#pragma warning(pop)

#include <stdint.h>


#define X32_PVOID uint32_t
#define X32_SIZE_T uint32_t
#define X32_HANDLE X32_PVOID
#define X32_ULONG_PTR X32_PVOID
#define X32_ALPC_HANDLE X32_HANDLE
#define X32_PSID X32_PVOID
#define X32_KAFFINITY X32_PVOID


#pragma warning(push)
#pragma warning(disable: 4302 4311 4312) //silent pointer cvt
#pragma warning(disable: 4091) //silent struct typedef

extern "C" {
    #include "ntcall_stuff.h"
    #include "thunk64_structures32.h"
    #include "thunk64_convertors32to64.h"
    #include "thunk64_convertors64to32.h"
    #include "thunk64_functions.h"
};

#pragma warning(pop)