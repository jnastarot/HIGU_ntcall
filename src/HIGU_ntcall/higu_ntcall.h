#pragma once

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
#include <stdarg.h>
#include <string.h>
#include <cstdlib>
#include <intrin.h>

#include "cleancall/cleancall.h"

#pragma warning(push)
#pragma warning(disable: 4005) //redefine defs

#include "syscall_table.h"
#include "syscall_table_initialize.h"

#include "ntdll_functions.h"

#pragma warning(pop)