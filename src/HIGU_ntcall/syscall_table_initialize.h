#pragma once

#include <stdint.h>

#include "syscall_table.h"

extern "C" {

    bool is_syscall_table_initialized();

    bool initialize_syscall_table_auto();
    bool initialize_syscall_table_by_mapped(void* ntdll_handle);
    bool initialize_syscall_table_by_pre_init_table(uint32_t table[SYSCALL_TABLE_MAX]);

};