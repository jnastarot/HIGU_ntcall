extern int64_t __fastcall intrnl__syscall64(uint32_t syscall_idx, uint32_t args_count, uint64_t* arg_table);

__forceinline int64_t __syscall64(uint32_t syscall_idx, uint32_t arg_count, ...) {

    uint64_t arg_table[20];

    va_list variadic_arg;

    va_start(variadic_arg, arg_count);

    for (uint32_t idx = 0; idx < arg_count; idx++) {

        arg_table[idx] = va_arg(variadic_arg, uint64_t);
    }

    va_end(variadic_arg);

    return intrnl__syscall64(syscall_idx, arg_count, arg_table);
}


extern void* intrnl__ntcallmalloc(void* ctx, uint32_t size);

