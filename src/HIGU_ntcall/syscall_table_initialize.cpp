#include "pch.h"
#include "syscall_table_initialize.h"

static bool syscall_table_initialized = false;

extern "C" bool is_syscall_table_initialized() {
    return syscall_table_initialized;
}

extern "C" bool initialize_syscall_table_auto() {

    if (!syscall_table_initialized) {

        initialize_syscall_table_by_mapped(
            CONTAINING_RECORD(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)->DllBase //get ntdll by peb Ldr List
        );

        syscall_table_initialized = true;
    }

    return syscall_table_initialized;
}

extern "C" bool initialize_syscall_table_by_mapped(void* ntdll_handle) {

    syscall_table_initialized = false;

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)ntdll_handle;

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {

        return false;
    }


    IMAGE_NT_HEADERS32* nt_header32 = (IMAGE_NT_HEADERS32*)&((uint8_t*)ntdll_handle)[dos_header->e_lfanew];
    IMAGE_NT_HEADERS64* nt_header64 = (IMAGE_NT_HEADERS64*)nt_header32;

    if (nt_header32->Signature != IMAGE_NT_SIGNATURE) {

        return false;
    }

    bool is_x32 = nt_header32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    

    IMAGE_DATA_DIRECTORY export_data_dir =
        is_x32 ? nt_header32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        : nt_header64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!export_data_dir.VirtualAddress || !export_data_dir.Size) {

        return false;
    }

    IMAGE_EXPORT_DIRECTORY* export_dir =
        (IMAGE_EXPORT_DIRECTORY*)&((uint8_t*)ntdll_handle)[export_data_dir.VirtualAddress];


    if (!export_dir->AddressOfFunctions ||
        !export_dir->AddressOfNames ||
        !export_dir->AddressOfNameOrdinals ||
        !export_dir->NumberOfNames ||
        !export_dir->NumberOfFunctions) {

        return false;
    }

    uint32_t* functions = (uint32_t*)&((uint8_t*)ntdll_handle)[export_dir->AddressOfFunctions];
    uint32_t* names = (uint32_t*)&((uint8_t*)ntdll_handle)[export_dir->AddressOfNames];
    uint16_t* names_ordinals = (uint16_t*)&((uint8_t*)ntdll_handle)[export_dir->AddressOfNameOrdinals];

    size_t totaly_initialized = 0;

    for (size_t idx = 0; idx < SYSCALL_TABLE_MAX; idx++) {

        for (size_t name_idx = 0; name_idx < export_dir->NumberOfNames; name_idx++) {

            if (!strcmp((char*)&((uint8_t*)ntdll_handle)[names[name_idx]], get_syscall_name_by_idx((syscall_table_enum)idx))) {

                uint8_t* func = (uint8_t *)&((uint8_t*)ntdll_handle)[functions[names_ordinals[name_idx]]];

                if (func[0] == 0x4C && //mov r10,rcx
                    func[1] == 0x8B &&
                    func[2] == 0xD1 &&
                    func[3] == 0xB8) { //mov eax, syscall_index

                    set_syscall_by_idx((syscall_table_enum)idx, *(uint32_t*)&func[4]);
                }
                else if(func[0] == 0xB8) { //mov eax, syscall_index

                    set_syscall_by_idx((syscall_table_enum)idx, *(uint32_t*)&func[1]);
                }
                else {

                    set_syscall_by_idx((syscall_table_enum)idx, -1);
                    break;
                }

                totaly_initialized++;
                break;
            }
        }
    }

    syscall_table_initialized = true;

    return syscall_table_initialized;
}

extern "C" bool initialize_syscall_table_by_pre_init_table(uint32_t table[SYSCALL_TABLE_MAX]) {

    for (size_t idx = 0; idx < SYSCALL_TABLE_MAX; idx++) {

        set_syscall_by_idx((syscall_table_enum)idx, table[idx]);
    }

    syscall_table_initialized = true;

    return syscall_table_initialized;
}

