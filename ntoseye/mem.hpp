#pragma once

#include "windefs.h"
#include "mem.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <vector>
#include <source_location>

#include <cerrno>

#include <immintrin.h>

// to-do: phase out, this was only meant for debugging
#define VMM_MAX_ATTEMPTS    2

#define PAGE_SHIFT          12
#define PAGE_SIZE           (1UL << PAGE_SHIFT)
#define PAGE_MASK           (~(PAGE_SIZE-1))

#define PAGE_ALIGN(addr)     (((addr)+PAGE_SIZE-1)&PAGE_MASK)

struct windbg_process_data {
    int session_id;
    int client_id;
    uintptr_t peb_address;
    int parent_client_id;
    uintptr_t object_table_address;
    int handle_count;
};

namespace mem {
    class process {
    private:
        ssize_t read_virtual_memory(void *local_address, uint64_t remote_address, size_t length);
        ssize_t write_virtual_memory(void *local_address, uint64_t remote_address, size_t length);

    public:
        uint64_t dir_base;

        uint64_t base_address;

        uint64_t virtual_process;
        uint64_t physical_process;

        uint64_t process_id;
        bool WOW64;

        std::vector<MMVAD> vad_list;

        PIMAGE_DOS_HEADER dos_header = nullptr;
        PIMAGE_NT_HEADERS nt_headers;

        PEB peb;

        windbg_process_data win_dbg_data;

        void set_dir_base(uint64_t new_dir_base);

        uintptr_t virtual_to_physical(uintptr_t address);

        template <typename T>
        T read(uint64_t remote_address, std::source_location fun = std::source_location::current())
        {
            int missed_attempts = 0;

            T result;
            std::memset(&result, 0, sizeof(T));

            if (virtual_to_physical(remote_address) == 0)
                return result;

            for (
                ssize_t remaining = 0; 
                remaining < sizeof(T); 
            ) {
                auto read = read_virtual_memory((char*)&result + remaining, remote_address + remaining, sizeof(T) - remaining);
                if (read == -1) {
                    if (missed_attempts >= VMM_MAX_ATTEMPTS) {
                        // errorf("exceeded max attempts from %s (%s) [V(%012lX) -> P(%012lX)]\n", fun.function_name(), strerror(errno), remote_address, virtual_to_physical(remote_address));
                        return result;
                    }

                    missed_attempts++;
                    _mm_pause();
                    continue;
                }

                remaining += read;
            }

            return result;
        }

        bool read_bytes(void *local_address, uint64_t remote_address, size_t length, std::source_location fun = std::source_location::current());

        template <typename T>
        void write(uint64_t remote_address, T data, std::source_location fun = std::source_location::current())
        {
            int missed_attempts = 0;

            for (
                ssize_t remaining = 0; 
                remaining < sizeof(T); 
            ) {
                auto read = write_virtual_memory((char*)&data + remaining, remote_address + remaining, sizeof(T) - remaining);
                if (read == -1) {
                    if (missed_attempts >= VMM_MAX_ATTEMPTS) {
                        // errorf("exceeded max attempts from %s (%s) [V(%012lX) -> P(%012lX)]\n", fun.function_name(), strerror(errno), remote_address, virtual_to_physical(remote_address));
                        return;
                    }

                    missed_attempts++;
                    _mm_pause();
                    continue;
                }

                remaining += read;
            }
        }

        bool write_bytes(void *local_address, uint64_t remote_address, size_t length, std::source_location fun = std::source_location::current());
    };
}