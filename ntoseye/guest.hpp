#pragma once

#include "mem.hpp"
#include "util.hpp"

#include <cstdint>
#include <string>

namespace guest {
    struct ntos_offsets {
        int64_t active_process_links,
                session,
                session_id,
                client_id,
                stack_count,
                image_filename,
                dir_base,
                peb,
                peb32,
                thread_list_head,
                thread_list_entry,
                teb,
                vad_root,
                parent_client_id,
                object_table;
    };

    bool initialize();

    mem::process get_ntoskrnl_process();
    ntos_offsets get_ntoskrnl_offsets();

    std::vector<util::module> get_kernel_modules();

    bool query_process_basic_info(uint64_t &physical_process, uint64_t &virtual_process, mem::process &current_process);
    mem::process find_process(const std::string &name);

    uint64_t get_pxe_address(uint64_t va);
    uint64_t get_ppe_address(uint64_t va);
    uint64_t get_pde_address(uint64_t va);
    uint64_t get_pte_address(uint64_t va);
}