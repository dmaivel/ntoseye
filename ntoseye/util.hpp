#pragma once

#include "mem.hpp"
#include "windefs.h"
#include "pdb.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace util {
    struct symbol {
        std::string name;
        uint64_t address;
    };

    struct page_4kb_buffer {
        uint8_t data[0x1000];
    };

    struct module {
        mem::process process; // sub-optimal; needed for util::get_module_exports
        std::string name;
        uint64_t base_address;

        LDR_MODULE ldr_module;
    };

    bool set_process_headers(mem::process &process);

    uint64_t get_section_virtual_address(mem::process &process, const std::string &name);

    std::vector<symbol> get_process_exports(mem::process &process);
    uint64_t get_proc_address(std::vector<symbol> &symbols, const std::string &name);

    void set_process_peb(mem::process &process, uint64_t peb_offset);

    bool query_module_basic_info(mem::process &process, PEB_LDR_DATA ldr, LDR_MODULE &ldr_module, uint64_t &head, uint64_t &end, uint64_t &prev, bool in_order = true);

    std::vector<module> get_modules(mem::process &process);
    module get_module(mem::process &process, const std::string &module);
    std::vector<symbol> get_module_exports(module &module);

    bool is_vad_short(const MMVAD_SHORT &vad);
    uint64_t get_vad_start(const MMVAD &vad);
    uint64_t get_vad_length(const MMVAD &vad, uint64_t start = 0);

    pdb::metadata get_pdb_metadata(mem::process &process);

    uint64_t find_pattern(mem::process &process, uint64_t base, size_t length, uint8_t *bytes, const std::string &mask);

    std::string string_tolower(const std::string &string);
    std::string string_toupper(const std::string &string);
    
    static inline std::string string_replace(std::string string, const std::string_view &from, const std::string_view &to)
    {
        for (size_t pos = 0; (pos = string.find(from, pos)) != std::string::npos; pos += to.length())
            string.replace(pos, from.length(), to);
        return string;
    }
}