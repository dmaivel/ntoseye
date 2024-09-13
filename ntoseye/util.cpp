#include "util.hpp"
#include "host.hpp"
#include "mem.hpp"
#include "windefs.h"

#include <algorithm>
#include <cstring>
#include <memory>

bool util::set_process_headers(mem::process &process)
{
    // already initialized
    if (process.dos_header == nullptr)
        process.dos_header = (IMAGE_DOS_HEADER*)(new uint8_t[0x1000]);

    process.read_bytes(process.dos_header, process.base_address, 0x1000);
    auto header = (uint8_t*)process.dos_header;

    if (header[0] != 'M' || header[1] != 'Z')
        return false;

    process.dos_header = (IMAGE_DOS_HEADER*)(void*)header;
    process.nt_headers = (IMAGE_NT_HEADERS*)(void*)(header + process.dos_header->e_lfanew);
    if ((uint8_t*)process.nt_headers - header > sizeof(size_t) - 0x200 
            || process.nt_headers->signature != IMAGE_NT_SIGNATURE)
        return false;

    if (process.nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC 
            && process.nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;

    process.WOW64 = process.nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    return true;
}

uint64_t util::get_section_virtual_address(mem::process &process, const std::string &name)
{
    if (!util::set_process_headers(process))
        return {};

    auto section = IMAGE_FIRST_SECTION(process.nt_headers);
    for (int i = 0; i < process.nt_headers->FileHeader.NumberOfSections; i++, section++)
        if (name == (char*)section->Name)
            return section->VirtualAddress;

    return 0;
}

std::vector<util::symbol> util::get_process_exports(mem::process &process)
{
    if (!util::set_process_headers(process))
        return {};

    if (!process.nt_headers)
        return {};

    PIMAGE_DATA_DIRECTORY export_table = NULL;
    if (!process.WOW64)
        export_table = process.nt_headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
    else
        export_table = (reinterpret_cast<PIMAGE_NT_HEADERS32>(process.nt_headers))->OptionalHeader.DataDirectory 
                + IMAGE_DIRECTORY_ENTRY_EXPORT;

    if (!export_table->Size)
        return {};

    auto buffer = new uint8_t[export_table->Size];
    process.read_bytes(buffer, process.base_address + export_table->VirtualAddress, export_table->Size);

    PIMAGE_EXPORT_DIRECTORY export_directory = PIMAGE_EXPORT_DIRECTORY(buffer);

    buffer[export_table->Size - 1] = 0;
    if (!export_directory->NumberOfNames || !export_directory->AddressOfNames) {
        delete[] buffer;
        return {};
    }

    uint32_t export_offset = export_table->VirtualAddress;

    uint32_t* names = (uint32_t*)(void*)(buffer + export_directory->AddressOfNames - export_offset);
    uint16_t* ordinals = (uint16_t*)(void*)(buffer + export_directory->AddressOfNameOrdinals - export_offset);
    uint32_t* functions = (uint32_t*)(void*)(buffer + export_directory->AddressOfFunctions - export_offset);

    std::vector<util::symbol> exports;

    for (uint32_t i = 0; i < export_directory->NumberOfNames; i++) {
        if (names[i] > export_table->Size + export_offset || names[i] < export_offset || ordinals[i] > export_directory->NumberOfNames)
            continue;

        exports.push_back({
            strdup((char*)buffer + names[i] - export_offset),
            process.base_address + functions[ordinals[i]]
        });
    }

    delete[] buffer;
    return exports;
}

uint64_t util::get_proc_address(std::vector<symbol> &symbols, const std::string &name)
{
    auto result = std::find_if(symbols.begin(), symbols.end(), [name](const symbol & symbol) -> bool {
        return symbol.name == name;
    });

    return result != symbols.end() ? result->address : 0;
}

void util::set_process_peb(mem::process &process, uint64_t peb_offset)
{
    process.peb = process.read<PEB>(host::read_kvm_memory<uint64_t>(process.physical_process + peb_offset));
}

bool util::query_module_basic_info(mem::process &process, PEB_LDR_DATA ldr, LDR_MODULE &ldr_module, uint64_t &head, uint64_t &end, uint64_t &prev, bool in_order)
{
    if (head == 0 && end == 0 && prev == 0) {
        head = ldr.InMemoryOrdermoduleList.Flink;
        end = head;
        prev = head + 1;
    }
    else {
        if (head == end || head == prev)
            return false;
        
        prev = head;
    }

    // if we're invalid, bye
    if (head == 0)
        return false;

    // attempt to advance head
    ldr_module = process.read<LDR_MODULE>(head - sizeof(LIST_ENTRY) * in_order);
    head = process.read<uint64_t>(head);

    // if current module is invalid, query next
    if (!ldr_module.SizeOfImage || !ldr_module.BaseDllName.Length)
        return query_module_basic_info(process, ldr, ldr_module, head, end, prev, in_order);

    return true;
}

std::vector<util::module> util::get_modules(mem::process &process)
{
    std::vector<util::module> result;

    auto ldr = process.read<PEB_LDR_DATA>(process.peb.Ldr);
    uint64_t head = 0;
    uint64_t end = 0;
    uint64_t prev = 0;

    LDR_MODULE ldr_module;

    while (query_module_basic_info(process, ldr, ldr_module, head, end, prev, true)) {
        auto module_wide_name = new short[ldr_module.BaseDllName.Length];
        process.read_bytes(module_wide_name, ldr_module.BaseDllName.Buffer, ldr_module.BaseDllName.Length * sizeof(short));

        std::string modulename;
        for (int i = 0; i < ldr_module.BaseDllName.Length; i++)
            modulename.push_back(((char*)module_wide_name)[i*2]);

        delete[] module_wide_name;

        result.push_back({ process, modulename, ldr_module.BaseAddress, ldr_module });
    }

    return result;
}

util::module util::get_module(mem::process &process, const std::string &module)
{
    auto ldr = process.read<PEB_LDR_DATA>(process.peb.Ldr);
    uint64_t head = 0;
    uint64_t end = 0;
    uint64_t prev = 0;

    LDR_MODULE ldr_module;

    while (query_module_basic_info(process, ldr, ldr_module, head, end, prev, true)) {
        auto module_wide_name = new short[ldr_module.BaseDllName.Length];
        process.read_bytes(module_wide_name, ldr_module.BaseDllName.Buffer, ldr_module.BaseDllName.Length * sizeof(short));

        std::string modulename;
        for (int i = 0; i < ldr_module.BaseDllName.Length; i++)
            modulename.push_back(((char*)module_wide_name)[i*2]);

        delete[] module_wide_name;

        // empty means we want process base
        if ((module.empty() && ldr_module.BaseAddress == process.peb.ImageBaseAddress) || module == modulename.c_str())
            return { process, modulename, ldr_module.BaseAddress };
    }

    return {};
}

std::vector<util::symbol> util::get_module_exports(module &module)
{
    mem::process module_disguised_as_process = module.process;
    module_disguised_as_process.dos_header = nullptr;
    module_disguised_as_process.nt_headers = nullptr;
    module_disguised_as_process.base_address = module.base_address;

    return get_process_exports(module_disguised_as_process);
}

bool util::is_vad_short(const MMVAD_SHORT &vad)
{
    return vad.u.VadFlags.VadType == 0 && vad.u.VadFlags.PrivateMemory == 1;
}

uint64_t util::get_vad_start(const MMVAD &vad)
{
    auto vad_short = vad.Core;
    return ((uint64_t)vad_short.StartingVpn << 12) | ((uint64_t)vad_short.StartingVpnHigh << 44);   
}

uint64_t util::get_vad_length(const MMVAD &vad, uint64_t start)
{
    if (start == 0)
        start = get_vad_start(vad);

    auto vad_short = vad.Core;
    return ((((uint64_t)vad_short.EndingVpn + 1) << 12) | ((uint64_t)vad_short.EndingVpnHigh << 44)) - start; 
}

uint64_t util::find_pattern(mem::process &process, uint64_t base, size_t length, uint8_t *bytes, const std::string &mask)
{
    auto mask_length = mask.size();

    const auto match = [&process, bytes, mask, mask_length](uint64_t address) -> bool {
        auto block = std::make_unique<uint8_t[]>(mask_length);
        process.read_bytes(block.get(), address, mask_length);

        for (int i = 0; i < mask_length; i++)
            if (mask[i] != '?' && block[i] != bytes[i])
                return false;
        return true;
    };

    for (int i = 0; i < length - mask_length; i++) {
        auto current_address = base + i;
        if (match(current_address))
            return current_address;
    }
    
    return 0;
}

std::string util::string_tolower(const std::string &string)
{
    std::string result;
    result.resize(string.size());

    std::transform(string.begin(),
                   string.end(),
                   result.begin(),
                   ::tolower);

    return result;
}

std::string util::string_toupper(const std::string &string)
{
    std::string result;
    result.resize(string.size());

    std::transform(string.begin(),
                   string.end(),
                   result.begin(),
                   ::toupper);

    return result;
}

pdb::metadata util::get_pdb_metadata(mem::process &process)
{
    struct pdb_internal_info {
        uint32_t signature;
        uint8_t  guid[16];
        uint32_t age;
        char     pdb_filename[128];
    };

    constexpr auto format_guid = [](const uint8_t guid[16]) {
        return std::format("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                guid[3], guid[2], guid[1], guid[0],
                guid[5], guid[4],
                guid[7], guid[6],
                guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
    };

    constexpr auto construct_url = [format_guid](const pdb_internal_info &info) {
        return std::format("https://msdl.microsoft.com/download/symbols/{}/{}{:X}/{}",
                info.pdb_filename, format_guid(info.guid), info.age, info.pdb_filename);
    };

    if (!process.nt_headers)
        set_process_headers(process);

    if (!process.nt_headers)
        return {};

    PIMAGE_DATA_DIRECTORY debug_directory_entry = NULL;
    if (!process.WOW64)
        debug_directory_entry = process.nt_headers->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG;
    else
        debug_directory_entry = (reinterpret_cast<PIMAGE_NT_HEADERS32>(process.nt_headers))->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG;

    if (!debug_directory_entry->Size)
        return {};

    auto dbg_dir = process.read<IMAGE_DEBUG_DIRECTORY>(process.base_address + debug_directory_entry->VirtualAddress);

    if (dbg_dir.Type == _IMAGE_DEBUG_TYPE_CODEVIEW) {
        auto pdb_info = process.read<pdb_internal_info>(process.base_address + dbg_dir.AddressOfRawData);

        if (std::memcmp(&pdb_info.signature, "RSDS", 4) == 0)
            return { pdb_info.pdb_filename, std::format("{}{:X}", format_guid(pdb_info.guid), pdb_info.age), construct_url(pdb_info) };
    }

    return {};
}