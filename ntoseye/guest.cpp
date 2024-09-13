#include "guest.hpp"
#include "pdb.hpp"
#include "util.hpp"
#include "host.hpp"
#include "mem.hpp"
#include "log.hpp"

#include "windefs.h"

#include <cstdint>
#include <limits>

static uintptr_t mm_pte_base = 0;
static uintptr_t mm_pde_base = 0;
static uintptr_t mm_ppe_base = 0;
static uintptr_t mm_pxe_base = 0;
static uintptr_t mm_pxe_self = 0;

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((uintptr_t)1) << VIRTUAL_ADDRESS_BITS) - 1)
#define PTE_SHIFT 3
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#define mi_get_pxe_offset(va) ((uint32_t)(((uintptr_t)(va) >> PXI_SHIFT) & PXI_MASK))

#define mi_get_pxe_address(va)   ((uint64_t)mm_pxe_base + mi_get_pxe_offset(va))

#define mi_get_ppe_address(va)   \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + mm_ppe_base))

#define mi_get_pde_address(va)  \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + mm_pde_base))

#define mi_get_pte_address(va) \
    ((uint64_t)(((((uintptr_t)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + mm_pte_base))

static mem::process ntoskrnl_process;
static std::vector<util::symbol> ntoskrnl_symbols;
static guest::ntos_offsets ntoskrnl_offsets;

static auto get_ntoskrnl_entry() -> uint64_t
{
    char buf[0x10000];

    for (int i = 0; i < 10; i++) {
        host::read_kvm_memory(buf, i * 0x10000, 0x10000);
        
        for (int o = 0; o < 0x10000; o += 0x1000) {
            // start bytes
            if (0x00000001000600E9 ^ (0xffffffffffff00ff & *(uint64_t*)(void*)(buf + o)))
                continue;

            // kernel entry
            if (0xfffff80000000000 ^ (0xfffff80000000000 & *(uint64_t*)(void*)(buf + o + 0x70)))
                continue;

            // pml4
            if (0xffffff0000000fff & *(uint64_t*)(void*)(buf + o + 0xa0))
                continue;

            ntoskrnl_process.set_dir_base(*(uint64_t*)(void*)(buf + o + 0xa0));
            return *(uint64_t*)(void*)(buf + o + 0x70);
        }
    }

    return 0;
}

static bool get_ntoskrnl_base_address(uint64_t kernel_entry)
{
    uint64_t i, o, p, u, mask = 0xfffff;
    char buf[0x10000];

    while (mask >= 0xfff) {
        for (i = (kernel_entry & ~0x1fffff) + 0x20000000; i > kernel_entry - 0x20000000; i -= 0x200000) {
            for (o = 0; o < 0x20; o++) {
                ntoskrnl_process.read_bytes(buf, i + 0x10000 * o, sizeof(buf));

                for (p = 0; p < 0x10000; p += 0x1000) {
                    if (((i + 0x1000 * o + p) & mask) == 0 && *(short*)(void*)(buf + p) == IMAGE_DOS_SIGNATURE) {
                        int kdbg = 0, pool_code = 0;
                        for (u = 0; u < 0x1000; u++) {
                            kdbg = kdbg || *(uint64_t*)(void*)(buf + p + u) == 0x4742444b54494e49;
                            pool_code = pool_code || *(uint64_t*)(void*)(buf + p + u) == 0x45444f434c4f4f50;
                            if (kdbg & pool_code) {
                                ntoskrnl_process.base_address = i + 0x10000 * o + p;
                                
                                ntoskrnl_symbols = util::get_process_exports(ntoskrnl_process);
                                if (ntoskrnl_symbols.empty())
                                    break;

                                return true;
                            }
                        }
                    }
                }
            }
        }

        mask = mask >> 4;
    }

    return false;
}

static uint16_t get_ntos_version()
{
    auto get_version = util::get_proc_address(ntoskrnl_symbols, "RtlGetVersion");

    auto buffer = ntoskrnl_process.read<util::page_4kb_buffer>(get_version);
    auto buf = buffer.data;

    char major = 0, minor = 0;

    // rcx + 4, rcx + 8
    for (char* b = (char*)buf; b - (char*)buf < 0xf0; b++) {
        if (!major && !minor)
            if (*(uint32_t*)(void*)b == 0x441c748)
                return ((uint16_t)b[4]) * 100 + (b[5] & 0xf);
        if (!major && (*(uint32_t*)(void*)b & 0xfffff) == 0x441c7)
            major = b[3];
        if (!minor && (*(uint32_t*)(void*)b & 0xfffff) == 0x841c7)
            minor = b[3];
    }

    if (minor >= 100)
        minor = 0;

    return ((uint16_t)major) * 100 + minor;
}

static uint32_t get_ntos_build()
{
    uint64_t nt_build = util::get_proc_address(ntoskrnl_symbols, "NtBuildNumber");

    if (nt_build) {
        auto build = ntoskrnl_process.read<uint32_t>(nt_build);
        if (build)
            return build & 0xffffff;
    }

    uint64_t get_version = util::get_proc_address(ntoskrnl_symbols, "RtlGetVersion");

    auto buffer = ntoskrnl_process.read<util::page_4kb_buffer>(get_version);
    auto buf = buffer.data;

    // rcx + 12
    for (char* b = (char*)buf; b - (char*)buf < 0xf0; b++) {
        uint32_t val = *(uint32_t*)(void*)b & 0xffffff;
        if (val == 0x0c41c7 || val == 0x05c01b)
            return *(uint32_t*)(void*)(b + 3);
    }

    return 0;
}

// https://www.gaijin.at/en/infos/windows-version-numbers
static bool set_ntos_offsets(uint16_t version, uint32_t build)
{
    switch (version) {
    case 1000: /* W10 */
        ntoskrnl_offsets = (guest::ntos_offsets){
            .active_process_links = 0x2e8,
            .session = 0x448,
            .session_id = 0x8,
            .client_id = 0x440,
            .stack_count = 0x23c,
            .image_filename = 0x450,
            .dir_base = 0x28,
            .peb = 0x3f8,
            .peb32 = 0x30,
            .thread_list_head = 0x488,
            .thread_list_entry = 0x6a8,
            .teb = 0xf0,
            .vad_root = 0x7d8,
            .parent_client_id = 0x540,
            .object_table = 0x570,
        };

        if (build >= 18362) { /* Version 1903 or higher */
            ntoskrnl_offsets.active_process_links = 0x2f0;
            ntoskrnl_offsets.thread_list_entry = 0x6b8;
        }

        if (build >= 19041) { /* Version 2004 or higher */
            ntoskrnl_offsets.active_process_links = 0x448;
            ntoskrnl_offsets.stack_count = 0x348;
            ntoskrnl_offsets.image_filename = 0x5a8;
            ntoskrnl_offsets.peb = 0x550;
            ntoskrnl_offsets.thread_list_head = 0x5e0;
            ntoskrnl_offsets.thread_list_entry = 0x4e8;
            ntoskrnl_offsets.session = 0x558;
        }

        if (build >= 19045) {

        }

        break;
    default:
        return false;
    }
    return true;
}

bool guest::initialize()
{
    if (!get_ntoskrnl_base_address(get_ntoskrnl_entry())) {
        out::error("failed to get ntoskrnl base address\n");
        return false;
    }

    auto nt_version = get_ntos_version();
    auto nt_build = get_ntos_build();

    if (!set_ntos_offsets(nt_version, nt_build)) {
        out::error("failed to get ntoskrnl offsets\n");
        return false;
    }

    auto initial_system_process = util::get_proc_address(ntoskrnl_symbols, "PsInitialSystemProcess");
    ntoskrnl_process.virtual_process = ntoskrnl_process.read<uint64_t>(initial_system_process);
    ntoskrnl_process.physical_process = ntoskrnl_process.virtual_to_physical(ntoskrnl_process.virtual_process);

    // set the basic process info of ntoskrnl, lil hack
    uint64_t a = 0, b = 0;
    query_process_basic_info(a, b, ntoskrnl_process);

    std::print("Windows Kernel Version {}\n", out::value(nt_build));
    std::print("Kernel base = {} PsLoadedModuleList = {}\n\n", 
            out::address(ntoskrnl_process.base_address, out::fmt::x, out::prefix::with_prefix), 
            out::address(util::get_proc_address(ntoskrnl_symbols, "PsLoadedModuleList"), out::fmt::x, out::prefix::with_prefix));

    pdb::load(ntoskrnl_process, pdb::process_priv::kernel);

    uint8_t mi_get_pte_address_signature[] = "\x48\xc1\xe9\x09\x48\xb8\xf8\xff\xff\xff\x7f\x00\x00\x00\x48\x23\xc8\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xc1\xc3";
    char mi_get_pte_address_mask[] = "xxxxxxxxxxxxxxxxxxx????????xxxx";

    auto section = IMAGE_FIRST_SECTION(ntoskrnl_process.nt_headers);
    for (int i = 0; i < ntoskrnl_process.nt_headers->FileHeader.NumberOfSections; i++, section++) {
        section->Name[7] = 0;
        if (strcmp((char*)section->Name, ".text") == 0)
            break;
    }

    auto mi_get_pte_address = util::find_pattern(ntoskrnl_process, ntoskrnl_process.base_address + section->VirtualAddress, section->SizeOfRawData, mi_get_pte_address_signature, mi_get_pte_address_mask);
    
    mm_pte_base = ntoskrnl_process.read<uint64_t>(mi_get_pte_address + 0x13);
    mm_pde_base = mm_pte_base + (mm_pte_base >> 9 & 0x7FFFFFFFFF);
    mm_ppe_base = mm_pde_base + (mm_pde_base >> 9 & 0x3FFFFFFF);
    mm_pxe_base = mm_ppe_base + (mm_ppe_base >> 9 & 0x1FFFFF);
    mm_pxe_self = mm_pxe_base + (mm_pxe_base >> 9 & 0xFFF);

    return true;
}

mem::process guest::get_ntoskrnl_process()
{
    return ntoskrnl_process;
}

guest::ntos_offsets guest::get_ntoskrnl_offsets()
{
    return ntoskrnl_offsets;
}

std::vector<util::module> guest::get_kernel_modules()
{
    PEB_LDR_DATA ldr = { 0 };
    ldr.InMemoryOrdermoduleList.Flink = util::get_proc_address(ntoskrnl_symbols, "PsLoadedModuleList");

    uint64_t head = 0;
    uint64_t end = 0;
    uint64_t prev = 0;

    LDR_MODULE ldr_module;

    std::vector<util::module> modules;

    while (util::query_module_basic_info(ntoskrnl_process, ldr, ldr_module, head, end, prev, false)) {
        auto module_wide_name = new short[ldr_module.BaseDllName.Length];
        ntoskrnl_process.read_bytes(module_wide_name, ldr_module.BaseDllName.Buffer, ldr_module.BaseDllName.Length * sizeof(short));

        std::string modulename;
        for (int i = 0; i < ldr_module.BaseDllName.Length; i++)
            modulename.push_back(((char*)module_wide_name)[i*2]);

        delete[] module_wide_name;

        modules.push_back({ ntoskrnl_process, modulename.c_str(), ldr_module.BaseAddress, ldr_module });
    }

    return modules;
}

bool guest::query_process_basic_info(uint64_t &physical_process, uint64_t &virtual_process, mem::process &current_process)
{
    if (physical_process == 0 && virtual_process == 0) {
        physical_process = ntoskrnl_process.physical_process;
        virtual_process = ntoskrnl_process.virtual_process;
    }
    else {
        virtual_process = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.active_process_links) - ntoskrnl_offsets.active_process_links;
        if (!virtual_process)
            return false;

        physical_process = current_process.virtual_to_physical(virtual_process);
        if (!physical_process)
            return false;
    }

    current_process.process_id = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.active_process_links - 8);
    current_process.physical_process = physical_process;
    current_process.virtual_process = virtual_process;

    current_process.set_dir_base(host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.dir_base));

    util::set_process_peb(current_process, ntoskrnl_offsets.peb);

    current_process.win_dbg_data.session_id = ntoskrnl_process.read<uint32_t>(host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.session) + ntoskrnl_offsets.session_id);
    current_process.win_dbg_data.client_id = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.client_id);
    current_process.win_dbg_data.peb_address = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.peb);
    current_process.win_dbg_data.parent_client_id = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.parent_client_id);
    current_process.win_dbg_data.object_table_address = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.object_table);

    return true;
}

mem::process guest::find_process(const std::string &name)
{
    uint64_t physical_process = 0;
    uint64_t virtual_process = 0;
    mem::process current_process;

    while (query_process_basic_info(physical_process, virtual_process, current_process)) {
        auto stack_count = host::read_kvm_memory<uint64_t>(physical_process + ntoskrnl_offsets.stack_count);

        if (current_process.process_id < std::numeric_limits<int>::max() && stack_count) {
            auto base_module = util::get_module(current_process, {});

            if (name == base_module.name.c_str()) {

                auto physical_vad_root = physical_process + ntoskrnl_offsets.vad_root;
                auto vad_count = current_process.read<uint64_t>(physical_process + ntoskrnl_offsets.vad_root + 0x10);
    
                std::vector<uint64_t> visit;

                visit.push_back(physical_vad_root);

                while (visit.size() != 0) {
                    auto virtual_vad = host::read_kvm_memory<uintptr_t>(visit.back());
                    visit.pop_back();

                    if (!virtual_vad)
                        continue;

                    auto physical_vad = current_process.virtual_to_physical(virtual_vad);
                    visit.push_back(physical_vad + 0);
                    visit.push_back(physical_vad + 8);

                    auto short_vad = host::read_kvm_memory<MMVAD_SHORT>(physical_vad);

                    if (util::is_vad_short(short_vad)) {
                        MMVAD full_vad = { 0 };
                        full_vad.Core = short_vad;

                        current_process.vad_list.push_back(full_vad);
                    }
                    else {
                        current_process.vad_list.push_back(host::read_kvm_memory<MMVAD>(physical_vad));
                    }
                }

                current_process.base_address = base_module.base_address;

                return current_process;
            }
        }
    }

    return {};
}

uint64_t guest::get_pxe_address(uint64_t va)
{
    auto x = ((PMMPTE)mm_pxe_base + (((uint64_t)va >> 39) & 0x1FF));
    return *reinterpret_cast<uint64_t*>(&x);
}

uint64_t guest::get_ppe_address(uint64_t va)
{
    return mi_get_ppe_address(va);
}

uint64_t guest::get_pde_address(uint64_t va)
{
    return mi_get_pde_address(va);
}

uint64_t guest::get_pte_address(uint64_t va)
{
    return mi_get_pte_address(va);
}