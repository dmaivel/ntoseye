#include "dbg.hpp"
#include "cmd.hpp"
#include "gdb.hpp"
#include "guest.hpp"
#include "log.hpp"
#include "lua.hpp"
#include "util.hpp"
#include "mem.hpp"

#include <Zydis/Zydis.h>

#include <csignal>
#include <expected>
#include <ranges>

mem::process current_process;
int radix = 16;

mem::process& dbg::get_current_process()
{
    return current_process;
}

uintptr_t dbg::str2v(const std::string &str, int rad)
{
    return std::stoull(str, nullptr, rad);
}

uintptr_t dbg::sym2addr(pdb::symbol &symbol, const std::string &fn_start, const std::string &data_start)
{
    auto section = symbol.type == pdb::symbol::sym_type::data ? data_start : fn_start;
    return current_process.base_address + util::get_section_virtual_address(current_process, section) + symbol.offset;
}

uintptr_t dbg::name2addr(const std::string &name, const std::string &fn_start, const std::string &data_start)
{
    auto pdb_sym = pdb::get(name);
    if (pdb_sym.has_value())
        return sym2addr(pdb_sym.value(), fn_start, data_start);
    
    auto exports = util::get_process_exports(current_process);
    return util::get_proc_address(exports, name);
}

std::pair<std::string, uintptr_t> dbg::closest_symbol(uintptr_t address)
{
    auto pdb_symbols = pdb::get_all();
    if (!pdb_symbols.empty()) {
        pdb::symbol closest;
        closest.offset = 0;

        for (auto &sym : pdb_symbols) {
            auto sym_address = sym2addr(sym);
            if (sym_address <= address && sym_address > sym2addr(closest))
                closest = sym;
        }

        return { closest.name, address - sym2addr(closest) };
    }
    else {
        auto exports = util::get_process_exports(current_process);
        util::symbol closest;
        closest.address = 0;

        for (auto &sym : exports) {
            if (sym.address <= address && sym.address > closest.address)
                closest = sym;
        }

        return { closest.name, address - closest.address };
    }

    return { "??", 0 };
}

static std::expected<uintptr_t, std::string> arg_expect_address(const std::string &arg, int radix = 16)
{
    cmd::argument parsed_arg(arg, radix);

    switch (parsed_arg.type) {
    case cmd::arg_type::integer:
        return parsed_arg.u64;
    case cmd::arg_type::string:
        parsed_arg.u64 = dbg::name2addr(parsed_arg.str);
        if (parsed_arg.u64)
            return parsed_arg.u64;
        return std::unexpected("symbol not found");
    default:
        return std::unexpected("expected valid address");
    }
}

void dbg::install_builtin_commands()
{
    current_process = guest::get_ntoskrnl_process();

    cmd::register_callback("!pte", [&](auto args, auto current_process) {
        if (args.size() != 1)
            return cmd::status::invalid_syntax("expected 1 argument");

        auto expect_virtual_address = arg_expect_address(args[0]);
        if (!expect_virtual_address)
            return cmd::status::invalid_syntax(expect_virtual_address.error());

        auto virtual_address = expect_virtual_address.value();

        std::print("VA {}\n", out::address(virtual_address));

        auto pxe = guest::get_pxe_address(virtual_address);
        auto ppe = guest::get_ppe_address(virtual_address);
        auto pde = guest::get_pde_address(virtual_address);
        auto pte = guest::get_pte_address(virtual_address);
        
        std::print("PXE at {}    PPE at {}    PDE at {}    PTE at {}\n", 
                out::address(pxe, out::fmt::X), out::address(ppe, out::fmt::X), out::address(pde, out::fmt::X), out::address(pte, out::fmt::X));
        
        // incase current process isn't ntoskrnl
        auto ntoskrnl = guest::get_ntoskrnl_process();

        auto cpxe = ntoskrnl.read<MMPTE>(pxe);
        auto cppe = ntoskrnl.read<MMPTE>(ppe);
        auto cpde = ntoskrnl.read<MMPTE>(pde);
        auto cpte = !cpde.u.Hard.LargePage ? ntoskrnl.read<MMPTE>(pte) : MMPTE{ 0 };

        std::print("contains {}  contains {}  contains {}  contains {}\n", 
                out::value_hex(cpxe.u.Long, out::fmt::X), out::value_hex(cppe.u.Long, out::fmt::X), out::value_hex(cpde.u.Long, out::fmt::X), out::value_hex(cpte.u.Long, out::fmt::X));

        static constexpr auto dump_bits = [](const MMPTE &pte, bool first) {
            if (pte.u.Long == 0) {
                if (first)
                    std::print("not valid");
                return;
            }

            auto pfn_digits = std::format("{:04x}", pte.u.Hard.PageFrameNumber).size();

            std::print("pfn {:04x}{}{}{:c}{:c}{:c}{:c}{:c}{:c}{:c}{:c}{:c}{:c}{:c}  ",
                pte.u.Hard.PageFrameNumber,
                out::align(10, pfn_digits, 1),
                first ? "" : "",
                pte.u.Hard.CopyOnWrite ? 'C' : '-',
                pte.u.Hard.Global ? 'G' : '-',
                pte.u.Hard.LargePage ? 'L' : '-',
                pte.u.Hard.Dirty ? 'D' : '-',
                pte.u.Hard.Accessed ? 'A' : '-',
                pte.u.Hard.CacheDisable ? 'N' : '-',
                '-',
                pte.u.Hard.Owner ? 'U' : 'K',
                pte.u.Hard.Write ? 'W' : 'R',
                pte.u.Hard.NoExecute ? '-' : 'E',
                pte.u.Hard.Valid ? 'V' : '-');

            if (pte.u.Hard.LargePage)
                std::print("LARGE PAGE pfn {:04x}", pte.u.Hard.PageFrameNumber);
        };

        dump_bits(cpxe, true);
        dump_bits(cppe, false);
        dump_bits(cpde, false);
        dump_bits(cpte, false);

        std::puts("");

        return cmd::status::success();
    });

    cmd::register_callback("!process", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 2)
            return cmd::status::invalid_syntax("expected 2 arguments");

        int v0, v1;
        if (!safe_run([&]() { v0 = std::stoull(args[0], nullptr, radix); }) || !safe_run([&]() { v1 = std::stoull(args[1], nullptr, radix); }))
            return cmd::status::invalid_syntax("expected '!process 0 0'");

        if (v0 != 0 || v1 != 0)
            out::warn("flags not supported\n");

        std::print("**** NT ACTIVE PROCESS DUMP ****\n");

        uint64_t phys = 0;
        uint64_t virt = 0;
        mem::process process;

        while (guest::query_process_basic_info(phys, virt, process)) {
            auto base = util::get_module(process, {});
            if (base.name.empty())
                continue;

            std::print("PROCESS {}\n", out::address(virt, out::fmt::x));
            
            std::print("{} SessionId: {}  Cid: {}  Peb: {}  ParentCid: {}\n", out::indent(), 
                    out::value(process.win_dbg_data.session_id), out::value_hex<4>(process.win_dbg_data.client_id),
                    out::address<10>(process.win_dbg_data.peb_address), out::value_hex<4>(process.win_dbg_data.parent_client_id));
            
            std::print("{} DirBase: {}  ObjectTable: {}\n", out::indent(),
                    out::address<9>(process.dir_base), out::address(process.win_dbg_data.object_table_address));

            std::print("{} Image: {}\n\n", out::indent(), out::name(base.name.c_str()));
        }

        return cmd::status::success();
    }, "!process 0 0");

    cmd::register_callback(".process", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 1 && args.size() != 2)
            return cmd::status::invalid_syntax("expected either: [EPROCESS address] or [/p /r]");

        uint64_t address_of_eprocess;
        if (args.size() == 1)
            if (!safe_run([&]() { address_of_eprocess = std::stoull(args[0], nullptr, 16); }))
                return cmd::status::invalid_syntax("expected virtual address of EPROCESS");

        if (args.size() == 2)
            ::current_process = guest::get_ntoskrnl_process();
        else {
            uint64_t phys = 0;
            uint64_t virt = 0;
            mem::process process;

            while (guest::query_process_basic_info(phys, virt, process) && virt != address_of_eprocess);

            if (virt != address_of_eprocess)
                return cmd::status::invalid_argument("couldn't find matching EPROCESS address");

            ::current_process = process;
        }

        std::print("Implicit process is now {}\n", out::address(::current_process.virtual_process));

        pdb::load(::current_process, pdb::process_priv::user);

        return cmd::status::success();
    });

    cmd::register_callback("q", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        return cmd::status::unknown_command("if you see this, something went very wrong");
    });

    cmd::register_callback("reload_lua", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        return lua::initialize() ? cmd::status::success() : cmd::status::invalid_argument("failed to re-initialize lua");
    });

    cmd::register_callback("n", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 1)
            return cmd::status::invalid_syntax("expected 1 argument");

        int local_radix = 0;
        if (!safe_run([&]() { local_radix = std::stoull(args[0], nullptr, 10); }))
            return cmd::status::invalid_syntax("expected either '10' or '16'");

        if (local_radix != 10 && local_radix != 16)
            return cmd::status::invalid_argument("expected either '10' or '16'");

        radix = local_radix;

        return cmd::status::success();
    });

    cmd::register_callback("u", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 1 && args.size() != 2)
            return cmd::status::invalid_syntax("expected either just address or address and range");

        uintptr_t virtual_start_address;
        uintptr_t virtual_end_address;

        auto expect_virtual_start_address = arg_expect_address(args[0]);
        if (!expect_virtual_start_address)
            return cmd::status::invalid_syntax(expect_virtual_start_address.error());

        virtual_start_address = expect_virtual_start_address.value();

        int lines;
        if (args.size() == 1) {
            lines = DEFAULT_LINES;
        }
        else {
            auto arg1 = cmd::argument(args[1]);
            switch (arg1.type) {
            case cmd::arg_type::integer:
                virtual_end_address = arg1.u64;
                if (virtual_end_address < virtual_start_address)
                    return cmd::status::invalid_argument("invalid range, end address is smaller than start address");
                lines = 0;
                break;
            case cmd::arg_type::line:
                lines = arg1.u64;
                break;
            default:
                return cmd::status::invalid_argument("invalid range");
            }
        }

        ZydisDisassembledInstruction instruction;
        uint8_t data[16];
        int count = 0;

        auto symbol = closest_symbol(virtual_start_address);
        std::println("{}+0x{:x}", symbol.first, symbol.second);

        while (lines ? count < lines : virtual_start_address < virtual_end_address) {
            current_process.read_bytes(data, virtual_start_address, 16);

            ZydisDisassembleIntel(!current_process.WOW64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32, virtual_start_address, data, sizeof(data), &instruction);

            auto length = instruction.info.length;

            std::print("{}  {}{} {}\n", out::address(virtual_start_address), out::value(out::hex_arr(data, length)),
                    out::align(10, length, 2), instruction.text);

            virtual_start_address += length;
            count++;
        }

        return cmd::status::success();
    });

    cmd::register_callback("uf", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        auto s = args | std::views::join_with(' ') | std::ranges::to<std::string>();
        return cmd::attempt_callback("u " + s, current_process);
    });

    cmd::register_callback("db", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 1 && args.size() != 2)
            return cmd::status::invalid_syntax("expected either just address or address and range");

        uintptr_t virtual_start_address;
        uintptr_t virtual_end_address;

        auto expect_virtual_start_address = arg_expect_address(args[0]);
        if (!expect_virtual_start_address)
            return cmd::status::invalid_syntax(expect_virtual_start_address.error());

        virtual_start_address = expect_virtual_start_address.value();

        int lines;
        size_t bytes;

        if (args.size() == 1) {
            virtual_end_address = virtual_start_address + (DEFAULT_LINES * 0x10);

            lines = DEFAULT_LINES;
            bytes = lines * 0x10;
        }
        else {
            auto arg1 = cmd::argument(args[1]);
            switch (arg1.type) {
            case cmd::arg_type::integer:
                virtual_end_address = arg1.u64 + 1;
                if (virtual_end_address < virtual_start_address)
                    return cmd::status::invalid_argument("invalid range, end address is smaller than start address");
                break;
            case cmd::arg_type::line:
                virtual_end_address = virtual_start_address + arg1.u64;
                break;
            default:
                return cmd::status::invalid_argument("invalid range");
            }

            auto length = virtual_end_address - virtual_start_address;

            lines = (length / 0x10) + (length % 0x10 != 0);
            bytes = length;
        }

        auto memory = new uint8_t[bytes];
        current_process.read_bytes(memory, virtual_start_address, bytes);

        for (int i = 0; i < lines; i++) {
            int count = bytes > 0x10 ? 0x10 : bytes;
            auto arr = &memory[i * 0x10];

            std::print("{}  {}{} {}\n", out::address(virtual_start_address), out::hex_arr(arr, count, " "), out::align(0x10, count, 3), out::char_arr(arr, count));

            virtual_start_address += 0x10;
            bytes -= 0x10;
        }

        delete[] memory;

        return cmd::status::success();
    });

    cmd::register_callback("lm", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        auto modules = guest::get_kernel_modules();
        std::println("start            end              path");
        for (auto m : modules)
            std::println("{} {} {}", out::address(m.base_address), out::address(m.base_address + m.ldr_module.SizeOfImage), out::name(m.name.substr(0, m.name.find(".sys"))));
        return cmd::status::success();
    });

    cmd::register_callback("break", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        auto address = gdb::breakpoint();
        if (!address) {
            out::error("breakpoint failed ({})\n", address.error());
            return cmd::status::success();
        }

        std::println("Breakpoint at {}", out::address(address.value()));

        cmd::attempt_callback(std::format("u {:x} L1", address.value()), current_process);

        return cmd::status::success();
    });

    cmd::register_callback("g", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (gdb::resume()) {
            std::println("continued...");
            return cmd::status::success();
        }

        out::error("process already running\n");
        return cmd::status::success();
    });

    cmd::register_callback("x", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() != 1)
            return cmd::status::invalid_syntax("expected one argument");

        bool wildcard = args[0] == "*";
        auto pdb_symbols = pdb::get_all();

        for (auto &sym : pdb_symbols) {
            if (sym.name.contains(args[0]) || wildcard)
                std::println("{} {}", out::address(dbg::sym2addr(sym)), std::format("{}", sym.name));
        }

        return cmd::status::success();
    });

    cmd::register_callback("r", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        auto expected_registers = gdb::get_registers();
        if (!expected_registers)
            return cmd::status::invalid_argument(expected_registers.error());

        auto registers = expected_registers.value();

        if (args.empty()) {
            std::println("rax={} rbx={} rcx={}", out::value_hex(registers["rax"]), out::value_hex(registers["rbx"]), out::value_hex(registers["rcx"]));
            std::println("rdx={} rsi={} rdi={}", out::value_hex(registers["rdx"]), out::value_hex(registers["rsi"]), out::value_hex(registers["rdi"]));
            std::println("rip={} rsp={} rbp={}", out::value_hex(registers["rip"]), out::value_hex(registers["rsp"]), out::value_hex(registers["rbp"]));
            std::println(" r8={}  r9={} r10={}", out::value_hex(registers["r8"]), out::value_hex(registers["r9"]), out::value_hex(registers["r10"]));
            std::println("r11={} r12={} r13={}", out::value_hex(registers["r11"]), out::value_hex(registers["r12"]), out::value_hex(registers["r13"]));
            std::println("r14={} r15={}", out::value_hex(registers["r14"]), out::value_hex(registers["r15"]));

            auto eflags = *reinterpret_cast<gdb::eflags*>(&registers["eflags"]);
            std::println("iopl={} {} {} {} {} {} {} {} {}", (int)eflags.IOPL, 
                eflags.OF ? "ov" : "nv",
                eflags.DF ? "dn" : "up",
                eflags.IF ? "di" : "ei",
                eflags.SF ? "ng" : "pl",
                eflags.ZF ? "zr" : "nz",
                eflags.AF ? "ac" : "na",
                eflags.PF ? "po" : "pe",
                eflags.CF ? "cy" : "nc");

            std::println("cs={} ss={} ds={} es={} fs={} gs={} efl={}", 
                out::value_hex<4>(registers["cs"]), out::value_hex<4>(registers["ss"]), out::value_hex<4>(registers["ds"]), out::value_hex<4>(registers["es"]), out::value_hex<4>(registers["fs"]), out::value_hex<4>(registers["gs"]), out::value_hex<8>(registers["eflags"]));

            cmd::attempt_callback(std::format("u {:x} L1", registers["rip"]), current_process);
            
            return cmd::status::success();
        }

        // first validate input
        for (const auto &r : args)
            if (!registers.contains(r))
                return cmd::status::invalid_argument(std::format("register '{}' not found", r));

        // then print
        for (const auto &r : args)
            std::println("{}={}", r, out::value_hex(registers[r]));

        return cmd::status::success();
    });

    cmd::register_callback("~", [&](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
        if (args.size() > 1)
            return cmd::status::invalid_syntax("expected either one or no arguments");

        if (args.empty()) {
            auto result = gdb::get_current_thread();
            if (!result)
                return cmd::status::invalid_argument(result.error());

            std::println("Currently on processor {} ({} available)", result.value(), gdb::get_num_threads());
            return cmd::status::success();
        }

        cmd::argument arg(args[0], 10);
        if (arg.type != cmd::arg_type::integer)
            return cmd::status::invalid_argument("expected integer");

        auto result = gdb::set_current_thread(arg.u64);
        if (!result.has_value())
            return cmd::status::invalid_argument(result.error());

        return result.value() ? cmd::status::success() : cmd::status::invalid_argument("processor doesn't exist");
    });
}

static void int_handler(int status) 
{
    gdb::set_signal_raised();
    cmd::reformat_after_signal();
    cmd::attempt_callback("break", dbg::get_current_process());
    std::println("");
    cmd::finish_reformat_after_signal();
}

void dbg::install_breakpoint_signal()
{
    signal(SIGINT, int_handler);
}

void dbg::uninstall_breakpoint_signal()
{
    signal(SIGINT, SIG_DFL);
}