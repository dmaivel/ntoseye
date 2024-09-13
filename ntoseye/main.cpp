#include "cmd.hpp"
#include "curl.hpp"
#include "dbg.hpp"
#include "host.hpp"
#include "guest.hpp"
#include "lua.hpp"
#include "log.hpp"
#include "gdb.hpp"

#include "version.h"

#include <fmt/core.h>
#include <print>
#include <string>

static std::string strip(const std::string &s)
{
    auto it_start = s.begin();
    auto it_end = s.rbegin();

    while (std::isspace(*it_start))
        ++it_start;
    while (std::isspace(*it_end))
        ++it_end;

    return std::string(it_start, it_end.base());
}

int main(int argc, char **argv)
{
    bool gdb_status = gdb::initialize();
    out::special("Windows debugger for Linux (ntoseye v{})\n\n", NTOSEYE_VERSION);

    if (!gdb_status) {
        out::warn("gdbstub not found, proceeding without control flow capabilities\n");
        out::warn("to enable gdbstub, pass '-s -S' into QEMU\n\n");
    }

    // non-fatal
    curl::initialize();

    if (!host::initialize())
        return 1;

    if (!guest::initialize())
        return 1;

    dbg::install_builtin_commands();

    if (!lua::initialize())
        return 1;

    cmd::initialize_readline();

    while (true) {
        dbg::install_breakpoint_signal();
        auto input = cmd::read_line("\n" COLOR_INPUT "(ntoseye) " COLOR_RESET);
        dbg::uninstall_breakpoint_signal();

        if (input.empty())
            continue;

        try {
            if (strip(input) == "q")
                break;
        }
        catch (...) {
            continue;
        }

        auto status = cmd::attempt_callback(input, dbg::get_current_process());

        switch (status.status_value) {
        case cmd::status_code::success:
            break;
        case cmd::status_code::invalid_syntax:
            out::error("invalid syntax");
            break;
        case cmd::status_code::invalid_argument:
            out::error("invalid argument");
            break;
        case cmd::status_code::unimplemented:
            out::error("functionality is unimplemented");
            break;
        case cmd::status_code::unknown_command:
            out::error("unrecognized command");
            break;
        case cmd::status_code::script_failed_during_run:
            out::error("script failed during run");
            break;
        case cmd::status_code::script_callback_not_found:
            out::error("script has registered a callback, but callback not found");
            break;
        default:
            out::error("command returned unknown status (%d)", static_cast<int>(status.status_value));
            break;
        }

        if (status.status_value != cmd::status_code::success && !status.error_message.empty())
            std::print(" ({})\n", status.error_message);
        else if (status.status_value != cmd::status_code::success)
            std::puts("");
    }

    gdb::detach();
    return 0;
}
