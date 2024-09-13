#include "lua.hpp"
#include "cmd.hpp"
#include "guest.hpp"
#include "mem.hpp"
#include "config.hpp"
#include "log.hpp"

#include <filesystem>

#include <sol/forward.hpp>

#include <sol/sol.hpp>
#include <sol/types.hpp>
#include <sol/usertype_container.hpp>

sol::state lua_state;

bool lua::initialize()
{
    lua_state = sol::state();

    auto scripts_directory = config::get_storage_directory() + "/scripts";
    std::filesystem::create_directories(scripts_directory);

    lua_state.open_libraries(sol::lib::base, sol::lib::string, sol::lib::math);

    lua_state["status_code_success"] = (double)cmd::status_code::success;
    lua_state["status_code_invalid_syntax"] = (double)cmd::status_code::invalid_syntax;
    lua_state["status_code_invalid_argument"] = (double)cmd::status_code::invalid_argument;
    lua_state["status_code_unimplemented"] = (double)cmd::status_code::unimplemented;
    lua_state["status_code_unknown_command"] = (double)cmd::status_code::unknown_command;
    
    lua_state.new_usertype<std::vector<std::string>>("vector_string",
        "new", sol::constructors<std::vector<std::string>()>(),
        "size", &std::vector<std::string>::size,
        "get", [](std::vector<std::string>& vec, int index) {
            if (index >= 1 && index <= static_cast<int>(vec.size())) {
                return vec[index - 1];
            }
            return std::string();
        }
    );

    lua_state.new_usertype<uint64>("uint64",
        "low", &uint64::low,
        "high", &uint64::high);

    lua_state.set_function("status_success", []() { 
        return cmd::status::success();
    });

    lua_state.set_function("status_invalid_syntax", [](const std::string &m) { 
        return cmd::status::invalid_syntax(m);
    });

    lua_state.set_function("status_invalid_argument", [](const std::string &m) { 
        return cmd::status::invalid_argument(m);
    });

    lua_state.set_function("status_unimplemented", [](const std::string &m) { 
        return cmd::status::unimplemented(m);
    });

    lua_state.new_usertype<mem::process>("mem_process",
        "dir_base", &mem::process::dir_base,
        "base_address", sol::property(
                            [](mem::process& obj) -> uint64 {
                                return uint64(obj.base_address);
                            },
                            [](mem::process& obj, const uint64& luavalue) {
                                obj.base_address = luavalue.value;
                            }
                        ),
        "virtual_process", sol::property(
                                [](mem::process& obj) -> uint64 {
                                    return uint64(obj.virtual_process);
                                },
                                [](mem::process& obj, const uint64& luavalue) {
                                    obj.virtual_process = luavalue.value;
                                }
                           ),
        "physical_process", sol::property(
                                [](mem::process& obj) -> uint64 {
                                    return uint64(obj.physical_process);
                                },
                                [](mem::process& obj, const uint64& luavalue) {
                                    obj.physical_process = luavalue.value;
                                }
                            ),
        "virtual_to_physical", &mem::process::virtual_to_physical,
        "set_dir_base", &mem::process::set_dir_base,
        "read_bytes", &mem::process::read_bytes,
        "write_bytes", &mem::process::write_bytes);

    lua_state.set_function("guest_get_ntoskrnl_process", []() { 
        return guest::get_ntoskrnl_process();
    });

    int loaded_scripts_count = 0;
    bool any_errors = false;

    std::function<void(const std::string &directory)> load_scripts;
    load_scripts = [&](const std::string &directory) -> void {
        std::ranges::for_each(std::filesystem::directory_iterator(directory),
            [&](std::filesystem::directory_entry dir_entry) {
                if (dir_entry.is_directory())
                    load_scripts(dir_entry.path());

                if (!dir_entry.is_regular_file()) {
                    if (dir_entry.is_symlink())
                        dir_entry = std::filesystem::directory_entry(std::filesystem::read_symlink(dir_entry));
                    else
                        return;
                }

                try {
                    lua_state.script_file(dir_entry.path(), sol::load_mode::text);

                    auto file = dir_entry.path().filename().string();
                    auto table_name = file.substr(0, file.find_last_of('.'));

                    auto table = lua_state[table_name];
                    if (!table.valid()) {
                        any_errors = true;
                        out::error("script '{}' is missing table '{}'\n", file, table_name);
                        return;
                    }

                    sol::safe_function on_load = table["on_load"];
                    if (on_load.valid()) {
                        auto result = on_load();
                        if (!result.valid() || result.get_type() != sol::type::string || result.get<std::string>().empty()) {
                            any_errors = true;
                            out::warn("script '{}' didn't return a callback contained in string\n", file, table_name);
                            return;
                        }

                        auto cmd = result.get<std::string>();
                        cmd::register_callback(":" + cmd, [cmd](const std::vector<std::string> &args, mem::process &current_process) -> cmd::status {
                            sol::safe_function func = lua_state[cmd];
                            if (func.valid()) {
                                auto result = func(args, current_process);

                                if (!result.valid()) {
                                    sol::error err = result;
                                    std::print("{}\n", err.what());

                                    return cmd::status::script_failed_during_run();
                                }
                                else {
                                    return result;
                                }
                            }

                            return cmd::status::script_callback_not_found();
                        });

                        loaded_scripts_count++;
                    }
                    else {
                        any_errors = true;
                        out::error("script '{}' is missing '{}.on_load()'\n", file, table_name);
                    }
                }
                catch (const sol::error &e) {
                    any_errors = true;
                    out::error("something went wrong attempting to load script '{}' {}\n", dir_entry.path().string(), e.what());
                }
            });
    };

    std::puts("");
    load_scripts(scripts_directory);

    if (any_errors)
        std::puts("");

    std::print("Loaded {} scripts\n", out::value(loaded_scripts_count));

    return true;
}