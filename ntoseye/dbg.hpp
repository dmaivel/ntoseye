#pragma once

#include "pdb.hpp"
#include "mem.hpp"

#define DEFAULT_LINES 8

template<typename T>
struct is_void_return : std::is_same<T, void> {};

template<typename Func, typename... Args>
auto safe_run(Func&& func, Args&&... args) 
{
    using return_type = std::invoke_result_t<Func, Args...>;

    if constexpr (is_void_return<return_type>::value) {
        try {
            func(std::forward<Args>(args)...);
            return true;
        } catch (...) {
            return false;
        }
    } else {
        try {
            return std::optional<return_type>(func(std::forward<Args>(args)...));
        } catch (...) {
            return std::optional<return_type>();
        }
    }
}

namespace dbg {
    mem::process& get_current_process();

    uintptr_t str2v(const std::string &str, int rad = 16);

    uintptr_t sym2addr(pdb::symbol &symbol, const std::string &fn_start = ".text", const std::string &data_start = ".data");
    uintptr_t name2addr(const std::string &name, const std::string &fn_start = ".text", const std::string &data_start = ".data");
    std::pair<std::string, uintptr_t> closest_symbol(uintptr_t address);

    void install_builtin_commands();

    void install_breakpoint_signal();
    void uninstall_breakpoint_signal();
}