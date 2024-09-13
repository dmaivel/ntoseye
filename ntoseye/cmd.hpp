#pragma once

#include "mem.hpp"

#include <algorithm>
#include <functional>
#include <string>

namespace cmd {
    enum class status_code : int {
        success,
        invalid_syntax,
        invalid_argument,
        unimplemented,
        unknown_command,
        script_failed_during_run,
        script_callback_not_found,
    };

    enum class prompt_result : int {
        no,
        yes,
        all
    };

    enum class arg_type : int {
        string,     // self
        integer,    // 0x, 0, ...
        line,       // L_ (e.g L4)
        flag        // /_ (e.g /F)
    };

    struct argument {
        arg_type type;
        std::string str;
        uint64_t u64;

        argument(const std::string &arg, int radix = 16) {
            if (arg.empty())
                return;

            switch (arg[0]) {
            case '/':
                type = arg.size() > 1 ? arg_type::flag : arg_type::string; 
                str = arg;
                u64 = arg.size() > 1 ? (uint64_t)arg[1] : 0;
                return;
            case 'L':
                if (!std::all_of(arg.begin() + 1, arg.end(), ::isxdigit))
                    break;
                type = arg_type::line;
                str = arg;
                u64 = std::stoull(&arg.c_str()[1], nullptr, radix);
                return;
            default:
                break;
            }

            try {
                u64 = std::stoull(arg, nullptr, radix);
            }
            catch (...) {
                type = arg_type::string;
                str = arg;
                u64 = 0;
                return;
            }

            type = arg_type::integer;
            str = arg;
            return;
        }
    };

    struct status {
        status() noexcept : status_value(status_code::success) { }
        status(status_code status) : status_value(status) { }
        status(status_code status, const std::string &message) : status_value(status), error_message(message) { }
        
        status_code status_value;
        std::string error_message;

        static inline status success()
        {
            return status(status_code::success);
        }

        static inline status invalid_syntax(const std::string &message = "")
        {
            return status(status_code::invalid_syntax, message);
        }

        static inline status invalid_argument(const std::string &message = "")
        {
            return status(status_code::invalid_argument, message);
        }

        static inline status unimplemented(const std::string &message = "")
        {
            return status(status_code::unimplemented, message);
        }

        static inline status unknown_command(const std::string &message = "")
        {
            return status(status_code::unknown_command, message);
        }

        static inline status script_failed_during_run(const std::string &message = "")
        {
            return status(status_code::script_failed_during_run, message);
        }

        static inline status script_callback_not_found(const std::string &message = "")
        {
            return status(status_code::script_callback_not_found, message);
        }
    };

    using callback = std::function<status(const std::vector<std::string>&, mem::process&)>;

    void register_callback(const std::string &cmd, const callback &callback, const std::string &custom_completion = {});
    status attempt_callback(const std::string &fullcmd, mem::process &current_process);

    void initialize_readline();
    void reformat_after_signal();
    void finish_reformat_after_signal();
    
    std::string read_line(const char *s);
    bool read_yes_no(const char* s);
}