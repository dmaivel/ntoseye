#include "cmd.hpp"
#include "mem.hpp"

#include <map>
#include <algorithm>
#include <ostream>
#include <ranges>
#include <print>

#include <readline/history.h>
#include <readline/readline.h>

struct internal_callback {
    cmd::callback callback;
    std::string completion;
};

std::map<std::string, internal_callback> global_callbacks;

void cmd::register_callback(const std::string &cmd, const callback &callback, const std::string &custom_completion)
{
    global_callbacks[cmd] = { 
        .callback = callback,
        .completion = custom_completion.empty() ? cmd : custom_completion
    };
}

cmd::status cmd::attempt_callback(const std::string &fullcmd, mem::process &current_process)
{
    const std::string& delim = " ";
    auto args = fullcmd | std::views::split(delim)
                        | std::ranges::to<std::vector<std::string>>();

    // remove whitespaces
    args.erase(std::remove(args.begin(), args.end(), std::string()), args.end());

    // remove command
    auto command = *args.begin();
    args.erase(args.begin());
                            
    return global_callbacks.contains(command) 
            ? global_callbacks[command].callback(args, current_process)
            : cmd::status::unknown_command();
}

static char *command_generator(const char *text, int state)
{
    static int list_index, len;
    int local_index = 0;

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    if (list_index == global_callbacks.size())
        return NULL;

    for (const auto & [cmd, callbackInfo] : global_callbacks) {
        if (local_index < list_index) {
            local_index++;
            continue;
        }
        else {
            local_index++;
            list_index++;
        }

        const char *name = callbackInfo.completion.c_str();
        if (std::strncmp(name, text, len) == 0)
            return strdup(name);
    }

    return NULL;
}

static char **command_completion(const char *text, int start, int end)
{
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, command_generator);
}

void cmd::initialize_readline()
{
    using_history();
    rl_attempted_completion_function = command_completion;
}

void cmd::reformat_after_signal()
{
    std::println("");
    rl_on_new_line();
    rl_replace_line("", 0);
}

void cmd::finish_reformat_after_signal()
{
    rl_redisplay();
}

std::string cmd::read_line(const char *s)
{
    auto raw_input = readline(s);
    add_history(raw_input);

    std::string input(raw_input);
    delete[] raw_input;

    return input;
}

bool cmd::read_yes_no(const char* s)
{
    auto raw_input = readline(s);

    std::string input(raw_input);
    delete[] raw_input;

    if (input.empty() || input == "n" || input == "N")
        return false;
    else if (input == "y" || input == "Y")
        return true;

    std::puts("Please answer either y or [n].");
    return read_yes_no(s);
}