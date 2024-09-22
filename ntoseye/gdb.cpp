#include "gdb.hpp"
#include "log.hpp"
#include "util.hpp"

#include <cstring>
#include <expected>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include <print>
#include <sstream>
#include <vector>
#include <ranges>
#include <algorithm>
#include <functional>

// to-do: display error messages?

bool in_breakpoint = false;
bool signal_raised = false;

int processor_count = 0;

struct mi_entry {
    std::string name;
    std::string content;
    std::vector<mi_entry> children;

    mi_entry()
    {

    }

    mi_entry(const std::string &name, const std::string &content) : name(name), content(content)
    {

    }

    // strcmp equiv
    mi_entry& operator[](const std::string &name)
    {
        auto x = std::find_if(children.begin(), children.end(), [name](auto element){
            return element.name == name;
        });

        if (x == children.end())
            return *std::find_if(children.begin(), children.end(), [name](auto element){
                return element.content == name;
            });

        if (x == children.end())
            throw std::bad_expected_access("could not find expected entry from gdb");

        return *x;
    }

    // strstr equiv
    mi_entry& operator()(const std::string &name)
    {
        auto x = std::find_if(children.begin(), children.end(), [name](auto element){
            return element.name.contains(name);
        });

        if (x == children.end())
            return *std::find_if(children.begin(), children.end(), [name](auto element){
                return element.content.contains(name);
            });

        if (x == children.end())
            throw std::bad_expected_access("could not find expected entry from gdb");

        return *x;
    }

    inline bool is_valid()
    {
        return !content.empty();
    }

    inline bool is_string()
    {
        return children.empty() && !content.empty();
    }

    inline bool is_array()
    {
        return !children.empty();
    }

    static mi_entry construct(const std::string &raw_output)
    {
        mi_entry outputs;

        std::istringstream iss(raw_output);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.contains("(gdb)"))
                continue;

            outputs.children.push_back(mi_entry());
            auto &output = outputs.children.back();

            const std::string& delim = ",";
            auto line_elems = line | std::views::split(delim)
                                   | std::ranges::to<std::vector<std::string>>();

            auto first_string = line_elems[0];
            if (first_string[0] == '~' || first_string[0] == '&' || first_string[0] == '^') {
                output.content = util::string_replace(util::string_replace(first_string.substr(2), "\\n", "\n"), "\"", "");
                continue;
            }

            output.content = line_elems.begin()->substr(1, line_elems.begin()->back());
            line_elems.erase(line_elems.begin());

            using iter_t = std::vector<std::string>::iterator;

            std::function<iter_t(mi_entry &current_array, iter_t it)> recurse_build;
            recurse_build = [&](mi_entry &current_array, iter_t it) -> iter_t {
                for (auto iter = it; iter != line_elems.end();) {
                    auto content = *iter;
                    auto divide_at_equal = content.find("=");

                    content = util::string_replace(util::string_replace(content, "\\n", "\n"), "\"", "");

                    if (content.contains("{")) {
                        current_array.children.push_back(mi_entry(content.substr(0, divide_at_equal), ""));
                        auto next_level = current_array.children.back().children;

                        *iter = content.substr(content.find("{") + 1);
                        iter = recurse_build(current_array.children.back(), iter);
                    }
                    else if (content.contains("}")) {
                        current_array.children.push_back(mi_entry(content.substr(0, divide_at_equal), util::string_replace(content.substr(divide_at_equal + 1, content.back() - 2), "}", "")));
                        iter++;
                        return iter;
                    }
                    else {
                        current_array.children.push_back(mi_entry(content.substr(0, divide_at_equal), content.substr(divide_at_equal + 1, content.back() - 1)));
                        iter++;
                    }
                }

                return iter_t();
            };

            recurse_build(output, line_elems.begin());
        }

        return outputs;
    }

    void dump(int indent = 0) 
    {
        for (auto & x : children) {
            if (x.children.size() != 0) {
                std::println("{}> {}", std::string(indent, ' '), x.content);
                x.dump(indent + 2);
            }
            else {
                std::println("{}> {} = {}", std::string(indent, ' '), x.name, x.content);
            }
        }
    }
};

class gdb_interface {
public:
    gdb_interface()
    { 

    }

    ~gdb_interface()
    {
        close_pipes();
    }

    void in(const std::string &line)
    {
        if (!gdb_in)
            return;

        std::fprintf(gdb_in, "%s\n", line.c_str());
        std::fflush(gdb_in);
    }

    // to-do: turn into std::expected if elapsed is implemented?
    std::string out()
    {
        if (!gdb_out) 
            return "";

        char buffer[1024];
        std::string output;

        // to-do: count total iterations elapsed in case we get stuck here
        while (std::fgets(buffer, sizeof(buffer), gdb_out)) {
            output += buffer;
            if (std::strstr(buffer, "(gdb)") != nullptr) break;
        }

        return output;
    }

    inline std::string in_out(const std::string &line)
    {
        in(line);
        return out();
    }

    bool initialize()
    {
        int in_pipe[2], out_pipe[2];

        if (pipe(in_pipe) == -1 || pipe(out_pipe) == -1)
            return false;

        gdb_pid = fork();
        if (gdb_pid == -1)
            return false;

        if (gdb_pid == 0) {
            dup2(in_pipe[0], STDIN_FILENO);
            dup2(out_pipe[1], STDOUT_FILENO);
            dup2(out_pipe[1], STDERR_FILENO);

            close(in_pipe[0]);
            close(in_pipe[1]);
            close(out_pipe[0]);
            close(out_pipe[1]);

            execlp("gdb", "gdb", "--quiet", "--interpreter=mi", nullptr);
            exit(1);
        }

        // parent process
        close(in_pipe[0]);
        close(out_pipe[1]);

        gdb_in = fdopen(in_pipe[1], "w");
        gdb_out = fdopen(out_pipe[0], "r");

        if (!gdb_in || !gdb_out)
            return false;

        return true;
    }

    void close_pipes()
    {
        if (gdb_in) 
            fclose(gdb_in);
        if (gdb_out) 
            fclose(gdb_out);

        if (gdb_pid > 0) {
            kill(gdb_pid, SIGTERM);
            waitpid(gdb_pid, nullptr, 0);
        }

        // prevent detaching more than once
        gdb_in = 0;
        gdb_out = 0;
        gdb_pid = 0;
    }

    inline bool valid()
    {
        return gdb_pid != 0;
    }

    inline bool bad()
    {
        return gdb_pid == 0;
    }

    inline void sigint()
    {
        kill(gdb_pid, SIGINT);
    }

private:
    FILE *gdb_in = nullptr;
    FILE *gdb_out = nullptr;
    pid_t gdb_pid = 0;
};

gdb_interface gdb_stream;

bool gdb::initialize()
{
    if (!gdb_stream.initialize())
        return false;

    std::print("attempting to connect to gdbstub, this may take awhile...");
    std::fflush(stdout);

    auto initial_message = gdb_stream.out();
    auto target_remote_result = gdb_stream.in_out("target remote localhost:1234");
    auto countinue_result = gdb_stream.in_out("c");

    auto entry = mi_entry::construct(target_remote_result);
    for (const auto & x : entry.children) {
        if (x.content == "thread-created")
            processor_count++;
    }

    out::clear();

    if (target_remote_result.contains("Connection timed out.") || countinue_result.contains("not being run")) {
        gdb::detach();
        return false;
    }

    return true;
}

void gdb::detach()
{
    gdb_stream.in("q");
    gdb_stream.close_pipes();
}

std::expected<uintptr_t, std::string> gdb::breakpoint()
{
    if (gdb_stream.bad())
        return std::unexpected("feature not available");

    if (!signal_raised)
        gdb_stream.sigint();
    else
        signal_raised = false;

    if (in_breakpoint) {
        gdb_stream.out(); // discard
        return std::unexpected("breakpoint already established");
    }

    // apparently when user does CTRL+C, we don't have to send anything
    auto output = mi_entry::construct(gdb_stream.out());
    uintptr_t addr = 0;

    in_breakpoint = true;

    try {
        auto gdb_result = output["stopped"]["frame"]["addr"].content;
        std::sscanf(gdb_result.c_str(), "%lx", &addr);
        return addr;
    }
    catch (...) {
        return std::unexpected("failed to parse gdb output");
    }
}

bool gdb::resume()
{
    auto res = in_breakpoint;
    if (in_breakpoint) {
        gdb_stream.in_out("c");
        in_breakpoint = false;
    }

    return res;
}

std::expected<std::map<std::string, uintptr_t>, std::string> gdb::get_registers()
{
    if (!in_breakpoint)
        return std::unexpected("breakpoint needed to view registers");

    constexpr auto extract_value_from_line = [](const mi_entry &entry) {
        char throwaway[12];
        uintptr_t address;

        std::sscanf(entry.content.c_str(), "%s %lx", throwaway, &address);

        return address;
    };

    auto output = mi_entry::construct(gdb_stream.in_out("info registers"));

    std::map<std::string, uintptr_t> result;
    result["rax"] = extract_value_from_line(output("rax"));
    result["rcx"] = extract_value_from_line(output("rcx"));
    result["rdx"] = extract_value_from_line(output("rdx"));
    result["rbx"] = extract_value_from_line(output("rbx"));
    result["rsp"] = extract_value_from_line(output("rsp"));
    result["rbp"] = extract_value_from_line(output("rbp"));
    result["rsi"] = extract_value_from_line(output("rsi"));
    result["rdi"] = extract_value_from_line(output("rdi"));
    result["r8"] = extract_value_from_line(output("r8"));
    result["r9"] = extract_value_from_line(output("r9"));
    result["r10"] = extract_value_from_line(output("r10"));
    result["r11"] = extract_value_from_line(output("r11"));
    result["r12"] = extract_value_from_line(output("r12"));
    result["r13"] = extract_value_from_line(output("r13"));
    result["r14"] = extract_value_from_line(output("r14"));
    result["r15"] = extract_value_from_line(output("r15"));
    result["rip"] = extract_value_from_line(output("rip"));
    result["eflags"] = extract_value_from_line(output("eflags"));
    result["cs"] = extract_value_from_line(output("cs"));
    result["ss"] = extract_value_from_line(output("ss"));
    result["ds"] = extract_value_from_line(output("ds"));
    result["es"] = extract_value_from_line(output("es"));
    result["fs"] = extract_value_from_line(output("fs"));
    result["gs"] = extract_value_from_line(output("gs"));
    result["cr0"] = extract_value_from_line(output("cr0"));
    result["cr2"] = extract_value_from_line(output("cr2"));
    result["cr3"] = extract_value_from_line(output("cr3"));
    result["cr4"] = extract_value_from_line(output("cr4"));
    result["cr8"] = extract_value_from_line(output("cr8"));
    result["efer"] = extract_value_from_line(output("efer"));
    
    // to-do: xmm registers

    return result;
}

int gdb::get_num_threads()
{
    return processor_count;
}

std::expected<int, std::string> gdb::get_current_thread()
{
    if (!in_breakpoint)
        return std::unexpected("breakpoint needed to get current thread");

    auto entry = mi_entry::construct(gdb_stream.in_out("thread"));

    for (const auto & x : entry.children) {
        if (x.content.contains("Current")) {
            int result = -1;
            std::sscanf(x.content.c_str(), "[Current thread is %d", &result);
            return result - 1;
        }
    }

    return std::unexpected("failed to parse gdb output");
}

std::expected<bool, std::string> gdb::set_current_thread(int index)
{
    if (!in_breakpoint)
        return std::unexpected("breakpoint needed to set current thread");

    if (index >= processor_count || index < 0)
        return false;

    gdb_stream.in_out(std::format("thread {}", index + 1));
    return true;
}

void gdb::set_signal_raised()
{
    signal_raised = true;
}