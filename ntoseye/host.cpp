#include "host.hpp"
#include "util.hpp"
#include "log.hpp"

#include <cstdint>
#include <filesystem>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>

#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/uio.h>

#define KFIXV 0x80000000
#define KFIX(x) ((x) < KFIXV ? (x) : ((x) - KFIXV))

struct memory_region {
    uintptr_t start;
    uintptr_t end;
    size_t length;
};

static int pid = 0;
static memory_region largest_region;

static int get_kvm_pid()
{
    int result = 0;

    std::ranges::all_of(std::filesystem::directory_iterator("/proc"),
        [&](const auto& dir_entry) -> bool {
            if (!dir_entry.is_directory())
                return true;

            try {
                std::ranges::all_of(std::filesystem::directory_iterator(dir_entry.path().string() + "/fd"),
                    [&](const auto& dir_entry) -> bool {
                        if (dir_entry.is_symlink() && std::filesystem::read_symlink(dir_entry) == "/dev/kvm") {
                            std::sscanf(dir_entry.path().c_str(), "/proc/%d/", &result);
                            return false;
                        }
                        
                        return true;
                    }
                );
            }
            catch (...) {
                // dont care
            }

            return result == 0;
        }
    );

    return result;
}

int host::get_kvm_pid()
{
    return pid ? pid : ::get_kvm_pid();
}

static std::vector<memory_region> get_kvm_memory_regions(int pid)
{
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::vector<memory_region> regions;

    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t start, end;
        std::sscanf(line.c_str(), "%lx-%lx", &start, &end);

        regions.push_back({ start, end, end - start });
    }

    return regions;
}

bool host::initialize()
{
    pid = get_kvm_pid();
    if (!pid) {
        out::error("failed to find kvm\n");
        return false;
    }

    auto regions = get_kvm_memory_regions(pid);
    if (regions.empty()) {
        out::error("failed to get memory regions\n");
        return false;
    }

    largest_region = *std::max_element(regions.begin(), regions.end(),
            [](const auto& a, const auto& b) { return a.length < b.length; });

    return true;
}

ssize_t host::read_kvm_memory(void *local_address, uint64_t remote_address, size_t length)
{
    struct iovec local;
    struct iovec remote;
    local.iov_base = local_address;
    local.iov_len = length;
    remote.iov_base = (void*)((char*)largest_region.start + KFIX(remote_address));
    remote.iov_len = length;
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

ssize_t host::write_kvm_memory(void *local_address, uint64_t remote_address, size_t length)
{
    struct iovec local;
    struct iovec remote;
    local.iov_base = local_address;
    local.iov_len = length;
    remote.iov_base = (void*)((char*)largest_region.start + KFIX(remote_address));
    remote.iov_len = length;
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}