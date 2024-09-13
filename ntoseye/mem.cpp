#include "mem.hpp"
#include "host.hpp"
#include "windefs.h"
#include <ctime>

#define PAGE_OFFSET_SIZE 12

// PageFrameNumber
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

uintptr_t mem::process::virtual_to_physical(uintptr_t address)
{
    auto page_offset = address & ~(~0ul << PAGE_OFFSET_SIZE);
    auto pte = ((address >> 12) & (0x1ffll));
    auto pt = ((address >> 21) & (0x1ffll));
    auto pd = ((address >> 30) & (0x1ffll));
    auto pdp = ((address >> 39) & (0x1ffll));

    auto pdpe = host::read_kvm_memory<uint64_t>(dir_base + 8 * pdp);
    if (~pdpe & 1)
        return 0;

    auto pde = host::read_kvm_memory<uint64_t>((pdpe & PMASK) + 8 * pd);
    if (~pde & 1)
        return 0;

    /* 1GB large page, use pde's 12-34 bits */
    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

    auto pte_address = host::read_kvm_memory<uint64_t>((pde & PMASK) + 8 * pt);
    if (~pte_address & 1)
        return 0;

    /* 2MB large page */
    if (pte_address & 0x80)
        return (pte_address & PMASK) + (address & ~(~0ull << 21));

    address = host::read_kvm_memory<uintptr_t>((pte_address & PMASK) + 8 * pte) & PMASK;
    if (!address)
        return 0;

    return address + page_offset;
}

void mem::process::set_dir_base(uint64_t new_dir_base)
{
    dir_base = new_dir_base;
    dir_base &= ~0xf;
}

ssize_t mem::process::read_virtual_memory(void *local_address, uint64_t remote_address, size_t length)
{
    // request is contained within a single page of memory
    if ((remote_address >> 12ull) == ((remote_address + length - 1) >> 12ull))
        return host::read_kvm_memory(local_address, virtual_to_physical(remote_address), length);

    // otherwise, we only read partial data
    size_t new_length = PAGE_SIZE - (remote_address & 0xfff);
    return host::read_kvm_memory(local_address, virtual_to_physical(remote_address), length > new_length ? new_length : length);
}

ssize_t mem::process::write_virtual_memory(void *local_address, uint64_t remote_address, size_t length)
{
    // request is contained within a single page of memory
    if ((remote_address >> 12ull) == ((remote_address + length - 1) >> 12ull))
        return host::write_kvm_memory(local_address, virtual_to_physical(remote_address), length);

    // otherwise, we only read partial data
    size_t new_length = PAGE_SIZE - (remote_address & 0xfff);
    return host::write_kvm_memory(local_address, virtual_to_physical(remote_address), length > new_length ? new_length : length);
}

bool mem::process::read_bytes(void *local_address, uint64_t remote_address, size_t length, std::source_location fun)
{
    int missed_attempts = 0;

    for (
        ssize_t remaining = 0; 
        remaining < length; 
    ) {
        auto read = read_virtual_memory((char*)local_address + remaining, remote_address + remaining, length - remaining);
        if (read == -1) {
            if (missed_attempts >= VMM_MAX_ATTEMPTS) {
                // errorf("exceeded max attempts from %s (%s) [V(%012lX) -> P(%012lX)]\n", fun.function_name(), strerror(errno), remote_address, virtual_to_physical(remote_address));
                return false;
            }

            missed_attempts++;
            
            continue;
        }

        remaining += read;
    }

    return true;
}

bool mem::process::write_bytes(void *local_address, uint64_t remote_address, size_t length, std::source_location fun)
{
    int missed_attempts = 0;

    for (
        ssize_t remaining = 0; 
        remaining < length; 
    ) {
        auto write = write_virtual_memory((char*)local_address + remaining, remote_address + remaining, length - remaining);
        if (write == -1) {
            if (missed_attempts >= VMM_MAX_ATTEMPTS) {
                // errorf("exceeded max attempts from %s (%s) [V(%012lX) -> P(%012lX)]\n", fun.function_name(), strerror(errno), remote_address, virtual_to_physical(remote_address));
                return false;
            }

            missed_attempts++;
            
            continue;
        }

        remaining += write;
    }

    return true;
}