#pragma once

#include "mem.hpp"

namespace host {
    bool initialize();
    ssize_t read_kvm_memory(void *local_address, uint64_t remote_address, size_t length);
    ssize_t write_kvm_memory(void *local_address, uint64_t remote_address, size_t length);

    int get_kvm_pid();

    template <typename T>
    T read_kvm_memory(uint64_t remote_address)
    {
        T result;
        for (
            ssize_t remaining = 0; 
            remaining < sizeof(T); 
            remaining += read_kvm_memory((char*)&result + remaining, remote_address + remaining, sizeof(T) - remaining)
        ) {
            // ...
        }

        return result;
    }

    template <typename T>
    void write_kvm_memory(uint64_t remote_address, T data)
    {
        for (
            ssize_t remaining = 0; 
            remaining < sizeof(T); 
            remaining += write_kvm_memory((char*)&data + remaining, remote_address + remaining, sizeof(T) - remaining)
        ) {
            // ...
        }
    }

    mem::process get_ntoskrnl();
}