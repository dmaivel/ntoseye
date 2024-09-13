#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <map>

namespace gdb {
    struct eflags {
        uint32_t CF : 1;   // Carry Flag
        uint32_t : 1;      // Reserved
        uint32_t PF : 1;   // Parity Flag
        uint32_t : 1;      // Reserved
        uint32_t AF : 1;   // Auxiliary Carry Flag
        uint32_t : 1;      // Reserved
        uint32_t ZF : 1;   // Zero Flag
        uint32_t SF : 1;   // Sign Flag
        uint32_t TF : 1;   // Trap Flag
        uint32_t IF : 1;   // Interrupt Enable Flag
        uint32_t DF : 1;   // Direction Flag
        uint32_t OF : 1;   // Overflow Flag
        uint32_t IOPL : 2; // I/O Privilege Level (2 bits)
        uint32_t NT : 1;   // Nested Task Flag
        uint32_t : 1;      // Reserved
        uint32_t RF : 1;   // Resume Flag
        uint32_t VM : 1;   // Virtual 8086 Mode
        uint32_t AC : 1;   // Alignment Check
        uint32_t VIF : 1;  // Virtual Interrupt Flag
        uint32_t VIP : 1;  // Virtual Interrupt Pending
        uint32_t ID : 1;   // ID Flag (Can check CPUID support)
        uint32_t : 10;     // Reserved
    };

    bool initialize();
    void detach();

    std::expected<uintptr_t, std::string> breakpoint();
    bool resume();

    int get_num_threads();
    std::expected<int, std::string> get_current_thread();
    std::expected<bool, std::string> set_current_thread(int index);

    std::expected<std::map<std::string, uintptr_t>, std::string> get_registers();

    void set_signal_raised();
}