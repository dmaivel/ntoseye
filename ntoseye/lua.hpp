#pragma once

#include <cinttypes>

namespace lua {
    // lua doesn't support unsigned 64-bit integers, yay
    struct uint64 {
        uint64() noexcept : value(0) { }
        uint64(uint64_t value) : value(value) { }
        uint64(uint32_t hi, uint32_t lo) : value((uint64_t(hi) << 32) | uint64_t(lo)) { }

        union {
            struct {
                uint32_t low;
                uint32_t high;
            };

            uint64_t value;
        };

        bool operator==(uint64 const& w64) const { return value == w64.value; }
        bool operator!=(uint64 const& w64) const { return value != w64.value; }
        bool operator<(uint64 const& w64) const { return value < w64.value; }
        bool operator>(uint64 const& w64) const { return value > w64.value; }
        bool operator<=(uint64 const& w64) const { return value <= w64.value; }
        bool operator>=(uint64 const& w64) const { return value >= w64.value; }
    };

    bool initialize();
}