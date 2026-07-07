#pragma once
#include <cstddef>
#include <format>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using s8  = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

constexpr u64 CLUSTERS_PER_READ = 0x4000;
constexpr u64 CLUSTER_SIZE = 0x4000;

#define NON_COPYABLE(cls) cls(const cls&) = delete
#define NON_MOVEABLE(cls) cls(cls&&) = delete

struct DumperException : std::exception {
    template<typename... Args>
    DumperException(std::format_string<Args...> str, Args&&... args) :
        std::exception(),
        str(std::format(str, std::forward<Args>(args)...)) {}

    const char* what() const noexcept override { return str.c_str(); }

    std::string str;
};
