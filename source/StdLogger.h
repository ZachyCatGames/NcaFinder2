#pragma once
#include "Logger.h"
#include <cstddef>
#include <cstdio>
#include <memory>

class StdLogger : public Logger {
public:
    constexpr StdLogger() : m_dest(nullptr), m_closeOnDestroy(false) {}
    explicit constexpr StdLogger(std::nullptr_t) : m_dest(nullptr), m_closeOnDestroy(false) {}

    constexpr StdLogger(FILE* file, bool closeOnDestroy = false) : m_dest(file), m_closeOnDestroy(closeOnDestroy) {}
    StdLogger(std::string_view path, bool append = false);

    void putc(char ch) override;
    void puts(std::string_view str) override; 

    bool IsValid() const noexcept { return m_dest != nullptr; }
private:
    FILE* m_dest;
    bool m_closeOnDestroy;
};

inline auto StdoutLogger = std::make_shared<StdLogger>(stdout);
inline auto StderrLogger = std::make_shared<StdLogger>(stderr);
