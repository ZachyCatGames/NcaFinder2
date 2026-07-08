#pragma once
#include <format>

class Logger {
public:
    virtual ~Logger() = default;

    virtual void putc(char ch) = 0;
    virtual void puts(std::string_view str) = 0;

    template<typename... Ts>
    void print(std::format_string<Ts...> fmt, Ts&&... args) {
        std::string str = std::format(fmt, std::forward<Ts>(args)...);
        this->puts(str);
    }
}; // class Logger
