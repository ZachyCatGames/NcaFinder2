#include "StdLogger.h"

StdLogger::StdLogger(std::string_view path, bool append) {
    if (append)
        m_dest = std::fopen(path.data(), "a");
    else
        m_dest = std::fopen(path.data(), "w");

}

void StdLogger::putc(char ch) {
    std::fputc(ch, m_dest);
}

void StdLogger::puts(std::string_view str) {
    std::fputs(str.data(), m_dest);
}
