#include "MultiLogger.h"

void MultiLogger::putc(char c) {
    for (auto& logger : m_loggers) {
        logger->putc(c);
    }
}

void MultiLogger::puts(std::string_view s) {
    for (auto& logger : m_loggers) {
        logger->puts(s);
    }
}

bool MultiLogger::HasLogger(Logger *pLogger) const {
    return std::ranges::find(m_loggers, pLogger) != m_loggers.cend();
}

void MultiLogger::AddLogger(Logger *pLogger) {
    if (this->HasLogger(pLogger))
        return;

    m_loggers.push_back(pLogger);
}

void MultiLogger::AddLogger(std::unique_ptr<Logger> &&pLogger) {
    if (this->HasLogger(pLogger.get()))
        return;

    m_loggers.push_back(pLogger.get());
    m_uniqueLoggers.push_back(std::move(pLogger));
}

void MultiLogger::AddLogger(const std::shared_ptr<Logger> &pLogger) {
    if (this->HasLogger(pLogger.get()))
        return;

    m_loggers.push_back(pLogger.get());
    m_sharedLoggers.push_back(pLogger);
}

