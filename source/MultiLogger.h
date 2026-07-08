#include "Logger.h"
#include <memory>
#include <vector>

class MultiLogger : public Logger {
public:
    void putc(char ch) override;
    void puts(std::string_view str) override; 

    bool HasLogger(Logger* pLogger) const;

    void AddLogger(Logger* pLogger);
    void AddLogger(std::unique_ptr<Logger>&& pLogger);
    void AddLogger(const std::shared_ptr<Logger>& pLogger);
private:
    std::vector<Logger*> m_loggers;
    std::vector<std::shared_ptr<Logger>> m_sharedLoggers;
    std::vector<std::unique_ptr<Logger>> m_uniqueLoggers;
}; // class MultiLogger
