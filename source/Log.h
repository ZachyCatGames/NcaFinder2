#pragma once
#include <print>

enum LogLevel {
    LogLevel_Info,
    LogLevel_Verbose,
};

constinit inline int g_LogLevel = LogLevel_Verbose;

#define LOG_LVL(level, fmt, ...) if (level <= g_LogLevel) std::print(fmt __VA_OPT__(,) __VA_ARGS__)
#define FLOG_LVL(file, level, fmt, ...) if (level <= g_LogLevel) std::print(file, fmt __VA_OPT__(,) __VA_ARGS__)

#define LOG(fmt, ...) LOG_LVL(LogLevel_Info, fmt, __VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) LOG_LVL(LogLevel_Verbose, fmt, __VA_ARGS__)

#define FLOG(file, fmt, ...) FLOG_LVL(file, LogLevel_Info, fmt, __VA_ARGS__)
#define FLOG_VERBOSE(file, fmt, ...) FLOG_LVL(file, LogLevel_Verbose, fmt, __VA_ARGS__)
