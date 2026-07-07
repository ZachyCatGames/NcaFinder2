#pragma once
#include <cstdio>
#include <thread>

#include <windows.h>

class MultiLogger {
public:
    MultiLogger(FILE* file1, FILE* file2);

    ~MultiLogger();

    FILE* GetFile() const noexcept { return m_file; }
private:
    void Worker();
private:
    std::thread m_worker;

    FILE* m_file;

    HANDLE m_file1, m_file2;
    HANDLE m_readHandle, m_writeHandle;
}; // class MultiLogger

