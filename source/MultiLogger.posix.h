#pragma once
#include <cstdio>
#include <thread>

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

    int m_fd1, m_fd2;
    int m_rPipe, m_wPipe;
}; // class MultiLogger
