#include "MultiLogger.h"
#include "Common.h"
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>
#include <print>

MultiLogger::MultiLogger(FILE* file1, FILE* file2) {
    int p[2];
    if (pipe(p) < 0) {
        throw DumperException("Failed to create pipe: {}\n", strerror(errno));

    }
    m_rPipe = p[0];
    m_wPipe = p[1];

    m_fd1 = fileno(file1);
    m_fd2 = fileno(file2);

    m_file = fdopen(m_wPipe, "wb");
    if (m_file == nullptr) {
        throw DumperException("Failed to open pipe file: {}\n", strerror(errno));
    }

    /* Switch to line buffering. */
    std::setvbuf(m_file, nullptr, _IOLBF, BUFSIZ);
    
    int flags = fcntl(p[0], F_GETFL);
    fcntl(p[0], F_SETFL, flags | O_NONBLOCK);

    m_worker = std::thread(&MultiLogger::Worker, this);
}

MultiLogger::~MultiLogger() {
    fclose(m_file);
    close(m_wPipe);

    m_worker.join();

    close(m_rPipe);
}

void MultiLogger::Worker() {
    struct pollfd pfd = {
        m_rPipe, POLLIN | POLLHUP, 0
    };

    unsigned char buf[0x1000];
    while (true) {
        int r = poll(&pfd, 1, -1);

        int rd;
        while ((rd = read(m_rPipe, buf, 0x1000)) > 0) {
            if (rd < 0) {
                std::print(stderr, "MultiLogger: Failed to read from pipe: {}\n", strerror(errno));
                std::exit(-1); // TODO?
            }

            write(m_fd1, buf, rd);
            write(m_fd2, buf, rd);
        }

        if (pfd.revents & POLLHUP) {
            return;
        }
    }

}
