#include "ProgressBar.h"
#include <cassert>
#include <cinttypes>
#include <cstdio>
#include <string>

#if defined(__unix__) || defined(unix) || (defined(__APPLE__) && defined(__MACH__))

#include <asm/termbits.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

int GetColumns() {
    winsize ws;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    return ws.ws_col;
}

} // namespace

#elif defined(_WIN32)

#include <windows.h>

namespace {

// windows shoutouts.
// untested
int GetColumns() {
    /* Enable windows virtual terminal output. */
    /* We _might_ want to move this elsewhere, it's a bit awkward here but is also the most convenient spot atm. */
    static virtInputEnabled = false;
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!virtInputEnabled) {
        virtInputEnabled = true;

        /* Get the current mode. */
        DWORD mode;
        if (!GetConsoleMode(stdoutHandle, &mode))
            return -1;

        /* Add virtual terminal mode. */
        if (!SetConsoleMode(stdoutHandle, mode | ENABLE_VIRTUAL_TERMINAL_INPUT))
            return -1;
    }

    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(stdoutHandle, &info))
        return -1;

    return info.srWindow.Right - info.srWindow.left + 1;
}

} // namespace

#else
#error "Unsupported OS"
#endif

// ANSI control code reference:
// https://gist.github.com/ConnerWill/d4b6c776b509add763e17f9f113fd25b
void PrintProgressBar(double progress) {
    assert(progress <= 1.0);

    /* Get column count. */
    int cols = GetColumns();
    if (cols <= 3)
        return;
    int units = cols - 2;

    //std::printf("%d; %f\n", cols, progress);
    std::fflush(stdout);
    ClearProgressBar();


    int unitProgress = units * progress;
    std::printf("[");
    for (int i = 0; i < unitProgress; i++) {
        std::printf("#");
    }
    for (int i = 0; i < units - unitProgress; i++) {
        std::printf(" ");
    }
    std::printf("]");
    std::fflush(stdout);

}

void ClearProgressBar() {
    /* Clear the current line. */
    std::printf("\e[2K\e[0G");
    std::fflush(stdout);
}
