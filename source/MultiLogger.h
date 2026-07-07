#pragma once

#if defined(__unix__) || defined(unix) || (defined(__APPLE__) && defined(__MACH__))
#include "MultiLogger.posix.h"
#elif defined(_WIN32)
#include "MultiLogger.win32.h"
#else
#error "Unsupported OS"
#endif
