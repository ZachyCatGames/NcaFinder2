#include "ErrorCode.h"
#include <utility>

namespace {

constexpr const char* g_ErrorCodeStrings[] = {
    "Success",
    "IOstreamFailure",
    "OutOfBounds"
};

} // namespace

const char* ErrorCodeToString(ErrorCode code) {
    return g_ErrorCodeStrings[std::to_underlying(code)];
}
