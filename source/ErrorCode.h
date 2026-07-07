#pragma once

enum class ErrorCode : int {
    Success = 0,

    IOstreamFailure = 1,
    OutOfBounds = 2,
}; // enum class ErrorCode

const char* ErrorCodeToString(ErrorCode code);

