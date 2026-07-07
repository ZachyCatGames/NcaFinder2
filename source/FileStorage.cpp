#include "FileStorage.h"
#include "ErrorCode.h"
#include <cstdio>

ErrorCode FileStorage::Read(void* pDst, size_t offset, size_t size) {
    /* Seek to offset then read from our base stream. */
    std::fseek(m_file, offset, SEEK_SET);
    if (std::fread(pDst, 1, size, m_file) < 0)
        return ErrorCode::IOstreamFailure;

    return ErrorCode::Success;
}

ErrorCode FileStorage::Write(const void* pSrc, size_t offset, size_t size) {
    /* Seek to offset then write to our base stream. */
    std::fseek(m_file, offset, SEEK_SET);
    if (std::fwrite(pSrc, 1, size, m_file) < 0)
        return ErrorCode::IOstreamFailure;
    
    return ErrorCode::Success;
}

ErrorCode FileStorage::GetSize(size_t* size) {
    std::fseek(m_file, 0, SEEK_END);
    *size = static_cast<size_t>(std::ftell(m_file));
    return ErrorCode::Success;
}
