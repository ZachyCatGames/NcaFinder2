#include "SubStorage.h"
#include <cassert>
#include "ErrorCode.h"


ErrorCode SubStorage::Read(void* pDst, size_t offset, size_t size) {
    size_t newOffset = offset + m_start;

#ifdef SUBSTORAGE_DEBUG
    std::printf("SubStorage::Read: Reading 0x%lx bytes at offset 0x%lx (0x%lx base)\n", size, offset, newOffset);
#endif // SUBSTORAGE_DEBUG

    /* Make sure the access is within bounds. */
    if (newOffset + size > m_end)
        return ErrorCode::OutOfBounds;

    /* Read from the base storage. */
    return m_pBase->Read(pDst, newOffset, size);
}

ErrorCode SubStorage::Write(const void* pSrc, size_t offset, size_t size) {
    size_t newOffset = offset + m_start;

#ifdef SUBSTORAGE_DEBUG
    std::printf("SubStorage::Read: Writing 0x%lx bytes at offset 0x%lx (0x%lx base)\n", size, offset, newOffset);
#endif // SUBSTORAGE_DEBUG

    /* Make sure the access is within bounds. */
    if (newOffset + size > m_end)
        return ErrorCode::OutOfBounds;

    /* Write the base storage. */
    return m_pBase->Write(pSrc, newOffset, size);
}

ErrorCode SubStorage::GetSize(size_t* size) {
    *size = m_end - m_start;
    return ErrorCode::Success;
}
