#include "AesCtrStorage.h"
#include "Aes.h"
#include "ErrorCode.h"
#include "NcaHeaders.h"
#include <cassert>
#include <cstring>
#include <vector>

AesCtrStorage::AesCtrStorage(const std::shared_ptr<IStorage>& base, const void* key, size_t keySize, const void* ctr, size_t ctrSize) :
    m_base(base)
{
    assert(keySize == sizeof(m_key));
    assert(ctrSize == sizeof(m_ctr));

    std::memcpy(m_key, key, sizeof(m_key));
    std::memcpy(m_ctr, ctr, sizeof(m_ctr));

    //PrintKey("key", key, 0x10);
    //PrintKey("ctr", ctr, 0x10);
}

ErrorCode AesCtrStorage::Read(void* pDst, size_t offset, size_t size) {
    /* Read from base storage. */
    ErrorCode result = m_base->Read(pDst, offset, size);
    if (result != ErrorCode::Success)
        return result;

    /* Increment our counter by offset. */
    uint8_t updatedCounter[0x10];
    IncrementCounter(updatedCounter, m_ctr, offset / 0x10);

    //PrintKey("Updated CTR", updatedCounter, 0x10);

    /* Decrypt read-in data. */
    AesCtr dec(m_key, sizeof(m_key), updatedCounter, sizeof(updatedCounter));
    dec.Decrypt(pDst, pDst, size);

    return ErrorCode::Success;
}

ErrorCode AesCtrStorage::Write(const void* pSrc, size_t offset, size_t size) {
    /* Increment our counter by offset. */
    uint8_t updatedCounter[0x10];
    IncrementCounter(updatedCounter, m_ctr, offset / 0x10);

    /* Encrypt source data. */
    std::vector<std::byte> tmp(size);
    AesCtr enc(m_key, sizeof(m_key), updatedCounter, sizeof(updatedCounter));
    enc.Encrypt(tmp.data(), pSrc, size);

    /* Write the encrypted data. */
    return m_base->Write(tmp.data(), offset, size);
}

ErrorCode AesCtrStorage::GetSize(size_t* size) { return m_base->GetSize(size); }
