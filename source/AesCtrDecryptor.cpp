#include "AesCtrDecryptor.h"
#include "Aes.h"
#include <cassert>
#include <cstring>

AesCtrDecryptor::AesCtrDecryptor(const void* key, size_t keySize, const void* ctr, size_t ctrSize) :
    m_dec(key, keySize, ctr, ctrSize)
{
    assert(keySize == 0x10);
    assert(ctrSize == 0x10);

    std::memcpy(m_ctr, ctr, sizeof(m_ctr));
}

void AesCtrDecryptor::Decrypt(void *dst, const void *src, size_t offset, size_t size) {
    std::byte newCtr[0x10];

    IncrementCounter(newCtr, m_ctr, offset / 0x10);
    m_dec.SetCounter(newCtr, sizeof(newCtr));

    m_dec.Decrypt(dst, src, size);
}
