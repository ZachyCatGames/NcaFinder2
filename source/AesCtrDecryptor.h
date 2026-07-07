#pragma once
#include "Common.h"
#include "IDecryptor.h"
#include "Aes.h"

class AesCtrDecryptor : public IDecryptor {
public:
    NON_COPYABLE(AesCtrDecryptor);
    NON_MOVEABLE(AesCtrDecryptor);
    
    AesCtrDecryptor(const void* key, size_t keySize, const void* ctr, size_t ctrSize);

    void Decrypt(void* dst, const void* src, size_t offset, size_t size) override;
private:
    AesCtr m_dec;
    std::byte m_ctr[0x10];
}; // class AesCtrDecryptor
