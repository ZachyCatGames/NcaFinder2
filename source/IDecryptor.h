#pragma once
#include <cstddef>

class IDecryptor {
public:
    virtual ~IDecryptor() = default;

    /**
     * Decrypt size data from src to dst.
     *
     * offset is used as an implementation-specific decryption tweak.
     * E.g., for AES-CTR it is used to increment the base counter.
     */
    virtual void Decrypt(void* dst, const void* src, size_t offset, size_t size) = 0;
}; // class IDecryptor
