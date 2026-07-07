#pragma once
#include <mbedtls/cipher.h>
#include <cstddef>
#include "Common.h"

void IncrementCounter(void* pDst, const void* pSrc, uint64_t offset);

class NintendoAesXtsDecryptor {
public:
    NintendoAesXtsDecryptor(const void* key, size_t key_size, size_t sector_size);
    ~NintendoAesXtsDecryptor() {
        mbedtls_cipher_free(&m_ctx);
    }

    void Decrypt(void* dest, const void* src, size_t src_size);

    void Decrypt(void* dest, const void* src, size_t src_size, size_t start_sector) {
        m_current_sector = start_sector;
        this->Decrypt(dest, src, src_size);
    }

    void SetCurrentSector(size_t sect) noexcept { m_current_sector = sect; }
    size_t GetCurrentSector() const noexcept { return m_current_sector; }

    size_t GetSectorSize() const noexcept { return m_sector_size; }
private:
    mbedtls_cipher_context_t m_ctx;
    uint64_t m_current_sector, m_sector_size;
}; // class NintendoAesXtsEncryptor

class AesCtr {
public:
    AesCtr(const void* key, size_t keySize, const void* ctr, size_t ctrSize);
    ~AesCtr() {
        mbedtls_cipher_free(&m_ctx);
    }

    void Decrypt(void* dest, const void* src, size_t size);

    void Encrypt(void* dest, const void* src, size_t size) {
        this->Decrypt(dest, src, size);
    }

    void SetCounter(const void* ctr, size_t ctrSize);
private:
    mbedtls_cipher_context_t m_ctx;
}; // class AesCtr

class AesEcbDecryptor {
public:
    AesEcbDecryptor(const void* key, size_t keySize) {
        mbedtls_cipher_init(&m_ctx);
        mbedtls_cipher_setup(&m_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));
        mbedtls_cipher_setkey(&m_ctx, static_cast<const unsigned char*>(key), keySize * 8, MBEDTLS_DECRYPT);
    }

    ~AesEcbDecryptor() {
        mbedtls_cipher_free(&m_ctx);
    }

    void Decrypt(void* dest, const void* src, size_t size);
private:
    mbedtls_cipher_context_t m_ctx;
}; // class AesEcbDecryptor
