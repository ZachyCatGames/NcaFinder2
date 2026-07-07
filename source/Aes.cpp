#include "Aes.h"
#include "mbedtls/cipher.h"
#include <algorithm>
#include <cstring>
#include <print>

namespace {

void SetupTweak(uint8_t* out, uint64_t sector) {
    uint64_t tweak[2];
    tweak[0] = 0;
    tweak[1] = __builtin_bswap64(sector);
    std::memcpy(out, tweak, sizeof(tweak));
}

unsigned char* GetDestination(void* dest, const void* src, u64 size) {
    unsigned char* d;
    if (src == dest) {
        d = new unsigned char[size + 0x10];
    } else {
        d = static_cast<unsigned char*>(dest);
    }
    return d;
}

void Cleanup(void* dest, const void* src, u64 size, unsigned char* d) {
    if (dest == src) {
        std::memcpy(dest, d, size);
        delete[] d;
    }
}

} // namespace

void IncrementCounter(void* pDst, const void* pSrc, uint64_t offset) {
    /* Copy the upper half directly. */
    std::memcpy(pDst, pSrc, 8);

    /* Increment the upper half by the offset. */
    uint64_t lowerIv;
    std::memcpy(&lowerIv, static_cast<const std::byte*>(pSrc) + 8, sizeof(lowerIv));
    lowerIv = __builtin_bswap64(lowerIv);
    lowerIv += offset;
    lowerIv = __builtin_bswap64(lowerIv);
    std::memcpy(static_cast<std::byte*>(pDst) + 8, &lowerIv, sizeof(lowerIv));
}

NintendoAesXtsDecryptor::NintendoAesXtsDecryptor(const void* key, size_t key_size, size_t sector_size) : m_sector_size(sector_size), m_current_sector(0) {
    mbedtls_cipher_init(&m_ctx);
    mbedtls_cipher_setup(&m_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_XTS));
    mbedtls_cipher_setkey(&m_ctx, static_cast<const unsigned char*>(key), key_size * 8, MBEDTLS_DECRYPT);
}

void NintendoAesXtsDecryptor::Decrypt(void* dest, const void* src, size_t src_size) {
    size_t dest_size;
    uint8_t tweak[0x10];
    unsigned char* d = GetDestination(dest, src, src_size);

    for (size_t i = 0; i < src_size; i += m_sector_size) {
        size_t count = std::min(src_size - i, m_sector_size);
        SetupTweak(tweak, m_current_sector++);
        mbedtls_cipher_set_iv(&m_ctx, tweak, sizeof(tweak));
        mbedtls_cipher_update(&m_ctx, static_cast<const unsigned char*>(src) + i, count, d + i, &dest_size);
    }

    Cleanup(dest, src, src_size, d);
}

AesCtr::AesCtr(const void* key, size_t keySize, const void* ctr, size_t ctrSize) {
    mbedtls_cipher_init(&m_ctx);
    mbedtls_cipher_setup(&m_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR));
    mbedtls_cipher_setkey(&m_ctx, static_cast<const unsigned char*>(key), keySize * 8, MBEDTLS_DECRYPT);
    mbedtls_cipher_set_iv(&m_ctx, static_cast<const unsigned char*>(ctr), ctrSize);
}

void AesCtr::Decrypt(void* dest, const void* src, size_t size) {
    size_t outSize;
    unsigned char* d = GetDestination(dest, src, size);
    
    int res = mbedtls_cipher_update(&m_ctx, static_cast<const unsigned char*>(src), size, d, &outSize);
    if (res != 0) {
        std::print(stderr, "[AES-CTR] Failed to decrypt {}\n", res);
    }

    Cleanup(dest, src, size, d);
}

void AesCtr::SetCounter(const void* ctr, size_t ctrSize) {
    mbedtls_cipher_set_iv(&m_ctx, static_cast<const unsigned char*>(ctr), ctrSize);
}

void AesEcbDecryptor::Decrypt(void* dest, const void* src, size_t size) {
    size_t outSize;
    unsigned char* d = GetDestination(dest, src, size);
    
    mbedtls_cipher_update(&m_ctx, static_cast<const unsigned char*>(src), size, d, &outSize);

    Cleanup(dest, src, size, d);
}

