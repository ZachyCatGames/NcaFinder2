#pragma once
#include <mbedtls/sha256.h>

class Sha256 {
public:
    struct Hash {
        static constexpr size_t Size = 0x20;
        std::byte hash[0x20];
    }; // struct Has

    Sha256() { mbedtls_sha256_init(&m_ctx); }
    ~Sha256() { mbedtls_sha256_free(&m_ctx); }

    void Start() { mbedtls_sha256_starts(&m_ctx, false); }

    void Update(const void* data, size_t dataSize) {
        mbedtls_sha256_update(&m_ctx, static_cast<const unsigned char*>(data), dataSize);
    }

    void Finish(void* dst) { mbedtls_sha256_finish(&m_ctx, static_cast<unsigned char*>(dst)); }

    void ComputeOneShot(void* dst, const void* src, size_t size) {
        this->Start();
        this->Update(src, size);
        this->Finish(dst);
    }
private:
    mbedtls_sha256_context m_ctx;
}; // class Sha256

inline void ComputeSha256Sum(void* hashOut, const void* data, size_t size) {
    Sha256 sha;
    sha.Start();
    sha.Update(data, size);
    sha.Finish(hashOut);
}
