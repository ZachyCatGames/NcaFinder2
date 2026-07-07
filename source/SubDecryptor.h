#pragma once
#include "Common.h"
#include "IDecryptor.h"
#include "mbedtls/pkcs7.h"
#include <memory>

class SubDecryptor : public IDecryptor {
public:
    constexpr SubDecryptor() : m_pBase(nullptr), m_baseOffset(0) {}

    SubDecryptor(IDecryptor* pBase, u64 baseoffset) :
        m_pBase(pBase),
        m_baseOffset(baseoffset) {}

    SubDecryptor(std::shared_ptr<IDecryptor> pBase, u64 baseOffset) :
        m_pSharedBase(std::move(pBase)),
        m_pBase(m_pSharedBase.get()),
        m_baseOffset(baseOffset) {}

    void Decrypt(void* dst, const void* src, size_t offset, size_t size) override;
private:
    std::shared_ptr<IDecryptor> m_pSharedBase;
    IDecryptor* m_pBase;
    u64 m_baseOffset;
}; // class SubDecryptor
