#pragma once
#include <memory>
#include "Aes.h"
#include "Common.h"
#include "IStorage.h"


class AesCtrStorage : public IStorage {
public:
    NON_COPYABLE(AesCtrStorage);
    NON_MOVEABLE(AesCtrStorage);

    AesCtrStorage(const std::shared_ptr<IStorage>& base, const void* key, size_t keySize, const void* ctr, size_t ctrSize);
    ~AesCtrStorage() override = default;

    ErrorCode Read(void* pDst, size_t offset, size_t size) override;
    ErrorCode Write(const void* pSrc, size_t offset, size_t size) override;

    ErrorCode GetSize(size_t* size) override;
private:
    std::shared_ptr<IStorage> m_base;
    uint8_t m_key[0x10], m_ctr[0x10];
}; // class AesCtrStorage
