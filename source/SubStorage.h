#pragma once
#include <memory>
#include "Common.h"
#include "IStorage.h"

//#define SUBSTORAGE_DEBUG

class SubStorage : public IStorage {
public:
    constexpr SubStorage() : m_pBase(nullptr), m_start(0), m_end(0) {}

    SubStorage(IStorage* pBase, u64 start, u64 size) :
        m_pSharedBase(nullptr),
        m_pBase(pBase),
        m_start(start),
        m_end(start + size)
    {
#ifdef SUBSTORAGE_DEBUG
        size_t baseSize;
        m_pBase->GetSize(&baseSize);

        std::printf("SubStorage: Begin:     %lx\n", m_start);
        std::printf("SubStorage: End:       %lx\n", m_end);
        std::printf("SubStorage: Size:      %lx\n", size);
        std::printf("SubStorage: Base Size: %lx\n", baseSize);
#endif // SUBSTORAGE_DEBUG
    }

    SubStorage(std::shared_ptr<IStorage> base, u64 start, u64 size) :
        m_pSharedBase(std::move(base)),
        m_pBase(m_pSharedBase.get()),
        m_start(start),
        m_end(start + size)
    {
#ifdef SUBSTORAGE_DEBUG
        size_t baseSize;
        m_pBase->GetSize(&baseSize);

        std::printf("SubStorage: Begin:     %lx\n", m_start);
        std::printf("SubStorage: End:       %lx\n", m_end);
        std::printf("SubStorage: Size:      %lx\n", size);
        std::printf("SubStorage: Base Size: %lx\n", baseSize);
#endif // SUBSTORAGE_DEBUG
    }
    
    ~SubStorage() override = default;

    ErrorCode Read(void* pDst, size_t offset, size_t size) override;
    ErrorCode Write(const void* pSrc, size_t offset, size_t size) override;

    ErrorCode GetSize(size_t* size) override;
private:
    std::shared_ptr<IStorage> m_pSharedBase;
    IStorage* m_pBase;
    u64 m_start, m_end;
}; // class SubStorage
