#pragma once
#include <cstddef>

class IBlockVerifier {
public:
    virtual void Reset() = 0;
    virtual void Update(const void* pData, size_t dataSize) = 0;
    virtual bool Finish(const void* pHash, size_t hashSize) = 0;

    void Start(const void* pData, size_t dataSize) {
        this->Reset();
        this->Update(pData, dataSize);
    }

    bool Verify(const void* pData, size_t dataSize, const void* pHash, size_t hashSize) {
        this->Reset();
        this->Update(pData, dataSize);
        return this->Finish(pHash, hashSize);
    }
}; // class IBlockVerifier
