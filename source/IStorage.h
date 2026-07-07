#pragma once
#include <cstddef>
#include "ErrorCode.h"

class IStorage {
public:
    virtual ~IStorage() = default;

    virtual ErrorCode Read(void* pDst, size_t offset, size_t size) = 0;
    virtual ErrorCode Write(const void* pSrc, size_t offset, size_t size) = 0;

    virtual ErrorCode GetSize(size_t* size) = 0;
}; // class IStorage
