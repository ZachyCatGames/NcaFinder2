#pragma once
#include <fstream>
#include <memory>
#include "Common.h"
#include "IStorage.h"

class FileStorage : public IStorage {
public:
    NON_COPYABLE(FileStorage);
    NON_MOVEABLE(FileStorage);

    FileStorage(FILE* file) : m_file(file) {}
    ~FileStorage() override = default;

    ErrorCode Read(void* pDst, size_t offset, size_t size) override;
    ErrorCode Write(const void* pSrc, size_t offset, size_t size) override;

    ErrorCode GetSize(size_t* size) override;
private:
    FILE* m_file;
}; // class FileStorage

