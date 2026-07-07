#pragma once
#include "ISectionBlockDecryptor.h"
#include "IvfcProcessor.h"
#include <memory>

class SubSectionBlockDecryptor : public ISectionBlockDecryptor {
public:
    SubSectionBlockDecryptor(std::shared_ptr<ISectionBlockDecryptor> base, size_t start, size_t size) :
        m_base(std::move(base)),
        m_start(start),
        m_end(start + size) {}
    
    void DecryptBlock(void* dst, const void* src, size_t blockIdx, size_t size); 
private:
    std::shared_ptr<ISectionBlockDecryptor> m_base;
    size_t m_start, m_end;
}; // class SubSectionBlockDecryptor
