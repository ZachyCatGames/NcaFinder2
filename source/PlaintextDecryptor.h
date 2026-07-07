#pragma once
#include "IDecryptor.h"

class PlaintextDecryptor : public IDecryptor {
public:
    void Decrypt(void* dst, const void* src, size_t offset, size_t size) override;
};
