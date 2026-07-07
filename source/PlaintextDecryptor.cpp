#include "PlaintextDecryptor.h"
#include <cstring>

void PlaintextDecryptor::Decrypt(void* dst, const void* src, size_t offset, size_t size) {
    std::memcpy(dst, src, size);
}
