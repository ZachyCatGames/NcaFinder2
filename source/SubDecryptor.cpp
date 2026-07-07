#include "SubDecryptor.h"

void SubDecryptor::Decrypt(void* dst, const void* src, size_t offset, size_t size) {
    m_pBase->Decrypt(dst, src, offset + m_baseOffset, size);
}
