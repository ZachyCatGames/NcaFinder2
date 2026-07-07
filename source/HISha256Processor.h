#pragma once
#include <cstddef>
#include <memory>
#include <list>
#include <vector>
#include "BlockRecoverer.h"
#include "IDecryptor.h"
#include "IStorage.h"
#include "ISectionProcessor.h"
#include "NcaHeaders.h"
#include "NcaProcessor.h"
#include "Sha256.h"
#include "SubDecryptor.h"
#include "SubStorage.h"
#include "Extents.h"

class NcaProcessor;

class HISha256Processor : public ISectionProcessor {
public:
    using SectionInfoReader = NcaProcessor::SectionInfoReader;
    HISha256Processor(NcaProcessor* pParent, SectionInfoReader infoReader, std::shared_ptr<IStorage> pInputStorage, std::shared_ptr<IStorage> pRawStorage, std::shared_ptr<IStorage> pDecStorage, std::unique_ptr<IDecryptor>&& pSecBlockDec, FILE* logFile);

    bool Process(RecoveredList* pRecoveredList, u64 recoveryStartOffset) override;
private:
    using H256Data = FsHeader::HierarchicalSha256Data;
    class HashDataReader {
    public:
        constexpr HashDataReader(const H256Data* pData) : m_pData(pData) {}

        constexpr u32 BlockSize() const noexcept { return m_pData->blockSize; }

        constexpr const Sha256::Hash& MasterHash() const noexcept { return m_pData->masterHash; } 

        constexpr const H256Data::LayerRegion& operator[](size_t i) const noexcept {
            assert(i < 2);
            return m_pData->region[i];
        }

        void Validate() const;
    private:
        const H256Data* m_pData;
    }; // class HashDataReader

    std::list<Extents<u64>> ScanForCorruptDataBlocks(const std::vector<Sha256::Hash>& hashes);

    void FillRecoveredFromCorrupt(const std::list<Extents<u64>>& corrupt, u64 layerStart, u64 layerSize);
private:
    friend class NcaProcessor;
    NcaProcessor* m_pParent;

    SectionInfoReader m_sectInfo;
    HashDataReader m_hashData;

    std::shared_ptr<IStorage> m_pDecStorage;
    std::shared_ptr<IStorage> m_pRawStorage;
    std::shared_ptr<IStorage> m_pImageStorage;

    std::unique_ptr<IDecryptor> m_pDecryptor;

    RecoveredList m_recovered;

    // these are raw storages
    SubStorage m_hashRawStorage;
    SubStorage m_dataRawStorage;
    SubStorage m_hashDecStorage;
    SubStorage m_dataDecStorage;

    SubDecryptor m_hashDecryptor;
    SubDecryptor m_dataDecryptor;

    size_t m_imageStorageSize;
    size_t m_sectionSize;

    size_t m_blockSize;

    FILE* m_logFile;
}; // class HISha256Processor