#pragma once
#include <cstddef>
#include <memory>
#include "BlockRecoverer.h"
#include "IDecryptor.h"
#include "IStorage.h"
#include "ISectionProcessor.h"
#include "NcaHeaders.h"
#include "NcaProcessor.h"
#include "Sha256.h"
#include "Extents.h"
#include "SubDecryptor.h"
#include "SubStorage.h"
#include "Logger.h"

class NcaProcessor;

class IvfcSectionProcessor : public ISectionProcessor {
public:
    using SectionInfoReader = NcaProcessor::SectionInfoReader;

    IvfcSectionProcessor(NcaProcessor* pParent, SectionInfoReader sectInfo, std::shared_ptr<IStorage> pInputStorage, std::shared_ptr<IStorage> pRawStorage, std::shared_ptr<IStorage> pDecStorage, std::unique_ptr<IDecryptor>&& pSecBlockDec, const std::shared_ptr<Logger> pLogger);

    bool Process(RecoveredList* pRecoveredList, u64 recoveryStartOffset) override;
private:
    std::list<Extents<u64>> ScanForCorruptBlocks(int level, const std::vector<Sha256::Hash>& hashes, SubStorage* pDataStorage);

    std::vector<Sha256::Hash> ReadHashes(int level);

    void FillRecoveredFromCorrupt(const std::list<Extents<u64>>& corrupt, u64 sectStart, u64 sectSize);
private:
    using IvfcData = FsHeader::IntegrityMetaInfo;
    class HashDataReader {
    public:
        using LevelInfo = IvfcData::InfoLevelHash::LevelInfo;

        constexpr HashDataReader(const IvfcData* pData) noexcept : m_pData(pData) {}

        constexpr const Sha256::Hash& MasterHash() const noexcept { return m_pData->masterHash; }

        constexpr const LevelInfo& operator[](size_t i) const noexcept {
            assert(i < m_pData->infoLevelHash.levelInfo.size());
            return m_pData->infoLevelHash.levelInfo[i];
        }

        constexpr const auto& GetLeveLInfo() const noexcept { return m_pData->infoLevelHash.levelInfo; }

        void Validate() const;
    private:
        const IvfcData* m_pData;
    }; // class HashDataReader

    struct LevelInfo {
        u64 offset;
        u64 size;
        u64 blockSize;
    };

    static constexpr int LevelCount = FsHeader::IntegrityMetaInfo::NumberOfLevels;
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

    SubStorage m_levelRawStorage[LevelCount];
    SubStorage m_levelDecStorage[LevelCount];
    SubDecryptor m_levelDecryptor[LevelCount];
    LevelInfo m_levelInfo[LevelCount];

    size_t m_imageStorageSize;

    u64 m_blockSize;

    std::shared_ptr<Logger> m_pLogger;
};
