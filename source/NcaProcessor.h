#pragma once
#include <cstddef>
#include <fstream>
#include <memory>
#include <string>
#include <optional>
#include "IDecryptor.h"
#include "IStorage.h"
#include "ISectionProcessor.h"
#include "NcaHeaders.h"
#include "MultiLogger.h"

class NcaProcessor {
public:
    class SectionInfoReader {
    public:
        constexpr u64 GetStartOffset() const { return m_pEntry->startBlock * NCA_BLOCK_SIZE; }
        constexpr u64 GetEndOffset() const { return m_pEntry->endBlock * NCA_BLOCK_SIZE; }
        constexpr u64 GetSize() const { return (m_pEntry->endBlock - m_pEntry->startBlock) * NCA_BLOCK_SIZE; }

        constexpr bool IsSectionMisaligned() const noexcept{ return this->GetStartOffset() % CLUSTER_SIZE != 0; }
        constexpr u64 GetMisalignment() const noexcept { return this->GetStartOffset() % CLUSTER_SIZE; }

        constexpr FsHeader::FsType GetFilesystemType() const { return m_pHeader->fsType; }
        constexpr FsHeader::HashType GetHashType() const { return m_pHeader->hashType; }

        constexpr FsHeader::EncryptionType GetEncryptionType() const { return m_pHeader->encryptionType; }

        constexpr auto GetHierarchicalSha256Data() const { return &m_pHeader->hierarchicalSha256Data; }
        constexpr auto GetIntegrityMetaData() const { return &m_pHeader->integrityMetaInfo; }
    private:
        friend class NcaProcessor;
        SectionInfoReader(const FsEntry* pEnt, const FsHeader* pHdr) : m_pEntry(pEnt), m_pHeader(pHdr) {}
    private:
        const FsEntry* m_pEntry;
        const FsHeader* m_pHeader;
    }; // class SectionInfoReader
public:
    NcaProcessor(std::shared_ptr<IStorage> pImageStorage, uint64_t ncaOffset, bool isDev);

    ~NcaProcessor();

    void CopyContiguous();
    void Process();

    int64_t GetBaseOffset() const noexcept { return m_ncaOffset; }
private:
    std::unique_ptr<ISectionProcessor> CreateSectionProcessor(SectionInfoReader infoReader, std::shared_ptr<IStorage> pRawSect, std::shared_ptr<IStorage> pDecSect, std::unique_ptr<IDecryptor>&& pDecryptor);

    std::string CreateOutFilePath(std::string_view extension);
private:
    std::shared_ptr<IStorage> m_pImageStorage;
    std::shared_ptr<IStorage> m_pNcaStorage;
    size_t m_ncaOffset;

    std::byte m_aesCtrKey[0x10];

    FILE* m_ncaFile;
    FILE* m_logFile;

    std::optional<MultiLogger> m_logger;
    FILE* m_logOutput;

    RecoveredList m_recovered;

    NcaHeader m_mainHeader;
    FsHeader m_fsHeaders[4];
    int m_fsHeaderCount;

    bool m_plaintext;
};
