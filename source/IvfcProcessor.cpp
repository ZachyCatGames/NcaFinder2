#include "IvfcProcessor.h"
#include <cassert>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include "BlockRecoverer.h"
#include "Common.h"
#include "ProgressBar.h"
#include "Sha256.h"
#include "SubDecryptor.h"
#include "SubStorage.h"
#include "Util.h"

using namespace std::chrono_literals;

void IvfcSectionProcessor::HashDataReader::Validate() const {
    /* Sanity checks... */
    if (!m_pData->IsMagicValid()) {
        throw DumperException("IVFC Magic is invalid!\n");
    }

    if (m_pData->version != 0x20000) {
        throw DumperException("Unrecognized IVFC version (0x{:x})\n", m_pData->version);
    }

    if (m_pData->infoLevelHash.maxLayers != 7) {
        throw DumperException("Invalid number of layers ({})\n", m_pData->infoLevelHash.maxLayers);
    }
}

IvfcSectionProcessor::IvfcSectionProcessor(NcaProcessor* pParent, SectionInfoReader sectInfo, std::shared_ptr<IStorage> pInputStorage, std::shared_ptr<IStorage> pRawStorage, std::shared_ptr<IStorage> pDecStorage, std::unique_ptr<IDecryptor>&& pSecBlockDec, const std::shared_ptr<Logger> pLogger) :
    m_pParent(pParent),
    m_sectInfo(sectInfo),
    m_hashData(m_sectInfo.GetIntegrityMetaData()),
    m_pDecStorage(std::move(pDecStorage)),
    m_pRawStorage(std::move(pRawStorage)),
    m_pImageStorage(std::move(pInputStorage)),
    m_pDecryptor(std::move(pSecBlockDec)),
    m_pLogger(pLogger)
{
    assert(m_pParent != nullptr);
    assert(m_pDecStorage != nullptr);
    assert(m_pRawStorage != nullptr);
    assert(m_pImageStorage != nullptr);
    assert(m_pDecryptor != nullptr);
    assert(pLogger != nullptr);
    assert(sectInfo.GetHashType() == FsHeader::HashType::HierarchicalIntegrityHash);

    m_hashData.Validate();

    auto topLevelOrder = m_hashData[0].blockOrder;
    for (const auto& l : m_hashData.GetLeveLInfo()) {
        if (l.blockOrder != topLevelOrder) {
            throw DumperException("IVFC with varying block sizes is not supported.\n");
        }
    }

    /* TODO: Support diff block sizes. */
    /* Everything I've seen uses 0x4000 (matches FAT block size they use). */
    /* If I ever see anything else, I'll update this. */
    m_blockSize = static_cast<size_t>(1u) << topLevelOrder;
    if(m_blockSize != 0x4000) {
        throw DumperException("IVFC block size not supported (0x{:x})", m_blockSize);
    }

    /* Get input storage size. */
    m_pImageStorage->GetSize(&m_imageStorageSize);

    /* Setup sub storages and sub decryptors for each level. */
    for (int i = 0; i < LevelCount; i++) {
        const auto& levelInfo = m_hashData[i];
        m_levelRawStorage[i] = SubStorage(m_pRawStorage.get(), levelInfo.offset, levelInfo.size);
        m_levelDecStorage[i] = SubStorage(m_pDecStorage.get(), levelInfo.offset, levelInfo.size);
        m_levelDecryptor[i]  = SubDecryptor(m_pDecryptor.get(), levelInfo.offset);
    }
}

std::list<Extents<u64>> IvfcSectionProcessor::ScanForCorruptBlocks(int level, const std::vector<Sha256::Hash>& hashes, SubStorage* pDataStorage) {
    /* Get block count. */
    const u64 dataSize = m_hashData[level].size;

    //FLOG_VERBOSE(m_logFile, "Data Size: 0x{:x}\n", dataSize);

    std::vector<std::byte> levelData(CLUSTERS_PER_READ * CLUSTER_SIZE);

    if (dataSize == 0) {
        throw DumperException("Zero blocks?");
    }

    m_pLogger->print("Scanning for corrupt blocks...\n");
    //std::fflush(m_logFile);
    std::this_thread::sleep_for(100ms); // race condition hack
    PrintProgressBar(0.0);

    u64 offset       = 0;
    u64 remaining    = dataSize;
    u64 corruptCount = 0;
    ErrorCode error;
    std::list<Extents<u64>> corruptExtents;
    Extents<u64> curExtent;
    bool inCorrupt = false;
    while (remaining > 0) {
        const u64 dataRead = std::min(remaining, levelData.size());

        /* Read data from the data level. */
        error = pDataStorage->Read(levelData.data(), offset, dataRead);
        if (error != ErrorCode::Success) {
            throw DumperException("Failed to read level data: {}\n", ErrorCodeToString(error));
        }
        //PrintKey("Starting Level Data", levelData.data(), 0x200);

        /* Update the progress bar every 128 blocks. */
        const u64 barUpdateRate = dataRead < (128 * CLUSTER_SIZE) ? dataRead : dataRead / (128 * CLUSTER_SIZE);

        for (u64 i = 0; i < dataRead; i += CLUSTER_SIZE) {
            /* Zero pad the block if needed. */
            if (remaining < m_blockSize) {
                std::memset(&levelData[remaining], 0, m_blockSize - remaining);
            }

            /* Calculate the current block's hash. */
            Sha256::Hash shaHash;
            const u64 compareSize = std::min(m_blockSize, dataSize - offset);
            ComputeSha256Sum(&shaHash, &levelData[i], m_blockSize);

            /* Compare the hash with the expected one. */
            const u64 recSize = std::min(remaining, m_blockSize);
            if (std::memcmp(&shaHash, &hashes[offset / CLUSTER_SIZE], Sha256::Hash::Size)) {
                ClearProgressBar();
                m_pLogger->print("Offset 0x{:x} in level {} corrupt.\n", offset, level);

                /* Start a new extent or append to the current one. */
                if (inCorrupt) {
                    curExtent.Extend(recSize);
                } else {
                    inCorrupt  = true;
                    curExtent = Extents<u64>(offset, recSize);
                }

                corruptCount++;
            } else if (inCorrupt) {
                /* Break the current corrupt extent. */
                inCorrupt = false;
                corruptExtents.push_back(curExtent);
            }

            if (i % barUpdateRate == 0) {
                //std::fprintf(stderr, "%zd\n", count);
                PrintProgressBar(double(offset) / dataSize);
            }

            offset += recSize;
            remaining -= recSize;
        }
    }

    /* Add final extent. */
    if (inCorrupt) {
        corruptExtents.push_back(curExtent);
    }

    /* Announce scanning completion. */
    ClearProgressBar();
    m_pLogger->print("Scan end. Found {} corrupt blocks.\n", corruptCount);

    return corruptExtents;
}

bool IvfcSectionProcessor::Process(RecoveredList* pRecoveredList, u64 recoveryStartOffset) {
    /* Read the first level. */
    std::vector<std::byte> level0Data(m_hashData[0].size);
    m_levelDecStorage->Read(level0Data.data(), 0, level0Data.size());
    
    /* Query the target section's start offset. */
    const u64 sectionStart = m_sectInfo.GetStartOffset();

    /* Calculate level0 hash. */
    Sha256::Hash l0Hash;
    ComputeSha256Sum(&l0Hash, level0Data.data(), level0Data.size());
    //PrintKey("Level 0 sha256", &l0Hash, 0x20);
    //PrintKey("Level 0 0x200", level0Data.data(), 0x200);

    /* Check if we need to recovery level 0. */
    if (std::memcmp(&l0Hash, &m_hashData.MasterHash(), Sha256::Hash::Size)) {
        m_pLogger->print("Master Hash Mismatch.\n");

        /* TODO: Accomodate cases where level zero spans more than 1 block (I don't think this ever happens). */
        std::list<Extents<u64>> records {
            {0, m_blockSize }
        };
        std::vector<Sha256::Hash> mHash {
            m_hashData.MasterHash()
        };

        RecoveredList rec;
        BlockRecoverer recover(
            &m_levelRawStorage[0],
            m_pImageStorage.get(),
            &m_levelDecryptor[0],
            m_blockSize,
            0,
            sectionStart + m_hashData[0].offset,
            m_pLogger
        );
        if (recover.Recover(&rec, std::move(records), mHash) == 0) {
            throw DumperException("Failed to recover level 0.\n");
        }

        /* Add recoverd extents to the recovered list. */
        m_recovered.splice(m_recovered.cend(), std::move(rec));

    }

    /* Don't need this level 0 data anymore. */
    level0Data.clear();

    /* Check lower levels. */
    bool recAll = true;
    for (int i = 0; i < FsHeader::IntegrityMetaInfo::NumberOfLevels - 1; i++) {
        m_pLogger->print("Scanning level {} using level {} hashes.\n", i+1, i);

        const auto& hashLevelInfo = m_hashData[i];
        const auto& dataLevelInfo = m_hashData[i+1];

        /* Read the hashes. */
        auto hashes = this->ReadHashes(i);

        /* Create a list of corrupt extents. */
        auto records = this->ScanForCorruptBlocks(i + 1, hashes, &m_levelDecStorage[i+1]);
    
        /* Fill the recovered list using the gaps. */
        this->FillRecoveredFromCorrupt(records, dataLevelInfo.offset, dataLevelInfo.size);

        /* Try to find any invalid blocks in our input storage. */
        if (!records.empty()) {
            /* Attempt recovery. */
            RecoveredList rec;
            BlockRecoverer recover(
                &m_levelRawStorage[i+1],
                m_pImageStorage.get(),
                &m_levelDecryptor[i+1],
                m_blockSize,
                m_sectInfo.GetMisalignment(),
                sectionStart + hashLevelInfo.offset,
                m_pLogger
            );
            
            if (!recover.Recover(&rec, std::move(records), hashes))
                recAll = false;

            /* Update the recovered list. */
            for (const auto& r : rec) {
                m_recovered.emplace_back(r.GetImageStart(), r.GetSectionStart() + dataLevelInfo.offset, r.GetSize());
            }

            /* Abort if we fail to recover any level (further recovery would be unreliable). */
            if (!recAll) {
                break;
            }
        }
    }

    /* Sort and coalesce the recovered list. */
    m_recovered.sort();
    m_recovered.coalesce();

    /* Return the recovered list. */
    *pRecoveredList = std::move(m_recovered);

    return true;
}

std::vector<Sha256::Hash> IvfcSectionProcessor::ReadHashes(int level) {
    assert(level < LevelCount - 1);

    const auto& info = m_hashData[level+1];
    u64 count = AlignUp(static_cast<u64>(info.size), m_blockSize) / m_blockSize;

    std::vector<Sha256::Hash> hashes(count);
    m_levelDecStorage[level].Read(hashes.data(), 0, count * Sha256::Hash::Size);

    return hashes;
}

void IvfcSectionProcessor::FillRecoveredFromCorrupt(const std::list<Extents<u64>>& corrupt, u64 levelStart, u64 levelSize) {
    u64 s = 0;
    u64 startInImage = m_pParent->GetBaseOffset() + m_sectInfo.GetStartOffset() + levelStart;
    for (const auto& c : corrupt) {
        const u64 size = c.GetStart() - s;
        if (size != 0) {
            m_recovered.emplace_back(startInImage + s, s + levelStart, size);
        }
        s = c.GetEnd();
    }

    if (s != levelSize) {
        m_recovered.emplace_back(startInImage + s, s + levelStart, levelSize - s);
    }
}
