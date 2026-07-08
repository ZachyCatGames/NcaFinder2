#include "HISha256Processor.h"
#include "BlockRecoverer.h"
#include "Common.h"
#include "IBlockVerifier.h"
#include "ErrorCode.h"
#include "NcaHeaders.h"
#include "NcaProcessor.h"
#include "ProgressBar.h"
#include "Sha256.h"
#include "SubDecryptor.h"
#include "SubStorage.h"
#include "Util.h"
#include <bit>
#include <cstddef>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

namespace {

class H256BlockVerifier : public IBlockVerifier {
public:
    H256BlockVerifier(size_t blockSize) : m_blockSize(blockSize) {}

    void Reset() override {
        m_hash.Start();
    }

    void Update(const void* pData, size_t dataSize) override {
        m_hash.Update(pData, dataSize);
    }

    bool Finish(const void* pHash, size_t hashSize) override {
        assert(hashSize == sizeof(Sha256::Hash));

        /* Finish the hash. */
        Sha256::Hash hash;
        m_hash.Finish(&hash);

        /* Compare the hashes. */
        return std::memcmp(&hash, pHash, sizeof(hash));
    }
private:
    Sha256 m_hash;
    size_t m_blockSize;
}; // class H256BlockVerifier

} // namespace

void HISha256Processor::HashDataReader::Validate() const {
    /* Sanity checks... */
    if (m_pData->layerCount != 2) {
        throw DumperException("HSha256 layer count invalid ");
    }

    if (std::popcount(this->BlockSize()) != 1) {
        throw DumperException("Non-power-of-two HSha256 block sizes are not supported");
    }

    /* Each layer must start at a multiple of the FS block size. */
    /*
    for (int i = 0; i < m_pData->layerCount; i++) {
        if (m_pData->region[i].offset % CLUSTER_SIZE != 0) {
            throw DumperException("Region {} is not aligned to FAT cluster size", i);
        }
    } */
}

HISha256Processor::HISha256Processor(NcaProcessor* pParent, SectionInfoReader infoReader, std::shared_ptr<IStorage> pInputStorage, std::shared_ptr<IStorage> pRawStorage, std::shared_ptr<IStorage> pDecStorage, std::unique_ptr<IDecryptor>&& pSecBlockDec, const std::shared_ptr<Logger> pLogger) :
    m_pParent(pParent),
    m_sectInfo(infoReader),
    m_hashData(m_sectInfo.GetHierarchicalSha256Data()),
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
    assert(m_pLogger != nullptr);
    assert(infoReader.GetHashType() == FsHeader::HashType::HierarchicalSha256Hash);

    /* Verify hash data. */
    m_hashData.Validate();

    m_blockSize = m_hashData.BlockSize();
    m_pLogger->print("Block size: 0x{}\n", m_blockSize);

    /* Setup sub storages. */
    const u64 alignedHashSize = AlignUp(m_hashData[0].size, CLUSTER_SIZE);
    const u64 alignedDataSize = AlignUp(m_hashData[1].size, CLUSTER_SIZE);
    m_pLogger->print("hash region: start: {:x}; size: {:x}\n", m_hashData[0].offset, alignedHashSize);
    m_pLogger->print("data region: start: {:x}; size: {:x}\n", m_hashData[1].offset, alignedDataSize);
    m_hashRawStorage = SubStorage(m_pRawStorage.get(), m_hashData[0].offset, alignedHashSize);
    m_dataRawStorage = SubStorage(m_pRawStorage.get(), m_hashData[1].offset, alignedDataSize);
    m_hashDecStorage = SubStorage(m_pDecStorage.get(), m_hashData[0].offset, alignedHashSize);
    m_dataDecStorage = SubStorage(m_pDecStorage.get(), m_hashData[1].offset, alignedDataSize);

    /* Setup sub decryptors. */
    m_hashDecryptor = SubDecryptor(m_pDecryptor.get(), m_hashData[0].offset);
    m_dataDecryptor = SubDecryptor(m_pDecryptor.get(), m_hashData[1].offset);

    /* Get sizes. */
    m_pImageStorage->GetSize(&m_imageStorageSize);
    m_pDecStorage->GetSize(&m_sectionSize);

    /* raw size must be the same as dec size. */
    size_t rawSize;
    m_pRawStorage->GetSize(&rawSize);
}

std::list<Extents<u64>> HISha256Processor::ScanForCorruptDataBlocks(const std::vector<Sha256::Hash>& hashes) {
    const size_t count = hashes.size();

    const size_t dataSize = m_hashData[1].size;

    m_pLogger->print("Scanning data region for corrupt blocks...\n");
    //std::fflush(m_logFile);
    std::this_thread::sleep_for(100ms); // race condition hack
    PrintProgressBar(0.0f);

    ErrorCode error;
    u64 offset    = 0;
    u64 remaining = count;
    u64 corrupt   = 0;
    u64 extentStart, extentSize;
    std::vector<std::byte> buffer(m_blockSize * CLUSTERS_PER_READ);
    std::list<Extents<u64>> extents;
    bool inExtent = false;
    while (remaining > 0) {
        /* Read a bunch of blocks. */
        const u64 readCount = std::min(CLUSTERS_PER_READ, remaining);
        const u64 readSize  = std::min(readCount * m_blockSize, dataSize - offset * m_blockSize);
        error = m_dataDecStorage.Read(buffer.data(), offset * m_blockSize, readSize);
        if (error != ErrorCode::Success) {
            throw DumperException("Failed to read from data region {}", offset);
        }

        /* Verify each block. */
        const u64 barUpdateRate = readCount < 128 ? readCount : readCount / 128;

        for (u64 i = 0; i < readCount; i++) {
            const Sha256::Hash& targetHash = hashes[offset];

            const u64 hashSize = std::min(m_blockSize, dataSize - offset * m_blockSize);
            //if (hashSize != m_blockSize) {
            //    std::printf("block %zd; hashSize = %zx\n", (offset - start), hashSize);
            //}

            Sha256::Hash hash;
            ComputeSha256Sum(&hash, buffer.data() + i * m_blockSize, hashSize);
            if (std::memcmp(&hash, &targetHash, sizeof(hash))) {
                ClearProgressBar();
                //m_pLogger->print("Block {} in data region is corrupt\n", offset);
                
                /* Start a new extent or append to the current one. */
                if (inExtent) {
                    extentSize += hashSize;
                } else {
                    inExtent    = true;
                    extentStart = offset * m_blockSize;
                    extentSize  = hashSize;
                }

                /* Increment corrupt count. */
                corrupt++;
            } else if (inExtent) {
                /* Break the current extent. */
                inExtent = false;
                extents.emplace_back(extentStart, extentSize);
            }

            /* Update displayed progress. */
            if (i % barUpdateRate == 0) {
                PrintProgressBar(double(offset) / count);
            }

            remaining--;
            offset++;
            assert(remaining != std::numeric_limits<size_t>::max()); // overflow bad
            assert(offset != 0);
        }
    }

    /* Add final extent. */
    if (inExtent) {
        extents.emplace_back(extentStart, extentSize);
    }

    /* Announce scanning completion. */
    ClearProgressBar();
    m_pLogger->print("Finished scanning... {} corrupt blocks found.\n", corrupt);

    return extents;
}

bool HISha256Processor::Process(RecoveredList* pRecoveredList, u64 recoveryStartOffset) {
    /* Check if hash blocks are valid. */
    const u64 count = m_hashData[0].size / sizeof(Sha256::Hash);
    std::vector<Sha256::Hash> hashes(count);
    ErrorCode error = m_hashDecStorage.Read(hashes.data(), 0, hashes.size() * Sha256::Hash::Size);
    if (error != ErrorCode::Success) {
        throw DumperException("Failed to read hash storage.");
    }

    /* Query target section's start location. */
    const u64 sectionStart = m_sectInfo.GetStartOffset();

    //PrintKey("Cring e69", hashes.data(), 0x100);

    Sha256::Hash hash;
    ComputeSha256Sum(&hash, hashes.data(), m_hashData[0].size);
    if (std::memcmp(&hash, &m_hashData.MasterHash(), sizeof(hash))) {
        m_pLogger->print("Master hash mismatch\n");
        fflush(stdout);
        
        /* Try recovering the hash region. */
        std::list<Extents<u64>> records {
            { 0, m_hashData[0].size }
        };
        std::vector<Sha256::Hash> mHashes {
            m_hashData.MasterHash()
        };

        /* Setup recoverer. on the hash region. */
        BlockRecoverer recover(
            &m_hashRawStorage,
            m_pImageStorage.get(),
            &m_hashDecryptor,
            m_hashData[0].size,
            0,
            sectionStart + m_hashData[0].offset,
            std::make_shared<H256BlockVerifier>(m_blockSize),
            m_pLogger
        );

        RecoveredList rec;
        if (recover.Recover(&rec, std::move(records), mHashes) == 0) {
            throw DumperException("Failed to recover hash region\n");
        }

        /* NOTE/TODO: this assumes hashes start at offset 0. */
        m_recovered.splice(m_recovered.cend(), std::move(rec));

        /* Read recovered hashes. */
        error = m_hashDecStorage.Read(hashes.data(), 0, hashes.size() * Sha256::Hash::Size);
        if (error != ErrorCode::Success) {
            throw DumperException("Failed to read hash storage\n");
        }
    }

    /* Search for corrupt data blocks. */
    auto records = this->ScanForCorruptDataBlocks(hashes);

    /* Fill the gaps in the recovered list. */
    this->FillRecoveredFromCorrupt(records, m_hashData[1].offset, m_hashData[1].size);
    m_pLogger->print("filled\n");

    /* Attempt data recovery. */
    bool recAll = true; 
    if (!records.empty()) {
        /* Attempt recovery. */
        RecoveredList rec;
        BlockRecoverer recover(
            &m_dataRawStorage,
            m_pImageStorage.get(),
            &m_dataDecryptor,
            m_blockSize,
            0,
            sectionStart + m_hashData[1].offset,
            std::make_shared<H256BlockVerifier>(m_blockSize),
            m_pLogger
        );
        recAll = recover.Recover(&rec, std::move(records), hashes);
    
        /* Update our recovered list. */
        for (auto& r : rec) {
            m_recovered.emplace_back(r.GetImageStart(), r.GetSectionStart() + m_hashData[1].offset, r.GetSize());
        }
    } else {
        /* Add one entry spanning the entire section. */
        m_recovered.emplace_back(sectionStart, 0, m_sectionSize);
    }

    /* Sort and coalesce the recovered list. */
    m_recovered.sort();
    m_recovered.coalesce();

    /* Return the recovered list. */
    *pRecoveredList = std::move(m_recovered);

    return recAll;
}

void HISha256Processor::FillRecoveredFromCorrupt(const std::list<Extents<u64>>& corrupt, u64 layerStart, u64 layerSize) {
    u64 s = 0;
    u64 startInImage = m_pParent->GetBaseOffset() + m_sectInfo.GetStartOffset() + layerStart;
    for (const auto& c : corrupt) {
        const u64 size = c.GetStart() - s;
        if (size != 0) {
            m_recovered.emplace_back(startInImage + s, s + layerStart, size);
        }
        s = c.GetEnd();
    }

    if (s != layerSize) {
        m_recovered.emplace_back(startInImage + s, s + layerStart, layerSize - s);
    }
}
