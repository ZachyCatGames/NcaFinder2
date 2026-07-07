#include "BlockRecoverer.h"
#include "Common.h"
#include "ErrorCode.h"
#include "NcaHeaders.h"
#include "ProgressBar.h"
#include "Log.h"
#include "Sha256.h"
#include "Util.h"
#include <bit>
#include <cassert>
#include <cstring>
#include <limits>
#include <vector>

BlockRecoverer::BlockZeroRecoveryData::BlockZeroRecoveryData(u64 startPieceSize, FragmentInfoList::iterator frag) :
    blkData(startPieceSize),
    initialInfo(*frag),
    pInfo(frag) {}


BlockRecoverer::FragmentInfo::FragmentInfo(BlockRecoverer* pParent, u64 offset, u64 size, u64 startCluster, const std::vector<std::byte>& startData, const Sha256::Hash& hash, const MissingExtent& postExtent, bool isNew) :
    m_pParent(pParent),
    m_startData(startData.size()),
    m_offset(offset),
    m_size(size),
    m_startCluster(startCluster),
    m_postExtent(postExtent),
    m_hash(hash),
    m_isNew(isNew)
{
    assert(m_pParent != nullptr);
    assert(m_startData.size() > 0);
    assert(m_pParent->GetStartPieceSize() == static_cast<u64>(m_startData.size()));

    /* Decrypt the initial part. */
    m_pParent->GetDecryptor()->Decrypt(m_startData.data(), startData.data(), offset, m_startData.size());
}

bool BlockRecoverer::FragmentInfo::Compare(std::byte* pEndData) const {
    assert(pEndData != nullptr);

    const u64 endSize = m_pParent->GetEndPieceSize();
    const u64 endStartOffs = this->GetEndPieceOffset();
    std::byte* pWorkBuf = m_pParent->GetWorkBuffer();

    /* Decrypt the end part. */
    m_pParent->GetDecryptor()->Decrypt(pWorkBuf, pEndData, endStartOffs, endSize);

    /* Zero pad block if the extent is larger than the section storage. */
    {
        const u64 sectSize = m_pParent->GetSectionSize();
        if (endStartOffs + endSize > sectSize) {
            std::memset(&pWorkBuf[sectSize - endStartOffs], 0, endStartOffs + endSize - sectSize);
        }
    }

    /* Hash both pieces combined. */
    Sha256 sha;
    Sha256::Hash hash;
    sha.Start();
    sha.Update(m_startData.data(), m_startData.size());
    sha.Update(pWorkBuf, static_cast<size_t>(endSize));
    sha.Finish(&hash);

    //PrintKey("cringe", &hash, 0x20);

    /* Check if the hash matches. */
    return std::memcmp(&m_hash, &hash, sizeof(Sha256::Hash)) == 0;
}

auto BlockRecoverer::FragmentInfo::AddPostExtentToMissingList() const {
    m_pParent->m_missing.push_back(m_postExtent);
    return std::prev(m_pParent->m_missing.cend());
}

BlockRecoverer::BlockRecoverer(IStorage* pSectStorage, IStorage* pImageStorage, IDecryptor* pSecBlockDec, u64 blockSize, u64 blockOffset, u64 imageStartOffset, FILE* logFile) :
    m_pSectionStorage(pSectStorage),
    m_pImageStorage(pImageStorage),
    m_pDecryptor(pSecBlockDec),
    m_logFile(logFile),
    m_blockSize(blockSize),
    m_blockOffset(blockOffset),
    m_curRecExt(),
    m_inRecExt(false),
    m_workBuffer(blockSize),
    m_imageStartOffset(imageStartOffset),
    m_pBlkZeroRec(nullptr),
    m_blk0Reverted(false)
{
    assert(m_pSectionStorage != nullptr);
    assert(m_pImageStorage != nullptr);
    assert(m_pDecryptor != nullptr);
    assert(m_logFile != nullptr);
    assert(std::popcount(blockSize) == 1);
    assert(blockOffset < blockSize);

    /* Get storage sizes. */
    m_pImageStorage->GetSize(&m_imageStorageSize);
    m_pSectionStorage->GetSize(&m_sectionSize);

    /* NOTE: The misaligned size case assumes that each block is composed 
       complete blocks that end with padding. 
       The padding will also be restored alongside the main block data. */
    m_clustersPerBlock     = (blockSize + CLUSTER_SIZE - 1) / CLUSTER_SIZE;
    m_clustersBetweenBlock = m_clustersPerBlock;
    m_clusterCount         = m_imageStorageSize / CLUSTER_SIZE;

    /* Expand clusters per block by one if blocks are misaligned with clusters. */
    if (this->IsMisaligned()) {
        m_clustersPerBlock++;

        m_startPieceOffs = m_clustersPerBlock * CLUSTER_SIZE + m_blockOffset;
        m_startPieceSize = CLUSTER_SIZE - m_blockOffset;
        assert(m_startPieceSize < m_blockSize);

        m_expectedBegin.resize(m_startPieceSize);
    } else {
        m_startPieceOffs = 0; // unused
        m_startPieceSize = 0; // unused
    }

    m_alignedBlockSize = m_clustersBetweenBlock * CLUSTER_SIZE;
    m_endCluster = m_clusterCount - m_clustersPerBlock + 1;

    assert(m_clustersPerBlock > 0);
    assert(m_clustersBetweenBlock > 0);
    assert(m_clusterCount > 0);
    assert(std::popcount(m_alignedBlockSize) == 1); // pow of 2
    assert(m_endCluster > 0 && m_endCluster < m_clusterCount);
}

bool BlockRecoverer::Recover(RecoveredList* recoveredList, const ExtentList& missing, const std::vector<Sha256::Hash>& hashes) {
    assert(recoveredList != nullptr);
    
    /* Copy the hash list. */
    m_hashes = hashes.data();
    
    /* Create the missing / fragment list. */
    this->CreateInitialMissingList(missing, hashes);

    /* 
     * If block zero is corrupt, we have a problem because we can't "reliably"
     * know how it begins.
     * We'll trust the data pointed to by the provided image start offset over
     * whatever is currently in the NCA, but will still keep the old data 
     * to try as a last ditch effort if necessary...
     */
    if (!m_fragments.empty() && m_fragments.cbegin()->GetStartPieceOffset() == 0) {
        this->ExchangeBlockZeroStart();
    }

    /* Pass over the image until we run out of extents or don't find anything. */
    int pass = 0;
    int recovered = 0;
    while (!this->IsDone()) {
        /* Announce pass start. */
        std::print(m_logFile, "Pass {}\n", pass);

        /* Log current extents. */
        std::print(m_logFile, "Current Extents:\n");
        for (const auto& l : m_missing) {
            std::print(m_logFile, "\t0x{:x} - 0x{:x} (0x{:x})\n", l.GetStart(), l.GetEnd(), l.GetSize());
        }
        std::print(m_logFile, "Current block fragments:\n");
        for (const auto& f : m_fragments) {
            std::print(m_logFile, "\tstart=0x{:X}\n", f.GetStartPieceOffset());
        }

        int rec = this->RecoverPass(m_imageStartOffset);

        /* Announce pass end. */
        std::print(m_logFile, "Pass {} recoverd {} blocks\n", pass++, rec);

        /* Update the missing list. */
        this->UpdateMissingList();
        this->UpdateFragmentList();

        recovered += rec;
    }

    /* Handle any leftover recovered extent. */
    if (m_inRecExt) {
        m_recovered.push_back(m_curRecExt);
    }

    /* Log number of recovered blocks. */
    std::print(m_logFile, "Recovered {} blocks.\n", recovered);

    /* Log unrecovered extents. */
    for (const auto l : m_missing) {
        std::print(m_logFile, "Failed to recover 0x{:x} bytes at offset 0x{:x}\n", l.GetSize(), l.GetStart());
    }

    bool recAll = true;

    /* Cleanup. */
    m_missing.clear();
    if (recoveredList)
        *recoveredList = std::move(m_recovered);
    else
        m_recovered.clear();

    return recAll;
}

/* 
 * This is a bit gross because of the hint shit...
 * Basically this starts scanning from the block specified by startHint
 * up until the end of the image storage, then starts back at the beginning
 * and makes another sweep until it reaches startHint again.
 *
 * _In theory_ this speeds up a common case where an NCA is only fragmented
 * by a couple FS blocks.
 */
int BlockRecoverer::RecoverPass(u64 startHint) {
    FLOG_VERBOSE(m_logFile, "fsBlockCount     = 0x{:x}\n", m_clusterCount);
    FLOG_VERBOSE(m_logFile, "fsBlocksPerBlock = 0x{:x}\n", m_clustersPerBlock);
    FLOG_VERBOSE(m_logFile, "alignedBlockSize = 0x{:x}\n", m_alignedBlockSize);
    FLOG_VERBOSE(m_logFile, "startHint        = 0x{:x} (0x{:x})\n", startHint, startHint / CLUSTER_SIZE);

    FLOG_VERBOSE(m_logFile, "Scanning through {} blocks (0x{:x} bytes)\n", m_clusterCount, m_imageStorageSize);

    PrintProgressBar(0.0f);

    int recovered = 0;
    u64 offset    = startHint / CLUSTER_SIZE;
    u64 remaining = m_clusterCount;
    std::vector<std::byte> readBuffer(CLUSTERS_PER_READ * CLUSTER_SIZE);
    ErrorCode error;
    while (remaining > m_clustersPerBlock - 1 && !this->IsDone()) {
        /* Read a bunch of blocks in. */
        /* Avoid overshooting on either the first or second pass. */
        const u64 curRead = std::min(std::min(remaining, CLUSTERS_PER_READ), m_clusterCount - offset); 
        error = m_pImageStorage->Read(readBuffer.data(), offset * CLUSTER_SIZE, curRead * CLUSTER_SIZE);
        if (error != ErrorCode::Success) {
            ClearProgressBar();
            throw DumperException("Failed to read blocks from input: {}\n", ErrorCodeToString(error));
        }

        /* Skip clusters at the end that form partial blocks. */
        const u64 processed = curRead;

        /* Decrypt each using the info for each corrupt block. */
        const u64 barUpdateRate = curRead < 128 ? curRead : curRead / 128;
        for (u64 fsclusterIdx = 0; fsclusterIdx < processed; fsclusterIdx++) {
            std::byte* blkPtr = readBuffer.data() + fsclusterIdx * CLUSTER_SIZE;
            
            /* Check if these match any of the missing extents. */
            recovered += this->AnalyzeBlock(blkPtr, offset);

            /* Check if these match any of the fragmented blocks. */
            recovered += this->CheckFragments(blkPtr, offset);

            offset++;
            remaining--;

            /* Update progress bar. */
            /* NOTE: technically m_endCluster is correct here but using it can result in a fun underflow issue. */
            if (fsclusterIdx % barUpdateRate == 0) {
                //std::printf("Test %f %lx %lx\n", double(m_clusterCount - remaining), m_clusterCount, remaining);
                PrintProgressBar(double(m_clusterCount - remaining) / m_clusterCount);
            }
        }

        /* Handle end wraparound. */
        if (offset >= m_endCluster) {
            offset = 0;
        }
    }

    ClearProgressBar();

    return recovered;
}

int BlockRecoverer::AnalyzeBlock(const std::byte* pBlock, u64 clusterId) {
    int recovered = 0; // this is probably never greater than 1, but eh
    ErrorCode error;
    auto rec = m_missing.begin();

    while (rec != m_missing.end()) {
        //PrintKey("cringe 3", &hashes[rec->GetStart() / m_blockSize], 0x20);
        const auto start = rec->GetStart();
        const auto end   = rec->GetEnd();
        const auto size  = rec->GetSize();

        /* Decrypt block contents. */
        //std::printf("%lx\n", fsclusterIdx);
        m_pDecryptor->Decrypt(m_workBuffer.data(), pBlock + m_blockOffset, start, m_blockSize);

        /* Zero pad block if the extent is larger than the section storage. */
        if (end > m_sectionSize) {
            std::memset(&m_workBuffer[m_sectionSize - start], 0, end - m_sectionSize);
        }

        /* Check its sha256 hash. */
        Sha256::Hash shaHash;
        const u64 compareSize = std::min(size, m_blockSize);
        ComputeSha256Sum(&shaHash, m_workBuffer.data(), compareSize);

        /* Does it match the target hash? */
        decltype(rec) nextRec;
        const auto& targetHash = this->GetHashForOffset(start);
        if (!std::memcmp(&shaHash, &targetHash, sizeof(shaHash))) {
            /* Log that we recovered a block. */
            std::print(m_logFile, "Recovered 0x{:x} from image offset 0x{:x}\n", start, clusterId * CLUSTER_SIZE);
            
            /* Increment recovered count.*/
            recovered++;

            /* Write recovered block to the raw section storage. */
            const u64 writeSize = this->GetRequiredWriteSize(start);
            error = m_pSectionStorage->Write(pBlock, start, writeSize);
            if (error != ErrorCode::Success) {
                throw DumperException("Failed to write offset 0x{:x} in section storage!\n", start);
            }

            /* Save the beginning of the next block. */
            if (this->IsMisaligned()) {
                std::memcpy(m_expectedBegin.data(), pBlock + m_startPieceOffs, m_startPieceSize);
            }

            if (this->IsExpectedNextBlock(clusterId, start)) {
                /* Extend the current recover extent. */
                m_curRecExt.Extend(writeSize);
                m_expectedSecOffs += writeSize;
                m_expectedCluster += m_clustersBetweenBlock;
            } else if (m_inRecExt) {
                /* Add the current extent to the list. */
                m_recovered.push_back(m_curRecExt);

                m_inRecExt = false;
            } else {
                /* Setup a new recovered extent. */
                m_curRecExt         = RecoveredRecord(clusterId * CLUSTER_SIZE, start, compareSize);
                m_expectedSecOffs = start + writeSize;
                m_expectedCluster = clusterId + m_clustersBetweenBlock;
                m_inRecExt          = true;
            }

            if (rec->GetSize() - compareSize != 0) {
                rec->Forward(compareSize);
                nextRec = rec;
            } else {
                nextRec = m_missing.erase(rec);
            }
        } else if (this->IsMisaligned() && this->IsExpectedNextBlock(clusterId, start)) {
            /*
             * If we're operating on misaligned blocks, we're at the next expected section offset,
             * AND we didn't hit a match, we've hit a fragment (or there's corruption).
             * Add a fragment record.
             */
            m_fragments.emplace_back(this, start, size, clusterId, m_expectedBegin, targetHash, rec->Forwarded(m_blockSize));

            /* Skip this block for now. */
            m_missing.erase(rec);

            std::print(m_logFile,
                "Found block fragment: section_offset=0x{:X}; start_image_offset=0x{:X}\n",
                start,
                clusterId * CLUSTER_SIZE
            );

            nextRec = std::next(rec);
        }

        rec = nextRec;
    }

    return recovered;
}

bool BlockRecoverer::IsExpectedNextBlock(u64 clusterId, u64 secOffs) const {
    return m_inRecExt && clusterId == m_expectedCluster && secOffs == m_expectedSecOffs;
}

int BlockRecoverer::CheckFragments(std::byte* pClusters, u64 clusterId) {
    auto f = m_fragments.cbegin();
    int recovered = 0;
    while (f != m_fragments.cend()) {
        /* Compare against the fragment. */
        if (f->Compare(pClusters)) {
            const u64 start = f->GetStartPieceOffset() + m_startPieceSize;
            const u64 writeSize = this->GetRequiredWriteSize(start);

            /* Log our findings. */
            std::print(m_logFile,
                "Resolved fragment: section_offset=0x{:X}; start_image_offset=0x{:X}; resume_image_offset=0x{:X}\n",
                start,
                f->GetStartCluster(),
                clusterId
            );

            /* Write the clusters to the nca. */
            ErrorCode err = m_pSectionStorage->Write(pClusters, start, writeSize);
            if (err != ErrorCode::Success) {
                throw DumperException("Failed to write to section: {}\n", ErrorCodeToString(err));
            }

            /* Add post extent. */
            if (f->HasPostExtent()) {
                f->AddPostExtentToMissingList();
            }

            /* Update the recovered list. */
            m_recovered.emplace_back(clusterId * CLUSTER_SIZE, start, f->GetBlockSize());

            /* Remove the fragment record. */
            f = m_fragments.erase(f);

            /* Setup next block info. */
            if (m_inRecExt) {
                /* Add the current extent to the list. */
                m_recovered.push_back(m_curRecExt);

                m_inRecExt = false;
            } else {
                /* Setup a new recovered extent. */
                m_curRecExt         = RecoveredRecord(clusterId * CLUSTER_SIZE, start, writeSize);
                m_expectedSecOffs = start + writeSize;
                m_expectedCluster = clusterId + m_clustersBetweenBlock;
                m_inRecExt          = true;
            }

            /* Increment recovered count. */
            recovered++;
        } else {
            ++f;
        }
    }

    return recovered;
}

void BlockRecoverer::CreateInitialMissingList(const ExtentList& missing, const std::vector<Sha256::Hash>& hashes) {
    if (!this->IsMisaligned()) {
        this->CreateInitialMissingListImpl(missing);
    } else {
        this->CreateInitialFragmentList(missing, hashes);
    }
}

void BlockRecoverer::CreateInitialMissingListImpl(const ExtentList& missing) {
    for (const auto& m : missing) {
        m_missing.emplace_back(m.GetStart(), m.GetSize(), false);
    }
}

void BlockRecoverer::CreateInitialFragmentList(const ExtentList& missing, const std::vector<Sha256::Hash>& hashes) {
    /* We can safely assume the start piece is valid. */
    std::vector<std::byte> tmp(m_startPieceSize);
    for (const auto& m : missing) {
        this->MigrateExtentToFragmentList(m);
    }
}

template<typename Ext>
void BlockRecoverer::MigrateExtentToFragmentList(Ext m) {
    const u64 start = m.GetStart();
    const u64 end   = m.GetEnd();
    const u64 size  = m.GetSize();
    const u64 cluster = 0; // TODO

    /* Read the start piece. */
    m_pSectionStorage->Read(m_expectedBegin.data(), start, m_startPieceSize);  

    const auto postExtent = size > m_blockSize ? MissingExtent(start + m_blockSize, size - m_blockSize, true) :
                                            MissingExtent(0,0,false);
    const auto& targetHash = this->GetHashForOffset(start);
    const u64 fragSize = std::min(size, m_blockSize);

    /* Update the fragment list. */
    m_fragments.emplace_back(this, start, fragSize, cluster, m_expectedBegin, targetHash, postExtent);
}

void BlockRecoverer::UpdateMissingList() {
    auto m = m_missing.begin();
    while (m != m_missing.end()) {
        if (m->IsNew()) {
            /* Clear the new flag + skip this entry. */
            m->ClearNewFlag();
            ++m;
        } else if (m->GetSize() <= m_blockSize) {
            m = m_missing.erase(m);
        } else {
            /* Split the extent. */
            // TODO: Migrate to fragment list
            m = this->SplitAndRemoveMissingExtent(m);
        }
    }
}

void BlockRecoverer::UpdateFragmentList() {
    auto f = m_fragments.begin();
    while (f != m_fragments.end()) {
        if (f->GetStartPieceOffset() == 0 && !m_blk0Reverted) {
            /* Revert block 0 start to its initial state. */
            assert(m_pBlkZeroRec != nullptr);
            this->RevertBlockZeroStart();
        } else if (f->IsNew()) {
            f->ClearNewFlag();
            ++f;
        } else {
            /* Split + add the post-extent to the missing list. */
            if (f->GetPostExtent().GetSize() > m_blockSize) {
                this->SplitMissingExtent(f->GetPostExtent());
            }

            /* Remove the fragment entry. */
            f = m_fragments.erase(f);
        }
    }
}

void BlockRecoverer::SplitMissingExtent(const MissingExtent& missing) {
    assert(missing.GetSize() > m_blockSize);

    u64 offs = missing.GetStart();
    u64 remaining = missing.GetSize();
    u64 size = m_blockSize;
    while (remaining != 0) {
        m_missing.emplace_front(offs, size, false);
        offs += size;
        remaining -= size;
        size = std::min(size << 1u, remaining);
    }
}

template<typename Iter>
Iter BlockRecoverer::SplitAndRemoveMissingExtent(Iter ext) {
    this->SplitMissingExtent(ext->Forwarded(m_blockSize));
    return m_missing.erase(ext);
}

void BlockRecoverer::ExchangeBlockZeroStart() {
    /* Read the beginning data pointed to by image start offset. */
    const u64 offset = m_imageStartOffset + m_blockOffset;
    ErrorCode err = m_pImageStorage->Read(m_expectedBegin.data(), offset, m_startPieceSize);
    if (err != ErrorCode::Success) {
        throw DumperException("Failed to read block 0 candidate from image: {}\n", ErrorCodeToString(err));
    }

    /* Create block zero recovery data. */
    auto it = m_fragments.begin();
    auto pZeroRec = std::make_unique<BlockZeroRecoveryData>(m_startPieceOffs, it);

    /* Read the beginning of the original block 0. */
    err = m_pSectionStorage->Read(pZeroRec->GetBuffer(), 0, pZeroRec->GetBufferSize());
    if (err != ErrorCode::Success) {
        throw DumperException("Failed to read initial block 0 data from section: {}\n", ErrorCodeToString(err));
    }

    /* Write it to the section storage. */
    err = m_pSectionStorage->Write(m_expectedBegin.data(), 0, m_startPieceSize);
    if (err != ErrorCode::Success) {
        throw DumperException("Failed to write block 0 candidate to section: {}\n", ErrorCodeToString(err));
    }

    /* Update the block fragment record. */
    const auto postExt = it->GetPostExtent();
    *it = FragmentInfo(
        this,
        0,
        std::min(m_blockSize, m_sectionSize),
        m_imageStartOffset / CLUSTER_SIZE,
        m_expectedBegin,
        m_hashes[0],
        postExt,
        false
    );

    m_pBlkZeroRec = std::move(pZeroRec);
}

void BlockRecoverer::RevertBlockZeroStart() {
    /* Revert the block 0 fragment info. */
    *m_pBlkZeroRec->pInfo = m_pBlkZeroRec->initialInfo;

    /* Write block 0 data back. */
    ErrorCode err = m_pSectionStorage->Write(m_pBlkZeroRec->GetBuffer(), 0, m_pBlkZeroRec->GetBufferSize());
    if (err != ErrorCode::Success) {
        throw DumperException("Failed to write initial block 0 data back to section: {}\n", ErrorCodeToString(err));
    }

    m_blk0Reverted = true;
    m_pBlkZeroRec.reset();
}
