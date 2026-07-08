#pragma once
#include <list>
#include <memory>
#include <vector>
#include "Common.h"
#include "IBlockVerifier.h"
#include "IDecryptor.h"
#include "IStorage.h"
#include "Sha256.h"
#include "Extents.h"
#include "LocationRecord.h"
#include "Logger.h"

// TODO: sha3256
class BlockRecoverer {
public:
    using ExtentList    = std::list<Extents<u64>>;
    //using ExtentList = std::list<CorruptBlockInfo>;

    BlockRecoverer() : m_pSectionStorage(nullptr) {}
    BlockRecoverer(IStorage* pSectStorage, IStorage* pImageStorage, IDecryptor* pDecryptor, u64 blockSize, u64 blockOffset, u64 imageStartOffset, const std::shared_ptr<IBlockVerifier>& pVerifier, const std::shared_ptr<Logger> pLogger);

    bool Recover(RecoveredList* recoveredList, const ExtentList& missing, const std::vector<Sha256::Hash>& hashes);
private:
    template<typename T>
    class MissingExtentImpl {
    public:
        using ValueType = T;
        using InnerExtentsType = Extents<ValueType>;

        constexpr MissingExtentImpl(ValueType offs, ValueType size, bool isNew) noexcept :
            m_extents(offs, size),
            m_isNew(isNew) {}

        constexpr MissingExtentImpl(const InnerExtentsType& ext, bool isNew) :
            m_extents(ext),
            m_isNew(isNew) {}
        
        [[nodiscard]] constexpr ValueType GetStart() const noexcept { return m_extents.GetStart(); }
        [[nodiscard]] constexpr ValueType GetEnd()   const noexcept { return m_extents.GetEnd(); }
        [[nodiscard]] constexpr ValueType GetSize()  const noexcept { return m_extents.GetSize(); }
        
        [[nodiscard]] constexpr bool Contains(ValueType val) { return m_extents.Contains(val); }

        [[nodiscard]] constexpr auto Extended(ValueType v) const noexcept {
            InnerExtentsType ext = m_extents.Extended(v);
            return MissingExtentImpl<T>(ext, m_isNew);
        }

        [[nodiscard]] constexpr auto Forwarded(ValueType v) const noexcept {
            InnerExtentsType ext = m_extents.Forwarded(v);
            return MissingExtentImpl<T>(ext, m_isNew);
        }

        constexpr void Extend(ValueType v) noexcept { m_extents.Extend(v); }
        constexpr void Forward(ValueType v) noexcept { m_extents.Forward(v); }

        [[nodiscard]] constexpr bool IsNew() const noexcept { return m_isNew; }

        constexpr void ClearNewFlag() noexcept { m_isNew = false; }

        constexpr const auto& GetExtents() const noexcept { return m_extents; }
    private:
        InnerExtentsType m_extents;
        bool m_isNew;
    }; // class MissingExtentImpl

    using MissingExtent = MissingExtentImpl<u64>;

    class FragmentInfo {
    public:
        FragmentInfo(BlockRecoverer* pParent, u64 offset, u64 size, u64 startCluster, const std::vector<std::byte>& startData, const Sha256::Hash& hash, const MissingExtent& postExtent = {0,0,false}, bool isNew = true);

        [[nodiscard]] bool Compare(std::byte* pEndData) const;

        [[nodiscard]] bool IsNew() const noexcept { return m_isNew; }
        void ClearNewFlag() noexcept { m_isNew = false; }

        auto AddPostExtentToMissingList() const;

        [[nodiscard]] bool HasPostExtent()                 const noexcept { return m_postExtent.GetSize() != 0; }
        [[nodiscard]] const MissingExtent& GetPostExtent() const noexcept { return m_postExtent; }

        [[nodiscard]] u64 GetStartCluster()     const noexcept { return m_startCluster; }
        [[nodiscard]] u64 GetBlockSize()        const noexcept { return m_size; }
        [[nodiscard]] u64 GetStartPieceOffset() const noexcept { return m_offset; }
        [[nodiscard]] u64 GetEndPieceOffset()   const noexcept { return m_offset + m_pParent->GetStartPieceSize(); }
    private:
        BlockRecoverer* m_pParent;
        std::vector<std::byte> m_startData;
        u64 m_offset;
        u64 m_size;
        u64 m_startCluster;
        MissingExtent m_postExtent;
        Sha256::Hash m_hash;
        bool m_isNew;
    }; // class FragmentInfo

    using MissingExtentList = std::list<MissingExtent>;

    using FragmentInfoList = std::list<FragmentInfo>;

    struct BlockZeroRecoveryData {
        BlockZeroRecoveryData(u64 startPieceSize, FragmentInfoList::iterator frag);

        std::byte* GetBuffer() { return blkData.data(); }
        u64 GetBufferSize() const { return blkData.size(); }

        std::vector<std::byte> blkData;
        FragmentInfo initialInfo;
        FragmentInfoList::iterator pInfo;
    }; // struct BlockZeroRecoveryData
private:
    [[nodiscard]] bool IsMisaligned() const noexcept { return m_blockOffset != 0; }

    [[nodiscard]] bool IsDone() const noexcept { return m_missing.empty() && m_fragments.empty(); }

    [[nodiscard]] bool IsExpectedNextCluster(u64 v)  const noexcept { return v == m_expectedCluster; }
    [[nodiscard]] bool IsExpectedNextSectAddr(u64 v) const noexcept { return v == m_expectedSecOffs; }

    [[nodiscard]] std::byte* GetWorkBuffer()    noexcept { return m_workBuffer.data(); }
    [[nodiscard]] IDecryptor* GetDecryptor()    const noexcept { return m_pDecryptor; }
    [[nodiscard]] IBlockVerifier* GetVerifier() const noexcept { return m_pVerifier.get(); }
    [[nodiscard]] u64 GetStartPieceSize()       const noexcept { return m_startPieceSize; }
    [[nodiscard]] u64 GetEndPieceSize()         const noexcept { return m_blockSize - m_startPieceSize; }
    [[nodiscard]] u64 GetSectionSize()          const noexcept { return m_sectionSize; }

    [[nodiscard]] bool IsExpectedNextBlock(u64 blockId, u64 secOffs) const;

    [[nodiscard]] const Sha256::Hash GetHashForOffset(u64 offs) const noexcept { return m_hashes[offs / m_blockSize]; }

    int RecoverPass(u64 startHint);

    int AnalyzeBlock(const std::byte* pBlock, u64 blockId);

    int CheckFragments(std::byte* pClusters, u64 clusterId);

    void CreateInitialMissingList(const ExtentList& missing, const std::vector<Sha256::Hash>& hashes);
    void CreateInitialMissingListImpl(const ExtentList& missing);
    void CreateInitialFragmentList(const ExtentList& missing, const std::vector<Sha256::Hash>& hashes);

    void UpdateMissingList();
    void UpdateFragmentList();

    void ExchangeBlockZeroStart();
    void RevertBlockZeroStart();

    template<typename Ext>
    void MigrateExtentToFragmentList(Ext missing);

    void SplitMissingExtent(const MissingExtent& missing);

    template<typename Iter>
    Iter SplitAndRemoveMissingExtent(Iter ext);

    [[nodiscard]] u64 GetRequiredWriteSize(u64 start) const noexcept {
        return std::min(m_alignedBlockSize, m_sectionSize - start);
    }
private:
    IStorage* m_pSectionStorage;
    IStorage* m_pImageStorage;

    IDecryptor* m_pDecryptor;

    std::shared_ptr<IBlockVerifier> m_pVerifier;

    std::vector<std::byte> m_workBuffer;

    u64 m_imageStorageSize;
    u64 m_sectionSize;
    u64 m_blockSize;            // of hash structure
    u64 m_alignedBlockSize;     // aligned to cluster size.
    u64 m_imageStartOffset;

    u64 m_endCluster;
    u64 m_clustersPerBlock;
    u64 m_clustersBetweenBlock;
    u64 m_clusterCount;
    u64 m_blockOffset;

    /* 
     * Offset & size of the starting piece for the next block
     * located in the buffer containing the clusters for the
     * block currently being processed.
     * These only apply / are used when blocks are misaligned
     * from clusters.
     */
    u64 m_startPieceOffs;
    u64 m_startPieceSize;

    std::shared_ptr<Logger> m_pLogger;

    std::unique_ptr<BlockZeroRecoveryData> m_pBlkZeroRec;
    bool m_blk0Reverted;

    // Recover state.
    const Sha256::Hash* m_hashes;
    MissingExtentList m_missing;
    std::list<FragmentInfo> m_fragments;
    RecoveredList m_recovered;
    std::list<Extents<u64>> m_failed;

    RecoveredRecord m_curRecExt;
    u64 m_expectedCluster;
    u64 m_expectedSecOffs;
    std::vector<std::byte> m_expectedBegin;
    bool m_inRecExt;
};
