#pragma once
#include <array>
#include "Aes.h"
#include "Sha256.h"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <ranges>
#include <utility>

constexpr inline size_t NCA_BLOCK_SIZE = 0x200;

// TODO: move me
inline void PrintKey(const char* name, const void* key, size_t keySize, int indentLevel = 0) {
    auto indent = [indentLevel]() {
        for (int i = 0; i < indentLevel; i++)
            std::putc('\t', stdout);
    };
    
    indent();
    std::printf("%s:\n", name);
    for (size_t i = 0; i < keySize / 16; i++) {
        indent();
        std::putc('\t', stdout);
        for (size_t j = 0; j < std::min(keySize - i * 16, 16ul); j++) {
            std::printf("%02X ", static_cast<const uint8_t*>(key)[i * 16 + j]);
        }
        std::putc('\n', stdout);
    }
}

constexpr const inline uint8_t g_HeaderKey[2][2][16] = {
	{
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // retail
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	},
	{
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // dev
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	}
};

#pragma pack(push,1)

struct FsEntry {
    uint32_t startBlock;
    uint32_t endBlock;
    uint8_t reserved_x08[8];
}; // struct FsEntry
static_assert(sizeof(FsEntry) == 0x10);

struct NcaHeader {
    static constexpr char Magic[3] = { 'N', 'C', 'A' }; 

    static constexpr size_t MaxFilesystemCount = 4;

	uint8_t sig1[0x100];
	uint8_t sig2[0x100];
	char magic[4];
	uint8_t distType;
	uint8_t contentType;
	uint8_t keygenOld;
	uint8_t kakIdx;
	uint64_t contentSize;
	uint64_t programId;
	uint32_t contentIdx;
	uint32_t sdkVer;
	uint8_t keygen;
	uint8_t sigKeyRev;
	uint8_t reserved[0xE];
	uint8_t rightsId[0x10];
	FsEntry fsEntries[4];
    uint8_t sectionHash[4][0x20];
	uint8_t keyArea[4][0x10];
	uint8_t padding[0xC0];

    static constexpr const char* ContentTypeStrings[] = {
    	"Program",
    	"Meta",
    	"Control",
    	"Manuel",
    	"Data",
    	"PublicData",
    	"Ivalid",
    };
    constexpr const char* GetContentTypeString() const noexcept {
        if (contentType > 6) return "Invalid";
        return ContentTypeStrings[contentType];
    }

    constexpr int GetKeyGeneration() const {
        if (keygen == 0) {
            if (keygenOld == 2)
                return keygenOld - 1;
            return 0;
        } else {
            return keygen - 1;
        }
    }

    void Print() const;

    constexpr bool IsMagicValid() const noexcept {
        if (!std::ranges::equal(Magic, std::ranges::subrange(magic, magic+3)))
            return false;

        /* Check the version number. */
        if (magic[3] > '4' || magic[3] < '0')
            return false;

        return true;
    }

    void GetDecryptedAesCtrKey(void* pDst, bool isDev) const;
};
constexpr const inline size_t g_HeaderSize = sizeof(NcaHeader);
static_assert(g_HeaderSize == 0x400);

inline bool ValidateNcaHeader(NcaHeader* header) {
	/* TODO: maybe validate rsa signature? */
	/* Check that magic is valid. */
    if (!header->IsMagicValid())
        return false;

	/* Basic size sanity check. */
	if (header->contentSize > 0xFFFFFFFFFF) {
		return false;
	}

	/* Validate content type. */
	if (header->contentType > 5) {
		return false;
	}

	/* Valid keygen. */
	if (header->keygenOld > 2) {
		return false;
	}

	return true;
}

struct FsHeader {
    enum class FsType : uint8_t {
        RomFS       = 0,
        PartitionFS = 1,
        Count,
    }; // enum class FsType

    enum class HashType : uint8_t {
        Auto                            = 0,
        None                            = 1,
        HierarchicalSha256Hash          = 2, // usually used on exefs
        HierarchicalIntegrityHash       = 3, // IVFS, usually used on romfs
        AutoSha3                        = 4,
        HierarchicalSha3256Hash         = 5,
        HierarchicalIntegritySha3Hash   = 6,
        Count,
    }; // enum class HashType

    enum class EncryptionType : uint8_t {
        Auto                    = 0,
        None                    = 1,
        AesXts                  = 2,
        AesCtr                  = 3,
        AesCtrEx                = 4,
        AesCtrSkipLayerHash     = 5,
        AesCtrExSkipLayerHash   = 6,
        Count,
    }; // enum class EncryptionType

    enum class MetaDataHashType : uint8_t {
        None                    = 0,
        HierarchicalIntegrity   = 1,
        Count,
    }; // enum class MetaDataHashType

    struct HierarchicalSha256Data {
        Sha256::Hash masterHash;
        uint32_t blockSize;
        uint32_t layerCount;

        struct LayerRegion {
            uint64_t offset;
            uint64_t size;
        };
        std::array<LayerRegion, 5> region;
        static_assert(sizeof(LayerRegion) == 0x10);

        uint8_t reserved_x78[0x80];
    }; // struct HierarchicalSha256Data
    static_assert(sizeof(HierarchicalSha256Data) == 0xF8);

    struct IntegrityMetaInfo {
        static constexpr char Magic[4] = { 'I', 'V', 'F', 'C' };

        static constexpr size_t NumberOfLevels = 6;

        char magic[4];
        uint32_t version;
        uint32_t masterHashSize;

        struct InfoLevelHash {
            uint32_t maxLayers;

            struct LevelInfo {
                int64_t offset;
                int64_t size;
                int32_t blockOrder; // order as in power/exponent
                uint8_t reserved_x14[4];
            };
            std::array<LevelInfo, 6> levelInfo;
            static_assert(sizeof(LevelInfo) == 0x18);
            static_assert(sizeof(levelInfo) == 0x90);

            uint8_t signatureSalt[0x20];
        } infoLevelHash;
        static_assert(sizeof(InfoLevelHash) == 0xB4);

        Sha256::Hash masterHash;
        uint8_t reserved_xE0[0x18];

        constexpr bool IsMagicValid() const noexcept {
            return std::ranges::equal(Magic, magic);
        }

        void Print() const;
    }; // struct IntegrityMetaInfo
    static_assert(sizeof(IntegrityMetaInfo) == 0xF8);

    uint16_t version;
    FsType fsType;
    HashType hashType;
    EncryptionType encryptionType;
    MetaDataHashType metaHashType;
    uint8_t reserved_x6[2];

    union {
        HierarchicalSha256Data hierarchicalSha256Data;
        IntegrityMetaInfo integrityMetaInfo;
    };

    uint8_t patchInfo[0x40]; // TODO?
    uint32_t generation;
    uint32_t secureValue;
    uint8_t sparseInfo[0x30]; // TODO?
    uint8_t compressionInfo[0x28]; // TODO?
    uint8_t metaHashInfo[0x30]; // TODO?
    uint8_t reserved_x1D0[0x30];

    constexpr uint64_t GetAesCtrUpperIv() const {
        return generation | (uint64_t(secureValue) << 32);
    }

    void GetIv(void* pDst, uint64_t offset) const;
    
    static constexpr const char* FsTypeString[] = {
        "Romfs",
        "PartitionFS"
    };
    constexpr const char* GetFsTypeString() const {
        if (std::to_underlying(fsType) >= std::to_underlying(FsType::Count))
            return "Invalid";
        return FsTypeString[std::to_underlying(fsType)];
    }

    static constexpr const char* HashTypeStrings[] = {
        "Auto",
        "None",
        "HierarchicalSha256Hash",
        "HierarchicalIntegrityHash",
        "AutoSha3",
        "HierarchicalSha3256Hash",
        "HierarchicalIntegritySha3Hash"
    };
    constexpr const char* GetHashTypeString() const {
        if (std::to_underlying(fsType) >= std::to_underlying(HashType::Count))
            return "Invalid";
        return HashTypeStrings[std::to_underlying(hashType)];
    }

    static constexpr const char* EncryptionTypeStrings[] = {
        "Auto",
        "None",
        "AesXts",
        "AesCtr",
        "AesCtxEx",
        "AesCtrSkipLayerHash",
        "AesCtrExSkipLayerHash"
    };
    constexpr const char* GetEncryptionTypeString() const {
        if (std::to_underlying(encryptionType) >= std::to_underlying(EncryptionType::Count))
            return "Invalid";
        return EncryptionTypeStrings[std::to_underlying(encryptionType)];
    }

    void Print() const;

}; // struct FsHeader
static_assert(sizeof(FsHeader) == 0x200);

class NcaReader {
public:
    static constexpr size_t MaxFsCount = 4;

    constexpr const NcaHeader& GetMainHeader() const { return m_mainHeader; }

    constexpr const FsHeader& GetFsHeader(int idx) const {
        assert(idx >= 0 && idx < MaxFsCount);
        return m_fsHeaders[idx];
    }



private:
    NcaHeader m_mainHeader;
    FsHeader m_fsHeaders[4];
}; // class NcaReader

#pragma pack(pop)
