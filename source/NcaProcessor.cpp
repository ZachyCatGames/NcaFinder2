#include "NcaProcessor.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <numeric>
#include <print>
#include <vector>
#include "Aes.h"
#include "AesCtrDecryptor.h"
#include "AesCtrStorage.h"
#include "Common.h"
#include "FileStorage.h"
#include "HISha256Processor.h"
#include "IDecryptor.h"
#include "IvfcProcessor.h"
#include "NcaHeaders.h"
#include "PlaintextDecryptor.h"
#include "SubStorage.h"
#include "StdLogger.h"

namespace {

void OutputRecoveredExtentsInfo(FILE* outFile, const RecoveredList& recList) {
    std::print(outFile, "nca_offset,image_offset,size\n");
    for (const auto& rec : recList) {
        std::print(outFile, "0x{:X},0x{:X},0x{:X}\n", rec.GetSectionStart(), rec.GetImageStart(), rec.GetSize());
    }
}

} // namespace

void why() {
    std::ofstream test("1009b500007c000/c000_Program.nca");
    test.seekp(0x20000);
}

NcaProcessor::NcaProcessor(std::shared_ptr<IStorage> pImageStorage, uint64_t ncaOffset, bool isDev, const std::shared_ptr<Logger>& pLogger) :
    m_pImageStorage(std::move(pImageStorage)),
    m_ncaOffset(ncaOffset),
    m_plaintext(true)
{
    /* Add passed logger to the multilogger. */
    m_pLogger = std::make_shared<MultiLogger>();
    m_pLogger->AddLogger(pLogger);

    /* Read and dcrypt headers. */
    NintendoAesXtsDecryptor headerDec(GetNcaHeaderKey(isDev), 0x20, 0x200);
    int fsHeaderCount = 0;
    {
        /* Read in the main header. */
        ErrorCode err = m_pImageStorage->Read(&m_mainHeader, ncaOffset, sizeof(m_mainHeader));
        if (err != ErrorCode::Success) {
            throw DumperException("Failed to read NCA header: {}", ErrorCodeToString(err));
        }
        //PrintKey("Cringe", &m_mainHeader, 0x200);

        /* Decrypt the main header. */
        if (!ValidateNcaHeader(&m_mainHeader)) {
            headerDec.Decrypt(&m_mainHeader, &m_mainHeader, sizeof(m_mainHeader));
            if (!ValidateNcaHeader(&m_mainHeader)) {
                throw DumperException("Invalid NCA header\n");
            }

            m_plaintext = false;
        }

        /* Read in fs headers until we reach an invalid entry. */
        int idx = 0;
        while (fsHeaderCount < 4 && m_mainHeader.fsEntries[fsHeaderCount].endBlock != 0) {
            m_pLogger->print("Reading fsHeader {}\n", fsHeaderCount);

            /* Read a header. */
            err = m_pImageStorage->Read(&m_fsHeaders[fsHeaderCount], ncaOffset + fsHeaderCount * 0x200 + 0x400, sizeof(m_fsHeaders[0]));
            if (err != ErrorCode::Success) {
                throw DumperException("Failed to read section header: {}", ErrorCodeToString(err));
            }

            if (!m_plaintext) {
                /* Reset decryptor sector to 0 if this is an NCA1 or NCA2. */
                if (m_mainHeader.magic[3] <= '2') {
                    headerDec.SetCurrentSector(0);
                }

                /* Decrypt it. */
                headerDec.Decrypt(&m_fsHeaders[fsHeaderCount], &m_fsHeaders[fsHeaderCount], sizeof(m_fsHeaders[0]));
                fsHeaderCount++;
            }
        }
    }

    m_fsHeaderCount = fsHeaderCount;
    m_pLogger->print("Section Counter: {}\n", m_fsHeaderCount);

    /* Printout the headers. */
    //m_mainHeader.Print();
    for (int i = 0; i < m_fsHeaderCount; i++) {
        //std::printf("\nSection Header %d:\n", i);
        //m_fsHeaders[i].Print();
    }

    /* Try creating the output directory. */
    {
        std::string outDir = std::format("{:016x}", m_mainHeader.programId);
        std::filesystem::create_directory(outDir);
    }

    /* Open the log file. */
    {
        std::string logPath = this->CreateOutFilePath(".txt");
        FILE* logFile = std::fopen(logPath.c_str(), "w");
        if (logFile == nullptr) {
            throw DumperException("Failed to open log file '{}'", logPath);
        }
        m_pLogger->AddLogger(std::make_shared<StdLogger>(logFile, true));
    }

    /* Derive the AES-CTR section key. */
    m_mainHeader.GetDecryptedAesCtrKey(m_aesCtrKey, isDev);

    /* Open the NCA file. */
    {
        std::string ncaPath = this->CreateOutFilePath(".nca");
        m_ncaFile = std::fopen(ncaPath.c_str(), "w+b");
        if (m_ncaFile == nullptr) {
            throw DumperException("Failed to create NCA file '{}'", ncaPath);
        }
        m_pNcaStorage = std::make_shared<FileStorage>(m_ncaFile);
    }
}

NcaProcessor::~NcaProcessor() {
    std::fclose(m_ncaFile);
}

void NcaProcessor::CopyContiguous() {
    /* Copy contiguous nca data from the image to to the output file. */
    u64 imageOffs = m_ncaOffset;
    u64 ncaOffs = 0;
    std::vector<std::byte> buffer(0x400000);
    while (imageOffs < m_mainHeader.contentSize + m_ncaOffset) {
        const u64 copyAmount = std::min(buffer.size(), m_mainHeader.contentSize - ncaOffs);
        m_pImageStorage->Read(buffer.data(), imageOffs, copyAmount);
        m_pNcaStorage->Write(buffer.data(), ncaOffs, copyAmount);

        imageOffs += copyAmount;
        ncaOffs += copyAmount;
    }
}

void NcaProcessor::Process() {
    /* Process sections by start offset. */
    std::vector<int> order(m_fsHeaderCount);
    std::ranges::iota(order, 0);
    std::ranges::sort(order, [&](int lhs, int rhs) {
        return m_mainHeader.fsEntries[lhs].startBlock < m_mainHeader.fsEntries[rhs].startBlock;
    });

    /* Process each section. */
    u64 recStartOffset = m_ncaOffset + m_mainHeader.fsEntries[order[0]].startBlock * NCA_BLOCK_SIZE;
    for (int i : order) {
        m_pLogger->print("Processing section {}\n", i);

        FsHeader& fsHeader = m_fsHeaders[i];
        FsEntry& fsEntry   = m_mainHeader.fsEntries[i];

        SectionInfoReader infoReader(&m_mainHeader.fsEntries[i], &m_fsHeaders[i]);
        const u64 sectionStart = infoReader.GetStartOffset();
        const u64 sectionSize  = infoReader.GetSize();

        m_pLogger->print("start: {:x}; size: {:x}\n", sectionStart, sectionSize);

        /* Setup section sub storage. */
        auto pSectRawStorage = std::make_shared<SubStorage>(m_pNcaStorage, sectionStart, sectionSize);

        /* Require sections to start and end at multiples of FAT cluster size. */
        if (sectionStart % CLUSTER_SIZE) {
            m_pLogger->print("Sections must start at multiples of the FAT cluster size. Aborting.\n");
            //continue;
        } else if (sectionSize % CLUSTER_SIZE) {
            m_pLogger->print("Section sizes must be multiples of the FAT cluster size. Aborting.\n");
            //continue;
        }

        /* Setup section block decryptor. */
        std::unique_ptr<IDecryptor> pSecBlockDec;
        std::shared_ptr<IStorage> pSectDecStorage;
        std::byte iv[0x10];
        switch(infoReader.GetEncryptionType()) {
        case FsHeader::EncryptionType::None:
            pSecBlockDec = std::make_unique<PlaintextDecryptor>();
            pSectDecStorage = pSectRawStorage;
            break;
        case FsHeader::EncryptionType::AesCtr:
            fsHeader.GetIv(iv, static_cast<u64>(m_mainHeader.fsEntries[i].startBlock) * NCA_BLOCK_SIZE);
            pSecBlockDec = std::make_unique<AesCtrDecryptor>(m_aesCtrKey, sizeof(m_aesCtrKey), iv, sizeof(iv));
            
            pSectDecStorage = std::make_shared<AesCtrStorage>(pSectRawStorage, m_aesCtrKey, sizeof(m_aesCtrKey), iv, sizeof(iv));
            break;
        default:
            m_pLogger->print("Unsupported encryption type.\n");
            continue;
        }

        /* Process section. */

        RecoveredList rec;
        bool result;
        try {
            auto pProcessor = this->CreateSectionProcessor(infoReader, std::move(pSectRawStorage), std::move(pSectDecStorage), std::move(pSecBlockDec));
            result = pProcessor->Process(&rec, recStartOffset);
        } catch(std::exception& excpt) {
            m_pLogger->print("{}\n", excpt.what());
            result = false;
        }

        if (result) {
            m_pLogger->print("Successfully recovered section {}\n", i);
        } else {
            m_pLogger->print("Failed to fully recover section {}\n", i);
        }

        /* Update the main recovered list. */
        m_recovered.splice(m_recovered.cend(), std::move(rec));

        m_pLogger->print("Section {} end.\n", i);
    }

    /* Coalesce the recovered list (it should already be sorted). */
    m_recovered.coalesce();

    /* Output info on the recovered extents. */
    {
        std::string recInfoPath = this->CreateOutFilePath("_recovered.csv");
        FILE* recInfoFile = std::fopen(recInfoPath.c_str(), "w");
        OutputRecoveredExtentsInfo(recInfoFile, m_recovered);
        std::fclose(recInfoFile);
    }
}

std::unique_ptr<ISectionProcessor> NcaProcessor::CreateSectionProcessor(SectionInfoReader infoReader, std::shared_ptr<IStorage> pRawSect, std::shared_ptr<IStorage> pDecSect, std::unique_ptr<IDecryptor>&& pDecryptor) {
    std::unique_ptr<ISectionProcessor> pProcessor = nullptr;
    switch(infoReader.GetHashType()) {
    case FsHeader::HashType::HierarchicalSha256Hash:
        pProcessor = std::make_unique<HISha256Processor>(this, infoReader, m_pImageStorage, std::move(pRawSect), std::move(pDecSect), std::move(pDecryptor), m_pLogger);
        break;
    case FsHeader::HashType::HierarchicalIntegrityHash:
        pProcessor = std::make_unique<IvfcSectionProcessor>(this, infoReader, m_pImageStorage, std::move(pRawSect), std::move(pDecSect), std::move(pDecryptor), m_pLogger);
        break;
    default:
        break;
    }

    return pProcessor;
}

std::string NcaProcessor::CreateOutFilePath(std::string_view extension) {
    return std::format("{:016x}/{:x}_{}{}", m_mainHeader.programId, m_ncaOffset, m_mainHeader.GetContentTypeString(), extension);
}
