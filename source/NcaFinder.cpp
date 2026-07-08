#include <iostream>
#include <print>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mutex>
#include <barrier>
#include <condition_variable>
#include <thread>
#include <argparse/argparse.hpp>
#include "Aes.h"
#include "NcaHeaders.h"

static constexpr size_t DEFAULT_FS_SECTOR_SIZE = 1024 * 4;
static constexpr size_t DEFAULT_FS_SECTORS_PER_READ = 1024;

static bool g_debugLog = false;

std::mutex g_debugLogMutex;

template<typename... Args>
void DebugLog(const char* fmt, Args&&... args) {
    if (g_debugLog) {
        std::scoped_lock lock(g_debugLogMutex);
        std::vprint_nonunicode(stderr, fmt, std::make_format_args(std::forward<Args>(args)...));
    }
}

bool useDevKeys;

uint8_t* g_primaryBuffer;
uint8_t* g_secondaryBuffer;

size_t g_fsSectorSize;
size_t g_currentOffset, g_currentSectorCount;

std::barrier g_syncBarrier(2);

bool g_scannerShouldAwaken;
std::condition_variable g_conditionVariable;
std::mutex g_condVarMutex;

void ReadWorker(FILE* input_file, size_t input_size, size_t max_chunk_size) {
    for (size_t offset = 0; offset < input_size; offset += max_chunk_size) {
        /* Read a chunk into the secondary buffer. */
        size_t count = std::min(input_size - offset, max_chunk_size);
        size_t sector_count = (count + g_fsSectorSize - 1) / g_fsSectorSize;
        DebugLog("Reader: Reading 0x{:X} containing 0x{:X} sectors\n", count, sector_count);
        std::fread(g_secondaryBuffer, 1, count, input_file);

        /* Wait until the scanning worker finishes. */
        DebugLog("Reader: Read worker done, waiting for scanning worker.\n");
        g_syncBarrier.arrive_and_wait();

        /* Set the current offset to offset. */
        g_currentOffset = offset;
        g_currentSectorCount = sector_count;

        /* Swap the primary and secondary buffers. */
        std::swap(g_primaryBuffer, g_secondaryBuffer);

        /* Awaken the scan worker. */
        DebugLog("Reader: Awakening scan thread.\n");
        {
            std::unique_lock lock(g_condVarMutex);
            g_scannerShouldAwaken = true;
        }
        g_conditionVariable.notify_all();
    }

    /* Once done, wait for the scan thread to finish one last time + tell it we're done. */
    DebugLog("Reader: And so our run has concluded... waiting for scan thread.\n");
    g_syncBarrier.arrive_and_wait();

    /* We'll use sector_count == 0 as a completion indicator. */
    g_currentSectorCount = 0;
    DebugLog("Reader: Awakening scan thread one last time.\n");
    {
        std::unique_lock lock(g_condVarMutex);
        g_scannerShouldAwaken = true;
    }
    g_conditionVariable.notify_all();

    DebugLog("Reader: Returning.\n");
}

void ScanWorker(FILE* csv_file) {
    /* Setup decryptor. */
    NintendoAesXtsDecryptor ctx(GetNcaHeaderKey(useDevKeys), 0x20, 0x200);

    while (true) {
        /* Wait for the read worker to finish. */
        DebugLog("Scanner: Waiting for reader to finish.\n");
        g_syncBarrier.arrive_and_wait();
    
        /* Wait for reader thread to awaken us. */
        DebugLog("Scanner: Waiting for reader to awaken us.\n");
        {
            std::unique_lock lock(g_condVarMutex);
            g_conditionVariable.wait(lock, []() { return g_scannerShouldAwaken; });
            g_scannerShouldAwaken = false;
        }
        DebugLog("Scanner: Awakened. Scanning 0x{:X} sectors.\n", g_currentSectorCount);

        /* Check if we should be done. */
        if (g_currentSectorCount == 0) {
            DebugLog("Scanner: We're done here.\n");
            return;
        }

        for (size_t sector = 0; sector < g_currentSectorCount; sector++) {
            /* Decrypt the current sector. */
            NcaHeader nca_header;
            //DebugLog("Scanner: Decrypting data at offset 0x%lx\n", g_currentOffset + sector * FS_SECTOR_SIZE);
            ctx.Decrypt(&nca_header, g_primaryBuffer + sector * g_fsSectorSize, sizeof(nca_header), 0);

            /* Does it kinda look like an NCA header? */
            if (ValidateNcaHeader(&nca_header)) {
        	    /* Log that we found an nca. */
                size_t ncaOffset = g_currentOffset + sector * g_fsSectorSize;
        	    std::print("Found: {:<11s} NCA{} with ProgramId {:016X} with size 0x{:012X} at 0x{:016X}!\n", 
                            nca_header.GetContentTypeString(), 
                            nca_header.magic[3], 
                            nca_header.programId, 
                            nca_header.contentSize, 
                            ncaOffset);

                /* Export to the csv. */
                std::print(csv_file, "{},0x{:016X},0x{:016X},0x{:016X}\n",
                    nca_header.magic,
                    nca_header.programId,
                    ncaOffset,
                    nca_header.contentSize);
            }
        }
    }
}

int main(int argc, char** argv) {
    const unsigned char xts_key[0x20] = {0};
    unsigned char xts_iv[0x10] = {0};

    /* Do argument stuffs. */
    argparse::ArgumentParser program("NcaFinder");
    program.add_argument("-v", "--verbose").flag();
    program.add_argument("-i", "--in-file")
           .help("specify input file to scan")
           .required();
    program.add_argument("-o", "--out-csv")
           .help("specify output csv path")
           .required();
    program.add_argument("-d", "--development")
           .help("use development unit keys")
           .flag();
    program.add_argument("-s", "--sector-size")
           .help("specify filesystem sector size")
           .default_value(DEFAULT_FS_SECTOR_SIZE)
           .scan<'x', size_t>();
    program.add_argument("-c", "--sectors-per-read")
           .help("specify number of filesystem sectors to process at a time")
           .default_value(DEFAULT_FS_SECTORS_PER_READ)
           .scan<'x', size_t>();

    program.add_description(
        "Scan a file for NCA headers and output the results to a CSV file.\n"
        "Author: ZachyCatGames"
    );

    try {
        program.parse_args(argc, argv);
    }
    catch (std::exception& excpt) {
        std::cerr << excpt.what() << '\n';
        std::cerr << program;
        return -1;
    }

    /* Parse inputs. */
    g_debugLog = program["--verbose"] == true;
    g_fsSectorSize = program.get<size_t>("--sector-size");
    size_t sectorsPerRead = program.get<size_t>("--sectors-per-read");
    useDevKeys = program["--development"] == true;
    auto csvPath = program.get<std::string>("--out-csv");
    auto inFilePath = program.get<std::string>("--in-file");

    /* Open our output csv file for writing. */
    FILE* csv_out = std::fopen(csvPath.c_str(), "w");
    if (!csv_out) {
        std::print("Failed to open output csv file \'{}\'. Quitting.", csvPath.c_str());
        return -1;
    }

    /* Open the input file. */
    FILE* file = std::fopen(inFilePath.c_str(), "rb");
    if (!file) {
        std::print("Failed to open input file \'{}\'. Quitting.\n", inFilePath.c_str());
        return -1;
    }

    /* Retreive input file size. */
    std::fseek(file, 0, SEEK_END);
    size_t input_size = std::ftell(file);
    std::fseek(file, 0, SEEK_SET);
    std::print("Input file size: 0x{:X}\n", input_size);

    /* Setup the two buffers. */
    size_t max_chunk_size = g_fsSectorSize * sectorsPerRead;
    std::vector<uint8_t> read_buffer(max_chunk_size * 2);
    g_primaryBuffer = read_buffer.data();
    g_secondaryBuffer = g_primaryBuffer + max_chunk_size;

    std::print(csv_out, "magic,program_id,offset,size\n");

    /* Start the reader and scanner workers. */
    std::jthread readWorker(&ReadWorker, file, input_size, max_chunk_size);
    std::jthread scanWorker(&ScanWorker, csv_out);

    return 0;
}
