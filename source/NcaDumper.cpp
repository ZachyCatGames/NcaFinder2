#include <cassert>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#include <cerrno>
#include <argparse/argparse.hpp>
#include "FileStorage.h"
#include <print>
#include "NcaProcessor.h"
#include "StdLogger.h"

/*
 * This tool attempts data recovery on a per-NCA basis.
 *
 * Recovery is done in the following steps:
 * 1) It'll first copy sequential bytes from the backing image file to
 *    the output NCA file directly without alterations, the number of bytes is
 *    the amount specified by the NCA's header.
 * 2) It'll scan over each NCA section for corrupt blocks, then attempt to find
 *    those blocks in the backing image through a bruteforce search using the blocks'
 *    hashes provided by the section's hash structure (IVFC or HierarchicalSha256).
 *    Successfully recovered blocks will be written to the output NCA file.
 * 
 * For IVFC sections the process invovles:
 * 1) Validating level 0 of the merkle tree using the master hash.
 *    If level 0 is corrupt, recovery will be attemped as described above.
 * 2) Each level will be scanned for validatity using the previous level (start with level 1).
 *    If a level is found to be corrupt, recovery will be attempted on that level immediately
 *    since verifying higher levels requires the lower levels to be intact.
 */


int Test() {
    auto inputFile = std::make_shared<std::fstream>("../test files/26b9350ff63d74beba14502ce7a9d551.nca", std::ios::in | std::ios::binary);
    if (inputFile->bad()) {
        std::printf("Failed to open NCA: %s\n", "TEST FILE\n");
        return -1;
    }

    const char* imagePath = "../test files/arms-program-fragmented.nca";
    FILE* imageFile = std::fopen(imagePath, "rb");
    if (imageFile == nullptr) {
        std::printf("Failed to open image file '%s'\n", imagePath);
        return -1;
    }

    auto imageStorage = std::make_shared<FileStorage>(imageFile);

    NcaProcessor ncaProc(imageStorage, 0xc000, true, StdoutLogger);
    ncaProc.CopyContiguous();
    ncaProc.Process();

    return 0;
}

int main(int argc, char** argv) {
    argparse::ArgumentParser program("NcaDumper");
    program.add_argument("-r", "--restrict")
           .help("Restricts which NCAs from provided list are dumped. Takes a comman-separated list of numbers and/or ranges (x-y) that specify line numbers.");
    program.add_argument("-d", "--development")
           .help("Use development unit keys")
           .flag();
    program.add_argument("-c", "--nca-list-path")
           .help("Path to a csv NCA listing produced by NcaFinder")
           .required();
    program.add_argument("-i", "--image-path")
           .help("Path to a disk image that NCA data will be extracted from")
           .required();
    program.add_argument("--no-defrag")
           .help("Disables fragmentation handling. Contiguous bytes will be copied from the image with no further handling.")
           .flag();

    try {
        program.parse_args(argc, argv);
    }
    catch (std::exception& excpt) {
        std::cerr << excpt.what() << '\n' << program;
        return -1;
    }

    //g_LogLevel = LogLevel_Verbose;
    const bool useDevKeys    = program["--development"] == true;
    const bool disableDefrag = program["--no-defrag"] == true;
    std::string ncaListPath  = program.get<std::string>("--nca-list-path");
    std::string imagePath    = program.get<std::string>("--image-path");

    std::ifstream ncaList(ncaListPath);
    if (ncaList.bad()) {
        std::print("Failed to open nca listing '{}'\n", ncaListPath.c_str());
        return -1;
    }

    FILE* imageFile = std::fopen(imagePath.c_str(), "rb");
    if (imageFile == nullptr) {
        std::print("Failed to open image file '{}'\n", imagePath.c_str());
        return -1;
    }

    auto imageStorage = std::make_shared<FileStorage>(imageFile);

    int lineNum = 0;
    while (!ncaList.eof()) {
        std::string line;
        ncaList >> line;

        if (line == "")
            continue;

        //std::cout << line << '\n';

        std::stringstream ss(line);

        /* NCA magic / version. */
        std::string magic, tmp;
        std::getline(ss, magic, ',');
        if (ss.eof()) {
            std::print("Line {} is incomplete, skipping.\n", lineNum);
            //continue;;
        }

        uint64_t programId, offset, size;
        std::getline(ss, tmp, ',');
        try {
            programId = std::stoll(tmp, nullptr, 16);
        } catch (std::exception& excpt) {
            std::print("ProgramID on line {} is not a number, skipping.\n", lineNum);
            continue;
        }

        std::getline(ss, tmp, ',');
        try {
            offset = std::stoll(tmp, nullptr, 16);
        } catch (std::exception&) {
            std::print("Offset on line {} is not a number, skipping.\n", lineNum);
            continue;
        }

        std::getline(ss, tmp);
        try {
            size = std::stoll(tmp, nullptr, 16);
        } catch (std::exception&) {
            std::print("Size on line {} is not a number, skipping.\n", lineNum);
            continue;
        }

        std::print("Processing {} ({:016x}):\n", magic.c_str(), programId);
        std::print("\tOffset: 0x{:x}\n", offset);
        std::print("\tSize:   0x{:x}\n", size);

        /* Process the NCA. */
        NcaProcessor ncaProc(imageStorage, offset, useDevKeys, StdoutLogger);
        ncaProc.CopyContiguous();
        if (!disableDefrag)
            ncaProc.Process();
    }

    //IvfcSectionProcessor proc(imageStorage, outStorage, &mainHeader.fsEntries[1], &fsHeaders[1], sec0key, sec0ctr);
    //proc.Process();

    //testOut.write(reinterpret_cast<const char*>(&mainHeader), sizeof(mainHeader));
    //testOut.write(reinterpret_cast<const char*>(fsHeaders), sizeof(fsHeaders));

    return 0;
}
