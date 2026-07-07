# NcaFinder2
A data recovery tool for Nintendo Switch NCA content that can deal with fragmentation.

## Building
This uses cmake for building, I've only tested it on Linux with g++.
I made an attempt at Windows support but it probably doesn't work.
It also depends on mbedtls and argparse but both are automagically pulled by cmake.
```
git clone https://github.com/ZachyCatGames/NcaFinder2
cd NcaFinder2
mkdir build && cd build
CMAKE_BUILD_TYPE=Release cmake ..
cmake --build . --parallel
```

## Using
NcaFinder2 is split into two tools.
`NcaFinder` searches an image for NCA headers and exports the results to a csv for use with `NcaDumper` (or other stuff).
```
Usage: NcaFinder [--help] [--version] [--verbose] --in-file VAR --out-csv VAR [--development] [--sector-size VAR] [--sectors-per-read VAR]

Scan a file for NCA headers and output the results to a CSV file.
Author: ZachyCatGames

Optional arguments:
  -h, --help              shows help message and exits 
  -v, --version           prints version information and exits 
  -v, --verbose           
  -i, --in-file           specify input file to scan [required]
  -o, --out-csv           specify output csv path [required]
  -d, --development       use development unit keys 
  -s, --sector-size       specify filesystem sector size [nargs=0..1] [default: 4096]
  -c, --sectors-per-read  specify number of filesystem sectors to process at a time [nargs=0..1] [default: 1024]
```
`NcaDumper` pulls NCAs from an image using the info in a csv produced by `NcaFinder` and attempts to repair any fragments.
```
Usage: NcaDumper [--help] [--version] [--restrict VAR] [--development] --nca-list-path VAR --image-path VAR [--no-defrag]

Optional arguments:
  -h, --help           shows help message and exits 
  -v, --version        prints version information and exits 
  -r, --restrict       Restricts which NCAs from provided list are dumped. Takes a comman-separated list of numbers and/or ranges (x-y) that specify line numbers. 
  -d, --development    Use development unit keys 
  -c, --nca-list-path  Path to a csv NCA listing produced by NcaFinder [required]
  -i, --image-path     Path to a disk image that NCA data will be extracted from [required]
  --no-defrag          Disables fragmentation handling. Contiguous bytes will be copied from the image with no further handling. 
```
