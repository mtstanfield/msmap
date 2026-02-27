# Modern C++ Best Practices App

A high-safety, high-performance, secure C++ application built following the guidelines and techniques from [cppbestpractices](https://github.com/cpp-best-practices/cppbestpractices).

## Features
- Modern C++ (C++20/23)
- Safety: Guideline Support Library (GSL), contracts, static analysis (clang-tidy)
- Performance: Optimized builds, sanitizers (ASan/UBSan/TSan)
- Security: Fuzzing, secure coding practices
- Build: CMake + Ninja + Clang
- Dependencies: CPM (CMake Package Manager)
- Testing: Catch2, fuzzing with libFuzzer

## Development Environment
Uses Ubuntu 24.04 Docker container for consistency (Windows host).

### Prerequisites
- Docker

### Build Dev Image
```bash
docker build -t cpp-dev .
```

### Run Container
```bash
docker run -it --rm -v "%cd%:/workspace" -w /workspace cpp-dev
```
(Use `%cd%` on Windows CMD; `${PWD}` on Unix shells.)

### Inside Container
```bash
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_COMPILER=clang++-18
ninja
```

## Project Structure
```
.
├── CMakeLists.txt
├── src/
├── include/
├── tests/
├── docs/
├── .gitignore
├── Dockerfile
└── README.md
```

## Commits
Incremental commits with prompts for review/rollback.

## Best Practices Applied
- See linked repo for details: GSL, expected/span/unexpected, contracts, etc.