cmake_minimum_required(VERSION 3.29)

project(msmap
    VERSION 0.1.0
    DESCRIPTION "Mikrotik Firewall Log Viewer"
    LANGUAGES CXX)

# ── C++ Standard ───────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)           # -std=c++23, not -std=gnu++23

# Always emit compile_commands.json (required by clang-tidy and editor tooling)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Options ────────────────────────────────────────────────────────────────
option(MSMAP_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(MSMAP_ENABLE_SANITIZERS  "Enable ASan + UBSan"               OFF)
option(MSMAP_ENABLE_CLANG_TIDY  "Run clang-tidy during build"       OFF)
option(MSMAP_ENABLE_CPPCHECK    "Run cppcheck during build"         OFF)
# Prefer .a over .so for app libraries. Set ON in release/distroless builds.
option(MSMAP_LINK_STATIC        "Link app libraries statically"     OFF)
# Build Catch2 unit tests. Default ON for Debug, OFF for Release.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    option(MSMAP_ENABLE_TESTS "Build unit tests" OFF)
else()
    option(MSMAP_ENABLE_TESTS "Build unit tests" ON)
endif()

# ── CMake modules ──────────────────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)
include(StaticAnalyzers)

# ── Dependencies ───────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

if(MSMAP_LINK_STATIC)
    pkg_check_modules(MICROHTTPD REQUIRED STATIC IMPORTED_TARGET libmicrohttpd)
    pkg_check_modules(SQLITE3    REQUIRED STATIC IMPORTED_TARGET sqlite3)
    pkg_check_modules(MAXMINDDB  REQUIRED STATIC IMPORTED_TARGET libmaxminddb)
else()
    pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
    pkg_check_modules(SQLITE3    REQUIRED IMPORTED_TARGET sqlite3)
    pkg_check_modules(MAXMINDDB  REQUIRED IMPORTED_TARGET libmaxminddb)
endif()

# ── Target ─────────────────────────────────────────────────────────────────
add_executable(msmap
    src/main.cpp
    src/parser.cpp)

target_compile_features(msmap PRIVATE cxx_std_23)

msmap_set_warnings(msmap)
msmap_enable_sanitizers(msmap)
msmap_enable_static_analyzers(msmap)

target_link_libraries(msmap PRIVATE
    PkgConfig::MICROHTTPD
    PkgConfig::SQLITE3
    PkgConfig::MAXMINDDB)

# ── Tests ───────────────────────────────────────────────────────────────────
# Catch2 is not in Debian bookworm; fetch it via CMake's built-in FetchContent.
if(MSMAP_ENABLE_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.7.1
        GIT_SHALLOW    TRUE
        FIND_PACKAGE_ARGS NAMES Catch2)
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
    include(Catch)

    enable_testing()

    add_executable(test_parser
        tests/test_parser.cpp
        src/parser.cpp)

    target_compile_features(test_parser PRIVATE cxx_std_23)
    target_include_directories(test_parser PRIVATE src)
    # Apply warnings but not static-analysis tools to the test target;
    # Catch2 macros generate code that confuses clang-tidy/cppcheck.
    msmap_set_warnings(test_parser)
    msmap_enable_sanitizers(test_parser)
    target_link_libraries(test_parser PRIVATE Catch2::Catch2WithMain)

    catch_discover_tests(test_parser)
endif()
