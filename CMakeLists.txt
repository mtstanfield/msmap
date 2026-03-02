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
option(MSMAP_ENABLE_CLANG_TIDY  "Run clang-tidy during build"       OFF)
option(MSMAP_ENABLE_CPPCHECK    "Run cppcheck during build"         OFF)
# Prefer .a over .so for app libraries. Set ON in release/distroless builds.
option(MSMAP_LINK_STATIC        "Link app libraries statically"     OFF)
# ASan + UBSan: default ON for non-Release builds, OFF for Release.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    option(MSMAP_ENABLE_SANITIZERS "Enable ASan + UBSan" OFF)
else()
    option(MSMAP_ENABLE_SANITIZERS "Enable ASan + UBSan" ON)
endif()
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
find_package(PkgConfig  REQUIRED)
find_package(Python3    REQUIRED COMPONENTS Interpreter)
find_package(Threads    REQUIRED)

# cmake (any version) does not support a STATIC keyword in pkg_check_modules;
# passing STATIC is treated as a module name and causes a configure error.
# Always discover with IMPORTED_TARGET for include paths and compile flags.
# When MSMAP_LINK_STATIC=ON, INTERFACE_LINK_LIBRARIES is overridden below
# using the <prefix>_STATIC_LIBRARIES variables (from pkg-config --static --libs)
# with each name resolved to a full .a path where available.
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(SQLITE3    REQUIRED IMPORTED_TARGET sqlite3)
pkg_check_modules(MAXMINDDB  REQUIRED IMPORTED_TARGET libmaxminddb)
pkg_check_modules(LIBCURL    REQUIRED IMPORTED_TARGET libcurl)

if(MSMAP_LINK_STATIC)
    # Walk each library's static-link list and resolve to .a where possible.
    # Falls back to a bare library name (dynamic) for any lib without a .a;
    # the linker includes those only if their symbols are actually referenced.
    #
    # Glibc sub-libraries (m, pthread, dl, rt, c, resolv) must remain dynamic
    # even in a semi-static build.  Their .a archives use GNU IFUNCs that
    # reference _dl_x86_cpu_features — a symbol that only exists in ld.so at
    # runtime.  Statically linking them causes undefined-reference link errors.
    # All of them are present in distroless/cc-debian12 via glibc.
    set(_glibc_libs m pthread dl rt c resolv)
    set(_saved_sfx "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    foreach(_prefix IN ITEMS MICROHTTPD SQLITE3 MAXMINDDB LIBCURL)
        set(_static_link)
        foreach(_lib IN LISTS ${_prefix}_STATIC_LIBRARIES)
            if(_lib IN_LIST _glibc_libs)
                # Keep dynamic: bare name → linker resolves as -l<name>.
                list(APPEND _static_link "${_lib}")
                continue()
            endif()
            # Unset before each call: find_library(NO_CACHE) reuses a stale
            # variable value rather than re-searching if the var is already set.
            unset(_lib_path)
            find_library(_lib_path "${_lib}" NO_CACHE)
            if(_lib_path)
                list(APPEND _static_link "${_lib_path}")
            else()
                list(APPEND _static_link "${_lib}")
            endif()
        endforeach()
        set_target_properties("PkgConfig::${_prefix}" PROPERTIES
            INTERFACE_LINK_LIBRARIES "${_static_link}")
    endforeach()
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_saved_sfx}")
endif()

# ── Web bundle ─────────────────────────────────────────────────────────────
# Run web/bundle.py to inline Leaflet + app assets into a single HTML file,
# then emit src/index_html.h as a constexpr string_view for embedding.
set(WEB_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/web")
set(INDEX_HTML_H  "${CMAKE_CURRENT_BINARY_DIR}/index_html.h")

add_custom_command(
    OUTPUT  "${INDEX_HTML_H}"
    COMMAND "${Python3_EXECUTABLE}"
            "${WEB_DIR}/bundle.py"
            "${WEB_DIR}/index.html"
            "${INDEX_HTML_H}"
            kIndexHtml
    DEPENDS
        "${WEB_DIR}/bundle.py"
        "${WEB_DIR}/index.html"
        "${WEB_DIR}/app.js"
        "${WEB_DIR}/app.css"
        "${WEB_DIR}/vendor/leaflet.min.js"
        "${WEB_DIR}/vendor/leaflet.min.css"
        "${WEB_DIR}/vendor/leaflet.markercluster.js"
        "${WEB_DIR}/vendor/MarkerCluster.css"
        "${WEB_DIR}/vendor/MarkerCluster.Default.css"
    VERBATIM
    COMMENT "Bundling web assets → index_html.h")

add_custom_target(web_bundle DEPENDS "${INDEX_HTML_H}")

# ── Target ─────────────────────────────────────────────────────────────────
add_executable(msmap
    src/main.cpp
    src/db.cpp
    src/geoip.cpp
    src/home_resolver.cpp
    src/http.cpp
    src/listener.cpp
    src/parser.cpp
    src/abuse_cache.cpp)

target_compile_features(msmap PRIVATE cxx_std_23)

msmap_set_warnings(msmap)
msmap_enable_sanitizers(msmap)
msmap_enable_static_analyzers(msmap)

# Make msmap depend on the web bundle and expose the build dir as an include path.
add_dependencies(msmap web_bundle)
target_include_directories(msmap PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

target_link_libraries(msmap PRIVATE
    PkgConfig::MICROHTTPD
    PkgConfig::SQLITE3
    PkgConfig::MAXMINDDB
    PkgConfig::LIBCURL)

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

    add_executable(test_db
        tests/test_db.cpp
        src/db.cpp
        src/geoip.cpp
        src/parser.cpp)

    target_compile_features(test_db PRIVATE cxx_std_23)
    target_include_directories(test_db PRIVATE src)
    msmap_set_warnings(test_db)
    msmap_enable_sanitizers(test_db)
    target_link_libraries(test_db PRIVATE
        Catch2::Catch2WithMain
        PkgConfig::SQLITE3
        PkgConfig::MAXMINDDB)

    catch_discover_tests(test_db)

    add_executable(test_geoip
        tests/test_geoip.cpp
        src/geoip.cpp)

    target_compile_features(test_geoip PRIVATE cxx_std_23)
    target_include_directories(test_geoip PRIVATE src)
    msmap_set_warnings(test_geoip)
    msmap_enable_sanitizers(test_geoip)
    target_link_libraries(test_geoip PRIVATE
        Catch2::Catch2WithMain
        PkgConfig::MAXMINDDB)

    catch_discover_tests(test_geoip)

    # test_http: tests the JSON serialiser (json.h) and Database::query_connections.
    # Does not link MICROHTTPD — HttpServer is not instantiated in these tests.
    add_executable(test_http
        tests/test_http.cpp
        src/db.cpp
        src/geoip.cpp
        src/parser.cpp)

    target_compile_features(test_http PRIVATE cxx_std_23)
    target_include_directories(test_http PRIVATE src)
    msmap_set_warnings(test_http)
    msmap_enable_sanitizers(test_http)
    target_link_libraries(test_http PRIVATE
        Catch2::Catch2WithMain
        PkgConfig::SQLITE3
        PkgConfig::MAXMINDDB)

    catch_discover_tests(test_http)

    add_executable(test_abuse_cache
        tests/test_abuse_cache.cpp
        src/abuse_cache.cpp
        src/db.cpp
        src/geoip.cpp
        src/parser.cpp)

    target_compile_features(test_abuse_cache PRIVATE cxx_std_23)
    target_include_directories(test_abuse_cache PRIVATE src)
    msmap_set_warnings(test_abuse_cache)
    msmap_enable_sanitizers(test_abuse_cache)
    target_link_libraries(test_abuse_cache PRIVATE
        Catch2::Catch2WithMain
        PkgConfig::SQLITE3
        PkgConfig::MAXMINDDB
        PkgConfig::LIBCURL)

    catch_discover_tests(test_abuse_cache)

    add_executable(test_integration
        tests/test_integration.cpp
        src/listener.cpp
        src/abuse_cache.cpp
        src/db.cpp
        src/geoip.cpp
        src/parser.cpp)

    target_compile_features(test_integration PRIVATE cxx_std_23)
    target_include_directories(test_integration PRIVATE src)
    msmap_set_warnings(test_integration)
    msmap_enable_sanitizers(test_integration)
    target_link_libraries(test_integration PRIVATE
        Catch2::Catch2WithMain
        PkgConfig::SQLITE3
        PkgConfig::MAXMINDDB
        PkgConfig::LIBCURL
        Threads::Threads)

    # SQLite global state triggers LSAN false positives at process exit.
    # Pass ASAN_OPTIONS to every discovered test case via catch_discover_tests PROPERTIES.
    catch_discover_tests(test_integration
        PROPERTIES
            ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
endif()
