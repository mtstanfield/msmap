# StaticAnalyzers.cmake
# Integrates clang-tidy and cppcheck as per cpp-best-practices.
# Enable with -DMSMAP_ENABLE_CLANG_TIDY=ON / -DMSMAP_ENABLE_CPPCHECK=ON.
# Requires CMAKE_EXPORT_COMPILE_COMMANDS=ON (set in CMakeLists.txt).

function(msmap_enable_static_analyzers target)
    if(MSMAP_ENABLE_CLANG_TIDY)
        find_program(CLANG_TIDY_EXE
            NAMES clang-tidy-18 clang-tidy
            REQUIRED)
        message(STATUS "clang-tidy: ${CLANG_TIDY_EXE}")
        set_target_properties(${target} PROPERTIES
            CXX_CLANG_TIDY
                "${CLANG_TIDY_EXE};--warnings-as-errors=*;\
--header-filter=${CMAKE_SOURCE_DIR}/(src|include)/.*")
    endif()

    if(MSMAP_ENABLE_CPPCHECK)
        find_program(CPPCHECK_EXE NAMES cppcheck REQUIRED)
        message(STATUS "cppcheck: ${CPPCHECK_EXE}")
        set_target_properties(${target} PROPERTIES
            CXX_CPPCHECK
                "${CPPCHECK_EXE};\
--enable=style,performance,warning,portability;\
--error-exitcode=1;\
--inline-suppr;\
--suppress=cppcheckError;\
--suppress=internalAstError;\
--suppress=unmatchedSuppression;\
--inconclusive")
    endif()
endfunction()
