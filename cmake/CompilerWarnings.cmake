# CompilerWarnings.cmake
# Warning flags based on cpp-best-practices/cmake_template.
# All builds use clang-18; no MSVC/GCC branches needed.

function(msmap_set_warnings target)
    set(WARNINGS
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
    )

    if(MSMAP_WARNINGS_AS_ERRORS)
        list(APPEND WARNINGS -Werror)
    endif()

    target_compile_options(${target} PRIVATE ${WARNINGS})
endfunction()
