# Sanitizers.cmake
# ASan + UBSan for Debug/CI builds.
# Enable with -DMSMAP_ENABLE_SANITIZERS=ON.
# Do NOT enable in release builds or the distroless runtime image.

function(msmap_enable_sanitizers target)
    if(NOT MSMAP_ENABLE_SANITIZERS)
        return()
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        message(WARNING "Sanitizers enabled on a Release build — "
                        "set BUILD_TYPE=Debug for meaningful results")
    endif()

    # ASan + UBSan. TSan is mutually exclusive with ASan; enable separately if needed.
    # -fno-sanitize-recover=all: treat every UBSan finding as fatal (same as ASan default).
    set(SANITIZE_FLAGS
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all)

    target_compile_options(${target} PRIVATE ${SANITIZE_FLAGS})
    target_link_options(${target}    PRIVATE ${SANITIZE_FLAGS})
endfunction()
