# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# msmap – Multi-stage Dockerfile
#
# Stages:
#   dev      – full toolchain for iterative development (volume-mounted src)
#   builder  – reproducible release build
#   runtime  – distroless runtime (ships only the binary)
#
# Usage (dev):
#   docker build --target dev -t msmap-dev .
#   docker run -it --rm -v "/c/Users/ms/projects/msmap:/workspace" msmap-dev
#
# Usage (release):
#   docker build -t msmap .
# -----------------------------------------------------------------------------

ARG LLVM_VER=18

# -----------------------------------------------------------------------------
# Stage 1: dev
# Full toolchain. Never ships to production.
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS dev
ARG LLVM_VER
ENV DEBIAN_FRONTEND=noninteractive

# Bootstrap: tools required to add external repos
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# LLVM apt repo – clang-18, clang-tidy, clang-format, lld, lldb
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/llvm-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-keyring.gpg] \
        http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VER} main" \
        > /etc/apt/sources.list.d/llvm.list

# cmake via pip – bookworm ships 3.25; best practices template requires 3.29+
RUN pip3 install --break-system-packages cmake

# Full toolchain + static analysis + project libraries
# All -dev packages include static .a files for semi-static linking
RUN apt-get update && apt-get install -y --no-install-recommends \
        # build
        build-essential \
        ninja-build \
        pkg-config \
        git \
        # LLVM toolchain
        clang-${LLVM_VER} \
        clang-tidy-${LLVM_VER} \
        clang-format-${LLVM_VER} \
        clang-tools-${LLVM_VER} \
        lld-${LLVM_VER} \
        lldb-${LLVM_VER} \
        libc++-${LLVM_VER}-dev \
        libc++abi-${LLVM_VER}-dev \
        # static analysis
        cppcheck \
        iwyu \
        # build acceleration
        ccache \
        # debugging
        gdb \
        # documentation
        doxygen \
        graphviz \
        # project libraries
        # all provide static .a files for semi-static release builds
        libmicrohttpd-dev \
        libsqlite3-dev \
        libmaxminddb-dev \
        libcurl4-openssl-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Unversioned symlinks – CMake find_program and editors find tools without suffix
RUN for bin in clang clang++ clang-tidy clang-format lld lldb; do \
        ln -sf /usr/bin/${bin}-${LLVM_VER} /usr/local/bin/${bin}; \
    done

ENV CC=clang-${LLVM_VER} \
    CXX=clang++-${LLVM_VER}

WORKDIR /workspace
CMD ["/bin/bash"]

# -----------------------------------------------------------------------------
# Stage 2: builder
# Compiles the release binary.
# Semi-static: libgcc + libstdc++ linked statically; glibc stays dynamic
# (fully static glibc has known NSS/getaddrinfo runtime issues).
# Project libs (sqlite, libmaxminddb, libmicrohttpd) are linked as .a.
# -----------------------------------------------------------------------------
FROM dev AS builder

COPY . .

RUN cmake -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=23 \
        -DCMAKE_CXX_EXTENSIONS=OFF \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DMSMAP_LINK_STATIC=ON \
    && ninja -C build msmap

# -----------------------------------------------------------------------------
# Stage 3: runtime
#
# distroless/cc-debian12:nonroot provides:
#   - glibc (matches bookworm ABI)
#   - libstdc++ / libgcc_s  (unused – we statically linked them)
#   - runs as uid 65532 (nonroot) – no root at runtime
#
# Everything else is baked into the binary.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /workspace/build/msmap /msmap

EXPOSE 8080

ENTRYPOINT ["/msmap"]
