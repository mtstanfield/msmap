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
#   docker build --build-arg MSMAP_CPU_TARGET=generic -t msmap:generic .
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

# cmake via pip — bookworm ships 3.25, but the project requires 3.29+.
# Pin to supported 3.x releases for reproducible static builds; CMake 4.x is
# intentionally outside the validated toolchain for this repo right now.
RUN pip3 install --break-system-packages "cmake>=3.29,<4"

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
        libclang-rt-${LLVM_VER}-dev \
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
        # project libraries (direct deps)
        libmicrohttpd-dev \
        libsqlite3-dev \
        libmaxminddb-dev \
        libcurl4-openssl-dev \
        libssl-dev \
        # static .a files for libmicrohttpd's GnuTLS transitive deps.
        # Needed only for MSMAP_LINK_STATIC=ON release builds; harmless in dev.
        libgnutls28-dev \
        libgmp-dev \
        nettle-dev \
        libtasn1-6-dev \
        libidn2-dev \
        libunistring-dev \
        zlib1g-dev \
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
# Default release builds target x86-64-v3 for modern servers. Override with
# --build-arg MSMAP_CPU_TARGET=generic for a portable image.
# Semi-static: libgcc + libstdc++ linked statically; glibc stays dynamic
# (fully static glibc has known NSS/getaddrinfo runtime issues).
# Project libs (sqlite, libmaxminddb, libmicrohttpd, curl) are linked as .a.
# -----------------------------------------------------------------------------
FROM dev AS builder

# Re-declare so ARG values are available in this stage's RUN commands.
ARG LLVM_VER=18
ARG MSMAP_CPU_TARGET=x86-64-v3

# ── Minimal static libcurl ────────────────────────────────────────────────────
# The Debian system libcurl4-openssl-dev links against nghttp2, rtmp, ssh2,
# brotli, zstd, gssapi, ldap… none of which have static .a files on bookworm.
# We build an HTTP-only + OpenSSL-only libcurl whose sole static deps are
# libssl.a and libcrypto.a — both available from libssl-dev.
ARG CURL_VER=8.11.0
RUN curl -fsSL \
        "https://github.com/curl/curl/releases/download/curl-$(echo ${CURL_VER} | tr . _)/curl-${CURL_VER}.tar.gz" \
        | tar -xz -C /tmp \
    && cmake -B /tmp/curl-build -G Ninja \
             -S /tmp/curl-${CURL_VER} \
             -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_C_COMPILER=clang-${LLVM_VER} \
             -DBUILD_SHARED_LIBS=OFF \
             -DBUILD_STATIC_LIBS=ON \
             -DBUILD_TESTING=OFF \
             -DBUILD_CURL_EXE=OFF \
             -DCURL_USE_OPENSSL=ON \
             -DHTTP_ONLY=ON \
             -DUSE_NGHTTP2=OFF \
             -DCURL_USE_LIBPSL=OFF \
             -DCURL_USE_LIBRTMP=OFF \
             -DCURL_USE_LIBSSH2=OFF \
             -DCURL_USE_LIBSSH=OFF \
             -DUSE_LIBIDN2=OFF \
             -DCURL_USE_GSSAPI=OFF \
             -DCURL_DISABLE_LDAP=ON \
             -DCURL_BROTLI=OFF \
             -DCURL_ZSTD=OFF \
             -DCURL_ZLIB=OFF \
             -DCMAKE_INSTALL_PREFIX=/opt/curl-static \
    && ninja -C /tmp/curl-build \
    && ninja -C /tmp/curl-build install \
    && rm -rf /tmp/curl-build /tmp/curl-${CURL_VER}

COPY . .

RUN cmake -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=23 \
        -DCMAKE_CXX_EXTENSIONS=OFF \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_C_COMPILER=clang-${LLVM_VER} \
        -DCMAKE_CXX_COMPILER=clang++-${LLVM_VER} \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++" \
        -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
        -DMSMAP_CPU_TARGET=${MSMAP_CPU_TARGET} \
        -DMSMAP_LINK_STATIC=ON \
        -DCMAKE_PREFIX_PATH=/opt/curl-static \
    && ninja -C build msmap

# Create persistent-data directories that are COPY-ed into the runtime stage.
#   /data                  — default DB mount point  (MSMAP_DB_PATH)
#   /var/lib/msmap/geoip   — default GeoIP mount point (MSMAP_CITY_MMDB / MSMAP_ASN_MMDB)
# /data is owned by uid 65532 (distroless nonroot) so the process can write the DB.
# GeoIP files are read-only; root ownership is fine.
RUN mkdir -p /data /var/lib/msmap/geoip \
    && chown 65532:65532 /data

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

# Explicitly copy the CA bundle so HTTPS (AbuseIPDB API) works regardless of
# what the distroless base image includes across version updates.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Runtime shared libs not present in distroless/cc-debian12.
# libmicrohttpd.a pulls in libgnutls.a which requires p11-kit (PKCS#11 provider).
# p11-kit requires libffi.  libatomic is a GCC runtime dep referenced by gnutls.
# All three depend only on libc.so.6 which distroless already provides.
# Copy versioned files (Docker COPY dereferences symlinks) with SONAME as dest.
COPY --from=builder /lib/x86_64-linux-gnu/libatomic.so.1.2.0    /lib/x86_64-linux-gnu/libatomic.so.1
COPY --from=builder /lib/x86_64-linux-gnu/libffi.so.8.1.2       /lib/x86_64-linux-gnu/libffi.so.8
COPY --from=builder /lib/x86_64-linux-gnu/libp11-kit.so.0.3.0   /lib/x86_64-linux-gnu/libp11-kit.so.0

# Persistent-data directories (created in builder with correct ownership).
COPY --from=builder /data /data
COPY --from=builder /var/lib/msmap/geoip /var/lib/msmap/geoip

COPY --from=builder /workspace/build/msmap /msmap

EXPOSE 8080

ENTRYPOINT ["/msmap"]
