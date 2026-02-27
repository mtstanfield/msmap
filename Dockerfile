FROM ubuntu:24.04

# Set non-interactive frontend and timezone
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install base tools, update system, install C++ dev stack
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
        software-properties-common \
        wget \
        gnupg \
        ca-certificates \
        lsb-release \
        curl \
        git \
        python3 \
        python3-pip \
        build-essential \
        cmake \
        ninja-build \
        doxygen \
        graphviz \
        clang-18 \
        clang-format-18 \
        clang-tidy-18 \
        clang-tools-18 \
        lld-18 \
        libc++-18-dev \
        libc++abi-18-dev && \
    python3 -m pip install --break-system-packages conan && \
    conan profile detect --force && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set default Clang compilers
ENV CC=clang-18
ENV CXX=clang++-18

# Working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]