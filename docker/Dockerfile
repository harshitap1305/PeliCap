FROM ubuntu:24.04 AS builder

# ── Layer 1: OS packages (cached unless apt deps change) ─────────────────────
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    zip \
    unzip \
    tar \
    pkg-config \
    libpcap-dev \
    libjsoncpp-dev \
    uuid-dev \
    zlib1g-dev \
    libbrotli-dev \
    libboost-all-dev \
    bison \
    flex \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# ── Layer 2: Install cmake 4.3.3 (exact version vcpkg requires) ──────────────
# Cached permanently — prevents vcpkg from downloading cmake on its own
RUN CMAKE_VERSION=4.3.3 && \
    wget -q "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.sh" \
         -O /tmp/cmake.sh && \
    chmod +x /tmp/cmake.sh && \
    /tmp/cmake.sh --skip-license --prefix=/usr/local && \
    rm /tmp/cmake.sh

# ── Layer 3: Bootstrap vcpkg (cached permanently) ────────────────────────────
RUN git clone https://github.com/microsoft/vcpkg.git /vcpkg && \
    /vcpkg/bootstrap-vcpkg.sh -disableMetrics

# ── Layer 4: Install C++ dependencies (cached unless vcpkg.json changes) ─────
# Copy ONLY vcpkg.json first — this layer only re-runs when dependencies change
WORKDIR /build
COPY vcpkg.json ./

# Install all vcpkg packages directly. This downloads and builds Boost, Drogon,
# PcapPlusPlus, etc. and caches them in this single Docker layer.
# This layer is NOT invalidated by changes to your .cpp or .hpp files.
RUN cd /build && /vcpkg/vcpkg install --triplet x64-linux

# ── Layer 5: Compile application (re-runs on any source code change) ─────────
# Only now do we copy the full source tree
COPY . .
COPY config/ /app/config/

RUN cmake -B build -S . \
    -DCMAKE_TOOLCHAIN_FILE=/vcpkg/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --config Release -j$(nproc)

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcap2-bin \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN useradd -m palicap
COPY --from=builder /build/build/palicap /app/palicap
COPY --from=builder /app/config/ /app/config/
RUN chown -R palicap:palicap /app

# Grant capability to capture packets without root
RUN setcap cap_net_raw,cap_net_admin=eip /app/palicap

EXPOSE 8080

USER palicap

CMD ["./palicap"]
