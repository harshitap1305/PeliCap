FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
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
    ninja-build

WORKDIR /build
COPY . /build

# Build the project using vcpkg
RUN if [ ! -d "vcpkg" ]; then git clone https://github.com/microsoft/vcpkg.git && ./vcpkg/bootstrap-vcpkg.sh -disableMetrics; fi
RUN cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=/build/vcpkg/scripts/buildsystems/vcpkg.cmake
RUN cmake --build build --config Release

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN useradd -m palicap
COPY --from=builder /build/build/palicap /app/palicap
RUN chown -R palicap:palicap /app

# Grant capability to capture packets without root
RUN setcap cap_net_raw,cap_net_admin=eip /app/palicap

EXPOSE 8080

USER palicap

CMD ["./palicap"]
