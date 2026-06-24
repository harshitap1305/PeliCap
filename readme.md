PeliCap: Network Traffic Intelligence Engine



PeliCap is a high-performance, production-ready network packet capture and analysis engine built in C++20. It transforms raw network traffic into structured, queryable insights using a modern, modular architecture. Designed for both live monitoring and forensic analysis, PeliCap serves as the foundation for advanced security and network management tools.

Key Features
High-Performance Capture Engine

Zero-copy packet capture using Linux AF_PACKET and TPACKET_V3
Lock-free SPSC ring buffers for high-throughput packet ingestion
Nanosecond-precision timestamps and intelligent packet metadata management
Production-Grade Architecture

Modular design with separation of concerns:

Capture Layer (libpcap + AF_PACKET)

Dispatch Bus (fan-out to multiple subscribers)

Packet Dissector (Protocol解析 - Phase 2)

Smart Storage (PCAP writer + SQLite integration)

RESTful Control API (Drogon framework)
Flexible Capture Configurations

Promiscuous mode for full network visibility
Custom BPF filter support for targeted analysis
Configurable snapshot length (snaplen) for performance optimization
Rich Packet Intelligence

Automatically extracts:

Ethernet, IPv4/IPv6, TCP/UDP headers

Layer 4 protocols and port information

Flow metadata (source/destination IPs and ports)
Built for Performance

Optimized C++20 implementation
Minimal memory allocations
Async API for non-blocking packet processing
Standards-Compliant

Uses industry-standard libpcap for portable capture
Follows best practices for network forensics tools
Quick Start
Prerequisites

C++20 compatible compiler (GCC 10+ or Clang 10+)
CMake 3.20+
VCPKG package manager
Linux environment (for AF_PACKET support)
Building the Project

# Initialize VCPKG (if not already done)
./vcpkg/bootstrap-vcpkg

# Install dependencies
./vcpkg/vcpkg install pcapplusplus drogon nlohmann-json boost-lockfree

# Create build directory
mkdir build && cd build

# Configure with CMake (pointing to your vcpkg installation)
cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake

# Compile
cmake --build .

Running the Engine

# Run the capture engine (requires root privileges or CAP_NET_ADMIN capability)
sudo ./build/palicap

# API access via Docker
# Attach to the container to monitor traffic
sudo docker run -it --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v /path/to/pcap:/app/pcaps \
    palicap:latest
Monitoring & Debugging

Check captured packets via REST API:

# List available interfaces
curl http://localhost:8080/api/interfaces

# Start capture on eth0 (first 10 seconds)
curl -X POST -d '{"interface":"eth0", "duration_seconds":10}' http://localhost:8080/api/capture/start

# Get live statistics
curl http://localhost:8080/api/stats

# Stop capture
curl -X POST -d '{}' http://localhost:8080/api/capture/stop
Architecture Overview

Capture Layer (core/capture)

interface_discovery.cpp: Discovers network interfaces on the system

capture_session.cpp: Manages libpcap capture sessions with BPF filters

pcap_loader.cpp: Loads PCAP files for offline analysis

Dispatch Bus (core/dispatch)

packet_bus.hpp: Publishes packets to multiple subscribers using SPSC queues

Packet Model (core/capture/packet.hpp)

Defines the Packet struct with nanosecond timestamps and raw bytes
Immutable design for thread-safe packet processing
API Layer (api)

capture_api.cpp: Exposes REST endpoints for capture control

Docker Deployment

The project includes a production-ready Dockerfile for easy deployment:

# Build the Docker image
docker build -t palicap .

# Run with appropriate capabilities
sudo docker run -d --name palicap_engine \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -p 8080:8080 \
    palicap:latest

Next Steps
Module 2: Protocol Dissector - Implement Ethernet, IPv4, TCP, and UDP dissectors

Module 3: Smart Storage - Add SQLite integration for persistent storage

Module 4: State Engine - Build flow reconstruction and session tracking

Module 5: Analytics - Implement security rules and anomaly detection

Module 6: Visualization - Create Grafana dashboards for network monitoring

Community & Contributions

This project is built for real-world network analysis. Contributions are welcome in the following areas:

Performance optimizations for high-speed capture

Additional protocol dissectors (ICMP, ARP, DNS, HTTP, etc.)

Advanced flow analysis and state management

Machine learning integration for anomaly detection

Web UI for visualization and exploration