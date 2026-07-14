# Module 2: Stateless Packet Dissection

## Overview
Module 2 is the translation engine of PaliCap. It takes raw arrays of captured bytes and structures them into human-readable, logically organized C++ objects (`ParsedPacket`). It walks the OSI model from Layer 2 (Data Link) up to Layer 7 (Application) to extract critical network metadata, enabling the system to understand *what* is happening on the network, not just that bytes are moving.

## Key Features Supported
*   **L2/L3 Dissection:** Extracts MAC Addresses, VLAN Tags, IP versions (IPv4/IPv6), IP Addresses, and TTLs.
*   **L4 Dissection:** Extracts TCP and UDP source/destination ports, TCP flags (SYN, ACK, FIN, RST), and sequence/acknowledgment numbers.
*   **Deep Packet Inspection (L7):** 
    *   **HTTP/1.1:** Extracts HTTP methods (GET, POST), request URIs, Host headers, and HTTP response status codes (e.g., 200, 404).
    *   **DNS:** Extracts queried domains and resolution IP answers.
    *   **TLS/SSL (HTTPS):** Extracts Server Name Indication (SNI) extensions from the Client Hello handshake, allowing the system to identify encrypted HTTPS traffic destinations without breaking encryption.
*   **App Protocol Classification:** Automatically determines the `AppProtocol` enum (e.g., `HTTP`, `HTTPS`, `DNS`, `SSH`) based on port mappings and L7 signatures.

## Architecture & Pipeline
The module is built around a single, unified class: `DissectorEngine`.
It receives a `CapturedPacket` and returns a `ParsedPacket`.

### Step-by-Step Flow
1. **Raw to Packet Conversion:** The engine wraps the raw byte array in a `pcpp::RawPacket` and feeds it to `pcpp::Packet` to build an initial layer tree.
2. **Layer Iteration:** It loops through the layers (`getFirstLayer`, `getNextLayer`) and delegates parsing to specific helper functions (e.g., `parse_ipv4`, `parse_tcp`).
3. **Data Extraction:** Each helper function safely extracts fields and populates the `ParsedPacket` struct.
4. **Post-Parse Classification:** After parsing all layers, it calls `classify_app_protocol` to assign a definitive high-level protocol, and `build_flow_key` to generate the 5-tuple string used by the Flow Engine.

## Libraries Chosen
*   **PcapPlusPlus (Packet Analysis):** We utilize `pcpp::Packet` and its associated layer classes (`pcpp::EthLayer`, `pcpp::IPv4Layer`, `pcpp::TcpLayer`, etc.). It automatically handles the heavy lifting of pointer arithmetic, endianness conversion (network byte order to host byte order), and protocol standard compliance.

## Design Decisions & "Why We Did It This Way"
*   **100% Stateless & Thread-Safe Design:** Notice that `DissectorEngine` has no instance variables and all its methods are `static noexcept`. It takes a `CapturedPacket` by `const ref` and returns a `ParsedPacket` by value. We did this so that if we scale the system to use a thread-pool of dissecting workers (e.g., 4 threads dissecting simultaneously), they will never block each other or require Mutex locks.
*   **Zero-Exception Philosophy (`noexcept`):** Network traffic is inherently malformed, dirty, and unpredictable. Hackers and network glitches routinely send truncated or illegal packets. The dissector wraps all parsing in bounds checks and avoids C++ exceptions entirely. If a packet is malformed, the dissector simply stops at the highest valid layer and returns what it has, rather than throwing an exception and crashing the pipeline.
*   **Return-By-Value over Pointers:** The engine returns `ParsedPacket` directly. Modern C++ (C++17/20) uses Return Value Optimization (RVO), meaning this is heavily optimized by the compiler to avoid memory copies. It is safer than managing raw pointers or `shared_ptr` overhead during high-speed dissection.