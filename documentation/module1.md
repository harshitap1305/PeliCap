# Module 1: Packet Capture & Dispatch

## Overview
Module 1 serves as the foundational ingestion layer for PaliCap. Its primary responsibility is to attach to physical or virtual network interfaces (e.g., `eth0`, `wlp1s0`, `docker0`), capture packets at line rate, and dispatch them into the backend processing pipeline without dropping traffic or blocking operations. It provides the raw material (bytes) for the rest of the application.

## Key Features Supported
*   **Live Interface Sniffing:** Captures live traffic directly from the host Network Interface Card (NIC).
*   **Promiscuous Mode:** Can be configured to capture all traffic on the network segment, not just traffic destined for the host machine.
*   **BPF (Berkeley Packet Filter) Support:** Supports hardware-level filtering (e.g., `tcp port 80`) to drop irrelevant packets before they even reach the application layer, saving CPU cycles.
*   **Asynchronous Dispatch:** Guarantees that the OS packet queue is drained instantly, moving packets to a background queue to prevent buffer overflows during traffic spikes.

## Architecture & Pipeline
The module is divided into two primary components:
1. **`CaptureSession`**: Interfaces directly with the OS network stack via `PcapLiveDevice`. It runs an asynchronous capture thread that reads raw bytes from the NIC.
2. **`PacketBus`**: A lock-free Single-Producer Single-Consumer (SPSC) queue that bridges the high-speed capture thread with the rest of the application.

### Step-by-Step Flow
1. **Initialization:** The user initiates a capture via the REST API (`POST /api/capture/start`), specifying an interface (e.g., `wlp1s0`) and an optional BPF filter.
2. **Device Binding:** `CaptureSession` initializes `pcpp::PcapLiveDevice` in promiscuous mode and starts a background OS thread managed by `PcapPlusPlus`.
3. **Packet Arrival:** When a packet arrives, `CaptureSession::onPacketArrives` is triggered. It packages the raw bytes into a `CapturedPacket` struct, copying the payload to ensure safe memory ownership.
4. **Queue Enqueue:** The `CapturedPacket` is pushed onto the `PacketBus` (an SPSC queue). If the queue is completely full (e.g., the backend is severely lagging), the packet is explicitly dropped to prevent out-of-memory (OOM) crashes, and the `packets_dropped_` metric is incremented.
5. **Queue Dequeue:** A dedicated dispatcher thread inside `PacketBus` constantly pops packets off the queue and broadcasts them to any registered subscribers (e.g., the Dissector Engine and Storage Engine).

## Libraries Chosen
*   **PcapPlusPlus (libpcap wrapper):** We chose `PcapPlusPlus` over raw `libpcap` because it provides a robust, object-oriented C++ abstraction for device management and capture loops. It simplifies cross-platform compatibility and device lookups while still delivering near-native `libpcap` performance.
*   **Boost.Lockfree (`boost::lockfree::spsc_queue`):** Chosen for the `PacketBus` implementation to provide lock-free ring buffers.

## Design Decisions & "Why We Did It This Way"
*   **Lock-Free Queues over Mutexes:** Packet capture is an extremely high-frequency event (potentially hundreds of thousands of packets per second). If we used a standard `std::queue` protected by a `std::mutex`, the OS-level lock contention would cause the capture thread to block, leading to dropped packets at the NIC buffer. The SPSC queue allows wait-free, lock-free enqueueing.
*   **Asynchronous Dispatch:** By decoupling the capture thread from the dissection/analysis threads, we ensure that a slow database write or heavy protocol dissection never stalls the OS from delivering new packets. If the backend pipeline falls behind, the SPSC queue acts as a shock absorber.
*   **Thread-local `CapturedPacket` ownership:** We copy the raw buffer out of the `PcapPlusPlus` ephemeral buffer into our own `std::vector<uint8_t>`. While copying incurs a slight memory penalty, it prevents catastrophic use-after-free bugs when the packet traverses multiple async queues, ensuring thread safety.