# Module 3: Stateful Flow Tracking

## Overview
Module 3 transforms a chaotic stream of individual packets into logical, stateful "conversations" called Network Flows. It maps individual `ParsedPacket`s into persistent `Flow` objects, tracks the bytes moving in both directions, and determines when a conversation has ended. It provides the essential aggregation layer needed by the Analytics and Threat Detection engines.

## Key Features Supported
*   **Bidirectional Tracking:** Separately counts forward (Client -> Server) and reverse (Server -> Client) bytes and packets for every single connection.
*   **5-Tuple Uniqueness:** Uniquely identifies connections based on Source IP, Destination IP, Source Port, Destination Port, and Protocol.
*   **TCP State Awareness:** Actively monitors TCP flags (SYN, ACK, FIN, RST) to accurately track the lifecycle of a connection.
*   **L7 Metadata Preservation:** Attaches SNI domain names or HTTP URIs to the flow object for rich contextual analysis downstream.
*   **Automatic Garbage Collection:** Automatically expires and flushes UDP and TCP flows that have been silent for a specified duration, ensuring the memory map never grows infinitely.

## Architecture & Pipeline
The module is powered by the `FlowEngine` and a fast `FlowTable`.

### Step-by-Step Flow
1. **Flow Key Generation:** When a `ParsedPacket` enters the engine, it generates a 5-tuple `FlowKey`.
2. **Table Lookup:** The engine hashes the key and checks the `FlowTable`.
   - If the flow doesn't exist, it allocates a new `Flow` object and triggers a `FLOW_CREATED` event.
   - If the flow exists, it updates the existing `Flow`.
3. **State Updates:** Depending on the packet direction (Forward vs Reverse), it increments `fwd_bytes`, `rev_bytes`, `fwd_packets`, or `rev_packets`. It also updates the `last_seen` timestamp.
4. **Lifecycle Management:** 
   - **TCP State Machine:** If a packet has a TCP `FIN` or `RST` flag, the engine knows the conversation is officially ending and marks the flow for closure.
   - **Timeouts:** A background garbage collection routine sweeps the table for inactive flows (60s for UDP, 300s for TCP).
5. **Event Dispatch:** When a flow ends, it is removed from the table, and a `FLOW_CLOSED` event is broadcast to the Storage and Metrics engines.

## Libraries Chosen
*   **Abseil C++ (`absl::flat_hash_map`):** We replaced the standard `std::unordered_map` with Google's Abseil library for the core flow table.

## Design Decisions & "Why We Did It This Way"
*   **Abseil `flat_hash_map` for Cache Locality:** Flow tracking is incredibly memory-intensive. `std::unordered_map` uses separate chaining (linked lists) for hash collisions, which scatters memory across the heap and ruins CPU cache locality. `absl::flat_hash_map` uses open addressing and parallel SSE instructions (SwissTable architecture) to keep flow records contiguous in memory. This drastically reduces CPU cache misses and speeds up packet-to-flow mapping.
*   **Flow Events over Polling:** Instead of having other modules (like the Storage Engine or Detection Engine) constantly poll the `FlowTable` to see what changed, we implemented a Pub/Sub event callback system (`set_event_callback`). When a flow closes, the `FlowEngine` pushes the final summary to the Storage Engine to be persisted. This avoids heavy CPU locks on the flow table.
*   **Decoupled Garbage Collection:** The flow timeout sweeper runs asynchronously so it doesn't interrupt the packet processing pipeline.