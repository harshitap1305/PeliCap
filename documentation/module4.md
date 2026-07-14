# Module 4: Real-Time Metrics & Analytics

## Overview
Module 4 converts high-velocity flow and packet data into high-level, human-readable analytics. It is responsible for calculating aggregate metrics—such as throughput rates, latency distributions (p50, p95), DNS query volumes, and HTTP error rates—over moving time windows.

## Key Features Supported
*   **Summary Metrics:** Tracks global throughput (Bytes/sec, Packets/sec) across all active flows.
*   **TCP Metrics:** Calculates real-time Round Trip Times (RTT) at p50/p95/p99 percentiles, and monitors TCP retransmission rates (packet loss indicators).
*   **DNS Metrics:** Computes DNS resolution latencies, NXDOMAIN (Not Found) error rates, Queries-Per-Second (QPS), and tracks the slowest resolving domains on the network.
*   **HTTP Metrics:** Aggregates Requests-Per-Second (RPS), server error rates (5xx codes), and HTTP response latencies.
*   **Sliding Windows:** All metrics are calculated over an active moving window (e.g., 60 seconds), ensuring dashboards always show current, relevant data rather than lifetime averages.

## Architecture & Pipeline
The `MetricsEngine` acts as an orchestrator for multiple specialized tracking classes:
*   `TcpMetricsTracker`: Analyzes TCP Round Trip Times (RTT) and retransmissions.
*   `HttpMetricsTracker`: Groups HTTP requests by status codes (2xx, 4xx, 5xx) and tracks server response latencies.
*   `DnsMetricsTracker`: Tracks DNS resolution times and NXDOMAIN error rates.

### Step-by-Step Flow
1. `MetricsEngine` subscribes to the `FlowEngine`'s event bus.
2. When a flow is updated or closed, the engine examines its Layer 7 properties.
3. The data is fed into the respective tracker.
4. The trackers maintain a `MetricWindow` (usually 60 seconds). All data points that fall outside the 60-second sliding window are expired and removed from memory.
5. When the REST API requests stats (e.g., `GET /api/metrics/tcp`), the trackers instantly aggregate their active window and return a JSON snapshot.

## Libraries Chosen
*   **Standard C++ (Atomics and Mutexes):** The module relies heavily on `std::atomic` for lock-free counters (like total bytes or request counts) and `std::mutex` for thread-safe vector sorting when calculating percentiles.

## Design Decisions & "Why We Did It This Way"
*   **In-Memory Sliding Windows vs. Database Queries:** We chose to compute real-time metrics strictly in C++ RAM using sliding windows, rather than relying on TimescaleDB to compute them. While TimescaleDB is fast, querying it every second to calculate the exact 95th percentile (p95) of DNS latency across thousands of queries would bottleneck the system. Pre-aggregating in memory allows sub-millisecond API responses.
*   **Percentile Calculations (p95/p99):** Averages (mean) are terrible for network latency because a single 5-second timeout can skew the entire metric. Percentiles give an accurate view of what "most users" are experiencing. To keep this fast, we store recent latencies in a ring buffer, and when the API is hit, we duplicate the buffer, sort it, and pick the 95th percentile index.
*   **Atomic Operations:** For simple metrics (bytes per second, error counts), we use `std::atomic<uint64_t>`. This avoids expensive thread locking entirely when the high-speed packet thread updates the counters.