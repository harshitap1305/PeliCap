# Module 5: Threat Detection & Anomalies

## Overview
Module 5 is the security and monitoring brain of PaliCap. It actively searches the network flow stream for behavioral anomalies, volumetric spikes, and protocol violations. When an anomaly is detected, it generates actionable `Alert` objects that are broadcast to connected clients via WebSockets and saved to the database.

## Key Features Supported
*   **Port Scan Detection (`PortScanDetector`):** Flags when a single IP addresses scans an abnormal number of ports in a short window, a classic sign of reconnaissance.
*   **TCP Latency Spikes (`TcpHighRttDetector`):** Flags when the 95th percentile (p95) of TCP Round Trip Times exceeds normal baselines, indicating severe network congestion.
*   **DNS Latency & Errors (`DnsLatencyDetector`, `DnsNxdomainDetector`):** Flags unusual spikes in DNS resolution times or a flood of "Domain Not Found" errors (often caused by malware attempting Domain Generation Algorithms).
*   **Volumetric DDoS (`TrafficSpikeDetector`, `LargeFlowDetector`):** Identifies sudden volumetric surges in network traffic throughput, or single flows consuming excessive bandwidth.
*   **Congestion Detection (`TcpRetransmissionSpikeDetector`, `ZeroWindowDetector`):** Detects when packets are being lost and retransmitted, or when receiving buffers are full, indicating physical layer or routing issues.

## Architecture & Pipeline
The `DetectionEngine` orchestrates an array of `AnomalyDetector` subclasses.

### Step-by-Step Flow
1. The `DetectionEngine` hooks into the main `ParsedPacketBus` and `FlowEngine` event bus.
2. Every 10 seconds, a background `evaluation_thread` ticks.
3. On every tick, the engine queries the `MetricsEngine` for the latest window aggregates (e.g., current TCP retransmission rate, current QPS).
4. The engine feeds these values into the registered detectors.
5. The detectors evaluate the current value against their internal baseline and standard deviation.
6. If the value exceeds the threshold (`baseline + (sigma * stddev)`), the detector generates an `Alert` object tagged with severity (WARNING/CRITICAL).
7. The alert is pushed to the `StorageEngine` and broadcast to the UI via the `AlertWsController` (WebSockets).

## Libraries Chosen
*   **Standard C++ / JSON (`nlohmann::json`):** Used for detector configuration and baseline state persistence (`baselines.json`), allowing the engine to "remember" network norms across reboots.

## Design Decisions & "Why We Did It This Way"
*   **Dynamic Baselining (EWMA):** Networks are highly organic. A hardcoded threshold for "High Traffic" that works for a home network will instantly trigger false positives in a datacenter. We implemented Exponentially Weighted Moving Averages (EWMA) to allow the detectors to "learn" the baseline of their environment over time. 
*   **Sigma Multipliers for Thresholds:** Rather than arbitrary numbers, thresholds are defined statistically. If a metric deviates from the norm by 3 standard deviations (`sigma = 3`), it is mathematically proven to be an outlier (representing the 99.7th percentile of abnormal behavior). This drastically reduces false positives.
*   **Cooldown Periods:** Once an alert fires, the detector enters a cooldown phase (e.g., 60 seconds). This prevents "alert fatigue" where a single ongoing DDoS attack floods the database with 10,000 identical alerts in one minute.
*   **Asynchronous Evaluation:** The anomaly evaluation happens on a background ticking thread, ensuring it never slows down the primary packet capture pipeline.
