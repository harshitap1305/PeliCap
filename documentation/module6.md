# Module 6: High-Performance Storage Engine

## Overview
Module 6 is the persistent memory of PaliCap. It guarantees that the massive volume of network metadata (flows, metrics, alerts) is securely written to a time-series database (TimescaleDB) for historical querying, while simultaneously writing truncated raw packets to standard `.pcap` files on disk for deep forensic analysis in external tools like Wireshark.

## Key Features Supported
*   **Time-Series Flow Storage:** Persists every closed network flow into TimescaleDB with full timestamps, bytes counts, and port data.
*   **Alert Logging:** Persists all security and anomaly alerts into the database for incident response tracking.
*   **PCAP Truncation:** Automatically slices payload bodies off of packets (keeping only the first 96 bytes) to save massive amounts of disk space while preserving OSI L2-L4 headers.
*   **Automated Disk Retention:** Implements a strict `RetentionManager` that deletes the oldest `.pcap` files when the configured storage quota (e.g., 5GB) is reached, ensuring the server never runs out of disk space.
*   **Database Migrations:** Automatically executes SQL `CREATE TABLE` and `CREATE hypertable` commands on startup via the `MigrationRunner`, requiring zero manual DB setup from the user.

## Architecture & Pipeline
The `StorageEngine` decouples high-speed data ingestion from slow disk I/O using a background-processing architecture.

### Step-by-Step Flow
1. **The Write Queue:** When a flow closes or an alert fires in the backend, it is pushed as a `StorageEvent` into a lock-free Single-Producer Single-Consumer queue (`WriteQueue`).
2. **The Batch Writer:** A dedicated background thread (`BatchWriter`) pops events from the queue. Instead of writing them to the database one by one, it accumulates them into a large batch buffer in RAM.
3. **Bulk Insertion:** Once the batch hits a size limit (e.g., 5000 flows) or a time limit (e.g., 1 second elapsed), it uses `libpqxx`'s `stream_to` functionality to perform a hyper-fast bulk insert into PostgreSQL via the `PgConnectionPool`.
4. **PCAP Management:** Raw packets are diverted to `PcapFileManager`. If a packet is larger than 96 bytes, it is truncated (snaplen) before being appended to the active `.pcap` file on disk.
5. **Log Rotation:** `PcapFileManager` rotates files every 10 minutes (e.g., `capture_20260714_1200.pcap`), keeping files small and easily manageable.

## Libraries Chosen
*   **TimescaleDB (PostgreSQL Extension):** We use TimescaleDB because network data is fundamentally time-series data. Regular SQL databases slow down exponentially as tables grow into the billions of rows. TimescaleDB uses "hypertables" to automatically partition data by time intervals, ensuring that inserting data at extreme velocities remains blazing fast.
*   **libpqxx:** The official C++ client for PostgreSQL. Used for its connection pooling and native `stream_to` bulk copy API.
*   **PcapPlusPlus:** Used for writing standard `.pcap` formatted files.

## Design Decisions & "Why We Did It This Way"
*   **Batch Writing over Single Inserts:** Executing an `INSERT` statement for every single network flow is highly inefficient and creates massive network overhead between the C++ backend and the Database. By grouping thousands of rows into a single `COPY` / `stream_to` transaction, we achieve orders-of-magnitude faster write throughput.
*   **Packet Truncation (Snaplen 96):** We capture full payloads in memory for L7 dissection, but when writing to disk, we truncate the packet to 96 bytes. Why? 96 bytes is enough to capture the full Ethernet, IP, and TCP headers (which are essential for forensics like Wireshark), but it drops the heavy video/file payloads. This turns a 10 GB raw capture into a lightweight 50 MB metadata capture, allowing the system to run for weeks without filling up the hard drive.
*   **Automatic Migrations:** The engine includes a `MigrationRunner` that automatically creates the required TimescaleDB hypertables (`flows`, `alerts`) on boot, ensuring zero-configuration deployment for the end user.
*   **Dev-Friendly TimescaleDB Tuning:** By default, TimescaleDB's tuning script auto-detects system hardware and allocates massive resources (e.g., 4GB shared buffers, 35 background workers on a 16-core laptop) assuming it's running on a dedicated production server. In our `docker-compose.yml`, we explicitly override these settings with dev-friendly caps (`shared_buffers=256MB`, limited worker threads) to prevent the database from starving the host OS and causing severe laptop heating during local development.