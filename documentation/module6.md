## Module 6 — Storage Layer: Complete Implementation Plan

---

## What this module does and its role in the system

Every other module is ephemeral. Module 1 captures packets that vanish from memory the moment they're processed. Module 3 holds flows in a hash map that evicts entries after timeout. Module 4 keeps ring buffers of the last hour. Module 5 holds the last 10,000 alerts in a deque.

Module 6 is the persistence layer. It takes everything the other modules produce and decides what to keep, for how long, in what format, and how to make it queryable. It answers the questions the other modules cannot: what happened three hours ago, which IP was generating the most traffic last Tuesday, what did this flow look like at the packet level.

The core challenge is that your system produces data at wildly different rates and with wildly different importance. A busy network produces 100,000 packets per second. You cannot store all of them forever. You must make intelligent decisions about what to store at full fidelity, what to store as summaries, and what to discard.

---

## The fundamental design decision: what NOT to store

This is the most important decision in the whole module and most people get it backwards by trying to store everything.

Raw packets should almost never be stored in a database. A single second of traffic on a 1 Gbps link is 1 GB of data. Storing that in PostgreSQL row-by-row would fill a 1 TB disk in 17 minutes and make every query scan gigabytes. Instead, think in tiers.

**Tier 1 — Store everything, briefly.** Raw packet bytes go into a rolling PCAP file on disk. New file every 10 minutes, keep the last 6 files, total retention 1 hour. If an incident happens, you have the raw packets for the last hour. After that they're gone. This is what professional network monitoring tools do.

**Tier 2 — Store summaries, longer.** Flow records go into PostgreSQL. One row per flow, not one row per packet. A flow that lasted 4 seconds and carried 412 packets becomes a single database row. Keep flow records for 30 days. This is what you query for incident investigation.

**Tier 3 — Store aggregates, indefinitely.** Metric snapshots — bytes per second, RTT p95, DNS query rate — go into a time-series structure. One row per minute per metric. Keep for 90 days or more. This is what you query for trend analysis and dashboard charts.

**Tier 4 — Store events, indefinitely.** Alerts and AI conversation history. These are small and important. Keep forever or until manually deleted.

---

## Technology choices and tradeoffs

### Primary database: PostgreSQL

PostgreSQL is the right choice for flow records, metrics snapshots, alerts, and AI conversations. The reasons:

It has native `INET` and `CIDR` types which let you write `WHERE src_ip << '192.168.0.0/16'` to filter entire subnets without string comparison. It has `JSONB` columns for flexible metadata without schema changes. It has `pg_partman` for automatic table partitioning by time, which is essential when a `flows` table has 50 million rows. It has excellent C++ drivers. It handles the write rates this system produces comfortably.

The alternative people reach for is ClickHouse, which is a column-oriented analytical database that queries much faster on aggregations like `SELECT src_ip, sum(bytes) FROM flows GROUP BY src_ip`. ClickHouse is the right choice if your primary use case is analytics queries over months of data. PostgreSQL is the right choice if your primary use case is operational queries like "show me all flows from this IP in the last hour" with occasional aggregations. For a project at this scale, start with PostgreSQL and you will not regret it.

Do not use SQLite for anything except a development fallback. It serializes all writes through a single mutex. At the write rates this system produces it becomes the bottleneck immediately.

### Time-series data: PostgreSQL with TimescaleDB extension

TimescaleDB is a PostgreSQL extension that adds automatic time-based partitioning, compression, and continuous aggregates to regular PostgreSQL tables. You write to it exactly like a PostgreSQL table. It automatically partitions data into chunks by time, compresses old chunks, and lets you query across all chunks transparently. The continuous aggregates feature lets you define a query like "hourly average RTT per interface" and TimescaleDB maintains that result incrementally as new data arrives, so dashboard queries are instant.

Install it once, enable it on your metrics tables, and you get the benefits of a dedicated time-series database without running a separate service.

The alternative is InfluxDB or Prometheus. Both are good but they add operational complexity — a separate service to run, monitor, back up, and integrate. TimescaleDB gives you 80% of the performance benefit with zero additional infrastructure.

### Raw packet storage: rolling PCAP files on disk

PCAP files are the universal format for packet captures. Every network tool in existence can read them. PcapPlusPlus can write them directly. They compress extremely well — a 1 GB capture typically compresses to 100-200 MB with gzip. Store them on disk in a rolling fashion: open a new file every 10 minutes, gzip and archive the previous file, delete files older than the retention window.

Do not store raw packets in PostgreSQL as blob columns. The I/O pattern is wrong — blobs fragment the table, make vacuuming expensive, and turn every packet query into a full row fetch.

### In-memory write buffer: separate thread with batch writes

Never write to PostgreSQL synchronously from the packet processing path. A database write takes 1-10 milliseconds. At 10,000 packets per second, synchronous writes would cap your throughput at 100-1,000 packets per second.

Instead, use a lock-free queue between the processing pipeline and the storage thread. The processing pipeline enqueues records in microseconds. A dedicated storage thread dequeues in batches and writes to PostgreSQL using bulk insert statements. One `INSERT INTO flows VALUES (...), (...), ...` with 1,000 rows is far faster than 1,000 individual inserts.

---

## PostgreSQL schema — all tables

### Flows table

The flows table is the most important and the one that receives the most writes. Design it carefully.

The primary key is `flow_id` as a `BIGINT`. Do not use UUIDs here — they are 128 bits, generate random page access patterns that thrash the B-tree index, and you have no benefit over a sequential integer at this scale.

The table needs to be partitioned by `start_time` using TimescaleDB's `create_hypertable` function with a chunk interval of 1 day. This means a query for "all flows from yesterday" only touches one partition instead of scanning the entire table.

Columns to store: `flow_id`, `src_ip` as `INET`, `dst_ip` as `INET`, `src_port` as `SMALLINT`, `dst_port` as `SMALLINT`, `protocol` as `SMALLINT`, `interface_name` as `TEXT`, `start_time` as `TIMESTAMPTZ`, `end_time` as `TIMESTAMPTZ`, `duration_ms` as `INTEGER`, `fwd_packets` as `BIGINT`, `rev_packets` as `BIGINT`, `fwd_bytes` as `BIGINT`, `rev_bytes` as `BIGINT`, `payload_bytes` as `BIGINT`, `tcp_state` as `SMALLINT`, `avg_rtt_us` as `INTEGER`, `min_rtt_us` as `INTEGER`, `retransmit_count` as `INTEGER`, `zero_window_events` as `INTEGER`, `app_protocol` as `SMALLINT`, `tls_sni` as `TEXT`, `http_host` as `TEXT`, `dns_query` as `TEXT`, `tags` as `JSONB` for any extra metadata.

Indexes to create: `(src_ip, start_time DESC)` for "all flows from this source", `(dst_ip, start_time DESC)` for "all flows to this destination", `(start_time DESC)` for time range queries, `(app_protocol, start_time DESC)` for "all DNS flows", `(tls_sni)` using a partial index `WHERE tls_sni IS NOT NULL` for SNI lookups, `(dst_port, start_time DESC)` for port-based queries.

Do not create indexes on `src_port` — source ports are ephemeral and random, an index on them is useless.

### Metrics snapshots table

One row per minute per metric. TimescaleDB with a 1-hour chunk interval. Compress chunks older than 7 days — compressed metric data uses about 10% of uncompressed size.

Columns: `time` as `TIMESTAMPTZ`, `metric_name` as `TEXT`, `interface_name` as `TEXT`, `value_avg` as `DOUBLE PRECISION`, `value_min` as `DOUBLE PRECISION`, `value_max` as `DOUBLE PRECISION`, `value_p95` as `DOUBLE PRECISION`, `sample_count` as `INTEGER`.

The `metric_name` column holds values like `bytes_in_per_sec`, `rtt_p95_us`, `dns_latency_ms`, `http_error_rate_pct`. This is a narrow schema that can store any metric without schema changes.

Create a TimescaleDB continuous aggregate for hourly summaries. This gives you instant queries for "what was the average RTT last week" without scanning minute-level data.

### Alerts table

Described in Module 5. Add a foreign key from alerts to flows: `flow_id BIGINT REFERENCES flows(flow_id)` nullable. When an alert is associated with a specific flow, link them so the frontend can show "this retransmission alert is associated with flow #4382, click to inspect it."

### DNS transactions table

Store matched DNS query/response pairs. This enables queries like "which domains had resolution times over 500ms yesterday" that cannot be answered from flow records alone.

Columns: `id` as `BIGSERIAL`, `time` as `TIMESTAMPTZ`, `flow_id` as `BIGINT`, `transaction_id` as `INTEGER`, `query_name` as `TEXT`, `query_type` as `SMALLINT`, `rcode` as `SMALLINT`, `resolution_time_ms` as `INTEGER`, `answers` as `TEXT[]`, `server_ip` as `INET`, `client_ip` as `INET`.

Index on `(query_name, time DESC)` and `(resolution_time_ms DESC, time DESC)` for slowest domain queries.

### HTTP transactions table

Store matched HTTP request/response pairs for API latency analysis.

Columns: `id` as `BIGSERIAL`, `time` as `TIMESTAMPTZ`, `flow_id` as `BIGINT`, `method` as `TEXT`, `url` as `TEXT`, `host` as `TEXT`, `status_code` as `SMALLINT`, `request_size` as `INTEGER`, `response_size` as `INTEGER`, `latency_ms` as `INTEGER`, `http_version` as `TEXT`.

Index on `(host, url, time DESC)` and `(latency_ms DESC, time DESC)` for slow endpoint queries. Create a partial index `WHERE status_code >= 400` for error queries.

### AI conversations table

Columns: `id` as `BIGSERIAL`, `session_id` as `UUID`, `time` as `TIMESTAMPTZ`, `user_query` as `TEXT`, `ai_response` as `TEXT`, `metrics_context` as `JSONB`, `model_used` as `TEXT`, `latency_ms` as `INTEGER`. The `metrics_context` column stores the exact JSON snapshot that was sent to the LLM so you can replay or audit any conversation.

### PCAP index table

When you write a rolling PCAP file, index it in PostgreSQL so the REST API can tell users "the packets for this flow are in file capture_20240115_143000.pcap.gz starting at offset 4,291,872."

Columns: `file_id` as `BIGSERIAL`, `filename` as `TEXT`, `start_time` as `TIMESTAMPTZ`, `end_time` as `TIMESTAMPTZ`, `file_size_bytes` as `BIGINT`, `packet_count` as `BIGINT`, `is_compressed` as `BOOLEAN`, `is_deleted` as `BOOLEAN`.

---

## The write pipeline architecture

The write pipeline has three layers that you must never collapse into one.

**Layer 1: The enqueue layer.** This runs on the same thread as the FlowEngine event callback. It must be as fast as possible — a few dozen nanoseconds. It takes a Flow or Alert object and places it into a lock-free SPSC queue. No serialization, no database calls, no mutexes.

**Layer 2: The serialization layer.** A dedicated thread reads from the queue, serializes objects to their database representation, and batches them into groups of 500-1000 records. Serialization is the expensive step — converting IP addresses to strings, computing durations, formatting timestamps. Do it here, not in Layer 1.

**Layer 3: The write layer.** Takes serialized batches and executes bulk PostgreSQL inserts. Uses libpqxx's prepared statements for the inserts. Handles connection failures with exponential backoff retry. Writes raw packets to the current PCAP file. Tracks write latency and alerts if the queue depth grows, which indicates the database cannot keep up.

The queue between Layer 1 and Layer 2 should hold at minimum 100,000 records. If it fills up, you have a backpressure situation — either the database is too slow or the network is producing data faster than you can store it. Log this condition prominently.

---

## The PCAP file manager

The PCAP file manager runs as a separate thread. Its responsibilities are:

**File rotation.** Every 10 minutes, close the current file and open a new one. Name files with a timestamp: `capture_YYYYMMDD_HHMMSS.pcap`. Write the new filename to the PCAP index table.

**Compression.** When a file is rotated, spawn a background process to gzip it. PcapPlusPlus writes standard PCAP format that gzip compresses to roughly 15% of original size for typical network traffic.

**Retention enforcement.** After compression, check if total disk usage of all PCAP files exceeds the configured maximum. Delete the oldest files until disk usage is within limits. Mark them as deleted in the PCAP index table. Never delete a file that is currently being written.

**Snaplen control.** PcapPlusPlus lets you configure how many bytes of each packet to capture. Full packet capture (`snaplen = 65535`) is needed if users want to inspect payloads. Metadata-only capture (`snaplen = 96`) captures just enough for Ethernet, IP, and TCP headers — about 2% of the data. Let users configure this. Metadata-only mode is appropriate for always-on monitoring. Full capture is appropriate for incident investigation.

---

## The StorageEngine class responsibilities

The `StorageEngine` class is the single entry point for all persistence operations. Other modules call its methods and do not interact with PostgreSQL or the file system directly.

The methods it exposes to other modules:

`write_flow(const Flow&)` — called by FlowEngine on FLOW_CLOSED and FLOW_EXPIRED. Enqueues for batch write. Non-blocking.

`write_alert(const Alert&)` — called by DetectionEngine. Enqueues immediately. Alerts are small so they can also be written synchronously if you want guaranteed persistence.

`write_dns_transaction(domain, latency_ms, rcode, flow_id)` — called by DnsTransactionTracker.

`write_http_transaction(method, url, status, latency_ms, flow_id)` — called by HttpMetrics.

`write_metrics_snapshot(const MetricsEngine&)` — called by a timer every 60 seconds. Serializes all current metric values and writes a batch of rows to the metrics table.

`write_raw_packet(const CapturedPacket&)` — called by the dispatch bus subscriber. Writes to the current PCAP file. Very fast — PcapPlusPlus PCAP writing is essentially a memory copy followed by a file write.

`query_flows(FlowQuery)` — used by the REST API. Executes a PostgreSQL SELECT with appropriate filters and returns a page of flow records.

`query_alerts(AlertQuery)` — similar.

`get_pcap_file_for_flow(flow_id)` — looks up which PCAP file contains the packets for a given flow, returns the filename and byte offset.

---

## The query interface

The REST API exposes these storage queries. Each maps to a specific SQL query that must be optimized with the indexes defined above.

`GET /api/flows` with query parameters: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `app_protocol`, `start_time`, `end_time`, `min_bytes`, `max_bytes`, `tls_sni`, `http_host`, `limit`, `offset`, `sort_by`, `sort_dir`.

The SQL for a flow query uses a dynamic WHERE clause. Build it using parameterized queries only — never string concatenation, which opens SQL injection vulnerabilities. libpqxx's prepared statements handle this correctly.

`GET /api/flows/:id` returns a single flow with all fields plus associated alerts and a link to its PCAP file if available.

`GET /api/flows/:id/packets` returns a link to download the PCAP file segment for that specific flow. In a full implementation this would seek to the packet offset in the PCAP file and stream only that flow's packets. For the initial version, returning the full PCAP file is acceptable.

`GET /api/metrics/history` with `metric_name`, `start_time`, `end_time`, `resolution` parameters. Resolution can be `1m`, `5m`, `1h`, `1d`. Each resolution maps to either the raw metrics table or a TimescaleDB continuous aggregate.

`GET /api/dns/slow` returns the DNS domains with highest average resolution time over a configurable window.

`GET /api/http/slow` returns HTTP endpoints with highest average latency.

`GET /api/storage/status` returns current disk usage, queue depth, write latency, PCAP file count, total flows stored, oldest data available.

---

## Data retention policies

Every table needs a retention policy. Without one, data grows forever until the disk fills.

Flows: 30 days. Use TimescaleDB's `add_retention_policy('flows', INTERVAL '30 days')`. This automatically drops old chunks.

Metrics: 90 days at 1-minute resolution. After 7 days, compress using `add_compression_policy`. After 90 days, drop. For hourly aggregates, keep indefinitely — they are tiny.

DNS transactions: 7 days.

HTTP transactions: 7 days.

Alerts: never automatically deleted. Let users manage manually.

AI conversations: never automatically deleted.

PCAP files: configurable by disk space limit rather than time. Default is 50 GB or 24 hours, whichever comes first. This is a deployment-time decision that depends on available storage.

---

## Connection pool

Never open a new database connection per query. Opening a PostgreSQL connection takes 30-100 milliseconds due to the TCP handshake, authentication, and session setup. Use a connection pool.

Use libpqxx with a connection pool of 8-16 connections. The write thread uses 2-4 connections (one per table for parallel bulk inserts). The REST API uses the remaining connections for read queries. This allows 12+ concurrent read queries without waiting for a write to finish.

The connection pool must handle connection failures gracefully. PostgreSQL connections drop if the server restarts, if the connection is idle for too long, or if the network hiccups. Each connection in the pool must be validated before use and re-established if dead. libpqxx does not provide a built-in pool — you write a simple wrapper with a `std::vector<std::unique_ptr<pqxx::connection>>` and a semaphore to manage checked-out connections.

---

## Migrations and schema versioning

Database schemas change as the project evolves. Without a migration system, every schema change requires manual ALTER TABLE statements applied in the right order. Use a simple migration table:

Create a `schema_migrations` table with columns `version` as `INTEGER`, `applied_at` as `TIMESTAMPTZ`, `description` as `TEXT`. On startup, the StorageEngine checks the current schema version, compares it to the list of known migrations embedded in the code, and runs any that have not been applied yet. Each migration is a SQL string. Run them in a transaction so a failed migration leaves the database unchanged.

Start at version 1 and increment for every schema change. Never modify an existing migration — only add new ones. This gives you a complete audit trail of every schema change.

---

## Backup strategy

For a production deployment, configure PostgreSQL's continuous archiving. Every time a WAL segment fills (typically every 16 MB or 5 minutes), PostgreSQL can call a script to copy the segment to S3 or another storage location. Combined with a base backup taken weekly, this gives you point-in-time recovery to any moment in the last 7 days.

For the development and student version, a daily `pg_dump` to a compressed file is sufficient. Add a cron job that runs `pg_dump network_copilot | gzip > backup_$(date +%Y%m%d).sql.gz` and keeps the last 7 backups.

---

## Libraries to use

**libpqxx** — the standard C++ PostgreSQL client library. Mature, well-tested, supports prepared statements, transactions, bulk copy, and connection pooling. Use version 7.x which has a modern C++17 API. Install via `apt install libpqxx-dev` or vcpkg.

**PcapPlusPlus** — already used in Module 1 for capture; use `PcapFileWriterDevice` for PCAP writing. It handles the PCAP file header and per-packet headers automatically.

**Boost.Lockfree** — specifically `boost::lockfree::spsc_queue` for the write queue between the processing pipeline and the storage thread. Lock-free means the packet processing thread never blocks waiting for the storage thread to consume.

**nlohmann/json** — already used elsewhere; use it for serializing the `tags` and `metrics_context` JSONB columns.

**{fmt}** or `std::format` — for building SQL parameter strings efficiently without sprintf.

---

## Project structure

```
core/
└── storage/
    ├── storage_engine.hpp         ← public interface
    ├── storage_engine.cpp         ← wires all sub-components
    ├── write_queue.hpp            ← lock-free SPSC queue wrapper
    ├── batch_writer.hpp           ← dequeues and batches records
    ├── batch_writer.cpp
    ├── pg_connection_pool.hpp     ← connection pool
    ├── pg_connection_pool.cpp
    ├── pcap_file_manager.hpp      ← rolling PCAP files
    ├── pcap_file_manager.cpp
    ├── migrations/
    │   ├── migration_runner.hpp   ← checks version, runs pending
    │   └── migrations.cpp         ← SQL strings for each version
    ├── queries/
    │   ├── flow_queries.cpp       ← SELECT queries for REST API
    │   ├── alert_queries.cpp
    │   ├── metrics_queries.cpp
    │   └── dns_http_queries.cpp
    └── retention/
        └── retention_manager.cpp  ← enforces policies, deletes old PCAP files
```

---

## Implementation order

Do these steps in sequence. Each step produces something you can verify independently.

First, get PostgreSQL running and the schema created. Write the migration runner, define the initial schema as migration version 1, and run it. Verify the tables exist with `\dt` in psql.

Second, implement the connection pool. Write a test that opens 8 connections and executes a simple `SELECT 1` on each. Verify all succeed and connections are returned to the pool correctly.

Third, implement bulk flow writes without the queue. Directly write a batch of 100 hardcoded Flow objects using a multi-row INSERT. Measure how long it takes. This is your baseline write performance.

Fourth, add the write queue. Wrap the bulk writer in a thread, wire a `spsc_queue` between it and a test producer. Verify the producer never blocks and the writer drains the queue correctly.

Fifth, wire the write queue to the FlowEngine. Run a live capture for 30 seconds. Check PostgreSQL — you should see flow records appearing. Verify the row counts, check that IP addresses are stored correctly as INET, check timestamps.

Sixth, implement the PCAP file manager. Run a capture, verify a file is created, verify it rotates after 10 minutes, verify the compressed file opens correctly in Wireshark.

Seventh, implement metrics snapshot writes. Add a timer that calls `write_metrics_snapshot()` every 60 seconds. Verify rows appear in the metrics table with correct values.

Eighth, implement the query interface. Start with `GET /api/flows` with just `src_ip` filtering. Verify the query returns correct results. Add filters one by one.

Ninth, add DNS and HTTP transaction storage. Verify the tables populate during a `curl http://example.com` and `dig google.com` session.

Tenth, add the retention manager. Set a very short retention period (1 minute) in a test environment, verify that rows are deleted and PCAP files are removed. Then set the real retention periods.

---

## The one thing that trips everyone up

Write amplification. When you first wire everything together, you will discover that every `FLOW_UPDATED` event (which fires for every single packet) is being enqueued for storage. That means 100,000 entries per second hitting the queue for a busy network — far more than PostgreSQL can consume. You only want to write a flow record once, when it closes, not on every update. The `FlowEngine` emits `FLOW_CLOSED` and `FLOW_EXPIRED` events specifically for this reason. The storage engine should subscribe only to those two events for flow writes, not to `FLOW_UPDATED`. The `FLOW_UPDATED` events go to the metrics engine, not storage. Get this routing correct early and the write rate becomes completely manageable — a few thousand closed flows per second at most.