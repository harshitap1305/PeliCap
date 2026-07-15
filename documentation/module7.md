# Module 7: Search Engine

## Overview
Module 7 introduces a high-performance search engine to the PaliCap platform, enabling users to execute complex, real-time queries across millions of flow records. Without this module, users would be restricted to viewing only recent flows ordered by time. With it, users can pinpoint exact events using a domain-specific query language.

## Architecture & Components
The search engine is designed as a pipeline that takes a user query string and safely executes it against the TimescaleDB backend. The architecture consists of four primary phases:

### 1. Lexer (`core/search/query/lexer.cpp`)
**Purpose:** Tokenize the raw search string into a stream of actionable tokens.
**Implementation:** A hand-written, single-pass scanner over the query string. Hand-writing the lexer in C++ ensures maximum compilation speed, avoids heavy library dependencies (like Boost.Spirit), and provides highly descriptive error messages on failure.
**Key Features:** 
- Supports standard operators (`=`, `!=`, `<`, `>`, `:`, `~/`).
- Native recognition of IP and CIDR values (e.g. `10.0.0.0/8`).
- Understands quotes for string values that contain spaces.

### 2. Parser (`core/search/query/parser.cpp`)
**Purpose:** Convert the flat stream of tokens into an Abstract Syntax Tree (AST).
**Implementation:** A recursive descent parser that handles operator precedence. 
**Key Features:**
- Understands explicit boolean logic (`AND`, `OR`, `NOT`).
- Implements implicit `AND` operators (e.g., `src_ip:1.1.1.1 dst_port:443` acts as `src_ip:1.1.1.1 AND dst_port:443`).
- Handles complex nesting using parentheses.
- Checks `FieldRegistry` to validate that queried fields actually exist in the database and have the correct data types.

### 3. Query Planner (`core/search/planner/query_planner.cpp`)
**Purpose:** Translate the validated AST into highly optimized SQL `WHERE` clauses.
**Implementation:** Visits the AST nodes and constructs parameterized PostgreSQL queries.
**Key Features:**
- Safely binds user input to parameterized queries (`$1, $2, ...`) using `libpqxx` to eliminate SQL injection risks.
- Expands field operators into their optimal SQL equivalents (e.g., mapping IP lookups to PostgreSQL's `<<=` containment operator).
- Translates string regex queries (`~/`) to case-insensitive POSIX regex (`~*`).
- Injects a mandatory `session_id` parameter to automatically bound search queries by time-chunks.

### 4. Query Executor (`core/search/executor/search_executor.cpp`)
**Purpose:** Execute the planned SQL and format the results into a clean JSON response.
**Implementation:** Uses `libpqxx` to interact with PostgreSQL.
**Key Features:**
- Enforces time and resource limits.
- Retrieves core metrics (duration, bytes, ips, ports) and Application Layer details (TLS SNI, HTTP Host, DNS Query) to populate the frontend.
- Tracks execution latency and row counts.

## Key Design Decisions & Libraries

### **Why `re2`?**
For regex-based queries, `re2` was added to the project via `vcpkg`. While `std::regex` exists, it can suffer from catastrophic backtracking, opening the platform to ReDoS (Regular Expression Denial of Service) attacks. `re2` guarantees linear time execution, making it safe for arbitrary user inputs.

### **Session-Scoped Partitioning**
TimescaleDB achieves its speed via time-based chunk exclusion. If a query spans the entire database without a `start_time` bound, it performs a catastrophic full table scan. 
To prevent this, we evolved the schema to include `session_id` in the `flows` and `alerts` tables. 
- Every new capture spins up a unique UUID.
- All search queries automatically pass the active `session_id` as the primary bounding box constraint in the Query Planner, completely avoiding full table scans without requiring users to manually guess time windows.

### **Database Schema Upgrades (`pg_trgm`)**
To allow ultra-fast wildcard and substring queries (`LIKE '%google.com%'`), the `pg_trgm` extension is enabled in PostgreSQL. This powers high-speed regex and substring matches on heavy text fields like `tls_sni`, `http_host`, and `dns_query`.

## API Endpoints
The search engine is exposed through the primary application REST API:

- **`POST /api/search`**:
  Accepts a JSON payload:
  ```json
  {
    "query": "src_ip:10.0.0.1 AND (dst_port:80 OR dst_port:443)",
    "session_id": "uuid-here",
    "limit": 50,
    "offset": 0
  }
  ```
  Returns a parsed SQL execution plan, execution latency, and a structured array of matched flows.