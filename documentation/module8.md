## Module 8 — Frontend Dashboard: Implementation Overview

This module covers the frontend architecture, state management, and page-by-page implementation of the PeliCap dashboard. The frontend is designed to be a highly responsive, session-aware single-page application (SPA) capable of handling both live real-time captures and historical data analysis.

---

## Technology Stack

The frontend is built with a modern, pragmatic React stack:

*   **React + Vite**: Fast build tooling and HMR. JSX is used for components.
*   **Tailwind CSS**: Utility-first CSS framework for rapid, consistent styling without managing separate stylesheets.
*   **React Router v6**: Client-side routing for navigating between dashboard views.
*   **Zustand**: Lightweight global state management, heavily utilized for the `captureStore` to manage session context across the app.
*   **TanStack Query (React Query)**: Handles all server state, data fetching, caching, and background polling. Essential for managing both live metrics polling and historical data fetching.
*   **Recharts**: Used for all charts and graphs (pie charts, bar charts, histograms).
*   **Lucide React**: Clean, consistent icon set used throughout the UI.
*   **Axios**: HTTP client for API requests.
*   **TanStack Virtual**: Used for virtualizing massive lists, specifically in the Packet Explorer to render thousands of packets smoothly.

---

## Core Architecture: Session-Awareness

The entire frontend is architected around **Session-Awareness**. The application can operate in two primary modes based on the state in `captureStore.js`:

1.  **Live Mode (`isCapturing: true`)**: The user has started a new capture. The UI polls high-frequency endpoints (e.g., `/api/metrics/http`) and listens to WebSockets for real-time packet counts and alerts.
2.  **Historical Mode (`isCapturing: false`)**: The user has selected a past session. The UI falls back to querying stored flows via the `/api/search` endpoint to derive analytics and statistics.

The `captureStore` (`sessionId`, `isCapturing`, `sessionName`) acts as the single source of truth. All TanStack Query keys include the `sessionId` to ensure data is properly scoped and caches are invalidated when switching sessions.

---

## Application Layout

The layout consists of three persistent regions:

*   **Top Navigation Bar (`TopBar.jsx`)**: Shows the current capture status, live packet/flow metrics, WebSocket connectivity status (WiFi icon), and a dynamic Alerts badge (bell icon). It reflects real-time status and removes any placeholder/dummy values.
*   **Sidebar (`Sidebar.jsx`)**: Left-side navigation with collapsible functionality. Contains links to Sessions, Overview, Flow Explorer, Packet Explorer, DNS Analytics, Web Analytics, Network Topology, Alerts, and AI Copilot. Includes dynamic badges (e.g., alert counts).
*   **Main Content Area**: The central workspace where page components are rendered. Features empty states for when no session is selected.

---

## Page Implementations

### 1. Sessions Management (`Sessions.jsx`)
The entry point of the application. Allows users to:
*   Start a new live capture on a selected network interface (with optional BPF filters).
*   Stop an active capture (which flushes in-memory flows to the database).
*   Select historical sessions from a paginated table for analysis.

### 2. Overview Dashboard (`Overview.jsx`)
Provides a high-level summary of the selected session.
*   **Historical Mode**: Derives "Total Flows" and "Session Duration" by querying the flows table (`/api/search`). Pulls actual packet capture/drop counts from the `capture_sessions` database table.
*   **Live Mode**: Displays real-time metrics polled from the backend.

### 3. Flow Explorer (`FlowExplorer.jsx`)
A powerful tool for analyzing network conversations.
*   Auto-loads flows on session selection.
*   Queries the backend `/api/search` endpoint (supporting advanced syntax like `dst_port=443 AND src_ip:10.0.0.0/8`).
*   Displays protocol badges, source/destination, SNI/App detection, bytes transferred, and duration.
*   Includes pagination controls and graceful empty states if flows haven't closed yet.

### 4. Packet Explorer (`PacketExplorer.jsx`)
Deep inspection of raw packets.
*   **Virtualization**: Uses `@tanstack/react-virtual` to render thousands of packets without DOM lag.
*   **Client-Side Filtering**: Supports a robust client-side filtering engine (`tcp`, `port 443`, `host 1.2.3.4`, etc.) applied instantly via an "Apply" button or Enter key.
*   **Detail Pane**: Clicking a packet opens a detailed breakdown of parsed fields (Ethernet, IPv4/IPv6, TCP/UDP, DNS, HTTP, TLS), selectively rendering only present layers and hiding null values.

### 5. Web Analytics (`HttpAnalytics.jsx`)
Comprehensive analysis of web traffic.
*   **Dual Protocol Support**: Detects and aggregates both plain HTTP (`http_host`) and HTTPS (`tls_sni`) traffic.
*   **Dual Mode**: In live mode, attempts to use real-time `/api/metrics/http`. In historical mode (or if live metrics are empty), it derives accurate stats by querying all closed flows via `/api/search`.
*   Displays a Protocol Breakdown (HTTP vs HTTPS) pie chart, Top Hosts by Requests/Traffic, and Slowest Connections.

### 6. DNS Analytics (`DnsAnalytics.jsx`)
Tracks domain resolution patterns.
*   Similar to Web Analytics, it utilizes dual-mode fetching, falling back to flow-derived stats (`/api/search` with an empty query) for robust historical analysis.
*   Avoids unsupported wildcard backend queries by using empty strings and client-side processing where necessary.

### 7. Network Topology (`NetworkTopology.jsx`)
Visualizes communication patterns.
*   Renders an interactive, SVG-based force-directed graph.
*   Nodes represent IP addresses (sized by traffic volume); edges represent flows (color-coded by dominant protocol like TCP/UDP).
*   Supports node dragging, zooming, and a detail panel when nodes are clicked.

### 8. Security Alerts (`Alerts.jsx`)
Displays anomalies detected during the session.
*   Queries `/api/alerts` scoped strictly to the current `session_id`.
*   Displays severity badges (CRITICAL, WARNING, INFO) and provides client-side text filtering by title or description.
*   Includes summary statistic cards for quick triaging.

---

## The "Flow Closure" Paradigm

A critical architectural concept implemented in the frontend is handling **Flow Closure**. 
Flows (HTTP, TLS, etc.) are only persisted to the PostgreSQL database when the connection closes (TCP FIN/RST) or times out (~60s). 
The frontend UI gracefully handles this by:
1. Explaining in empty states that traffic appears after connections close.
2. Relying on the `stopCapture` mutation to force-flush all in-memory flows to the database, instantly populating all historical views.