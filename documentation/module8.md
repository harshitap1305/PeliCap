## Module 8 — Frontend Dashboard: Complete Implementation Plan

---

## Technology stack decisions

**React with TypeScript** — TypeScript is non-negotiable for a project this size. You have complex data shapes coming from the API — flow records, parsed packet fields, metric snapshots, alerts, search results. Without types you will spend hours debugging why `flow.rtt_avg_us` is undefined when the field is actually called `rtt_avg_us` on one endpoint and `avg_rtt_us` on another. TypeScript catches these at compile time.

**Vite** as the build tool. Not Create React App which is abandoned, not Webpack which requires configuration. Vite starts in under a second, has native TypeScript support, and produces smaller bundles.

**React Router v6** for client-side routing. Each major page is a route.

**TanStack Query (React Query)** for all server state. This handles caching, background refetching, loading states, error states, and pagination automatically. Every API call in the dashboard goes through TanStack Query. Never use raw `useEffect` + `fetch` for data fetching.

**Recharts** for all charts and graphs. It is already in the tech stack from the original blueprint, it is React-native (not a D3 wrapper), and it handles responsive sizing well.

**TanStack Table (React Table)** for the packet explorer, flow explorer, and any other paginated table. It handles sorting, filtering, column visibility, virtualization, and pagination. The virtualization is critical — you cannot render 10,000 flow rows in the DOM without it.

**Zustand** for global client state — things like the currently selected capture session, the active time range filter, user preferences, sidebar collapse state. Zustand is simpler than Redux for this scope and has excellent TypeScript support.

**Socket.IO client** or native WebSocket for real-time updates. The dashboard overview page needs live packet counts, bandwidth graphs, and alert notifications without the user refreshing. The backend pushes updates every second via WebSocket.

**date-fns** for all date formatting and manipulation. Never use moment.js — it is huge and unmaintained.

**axios** for HTTP requests, wrapped inside TanStack Query's fetch functions. Configure a single axios instance with the base URL and default headers so every API call goes through one place.

---

## Design system and visual identity

This is the most important section to get right before writing a single component. Every visual decision flows from here. You decided on light theme, blue and white, professional, no gradients. Here is exactly what that means in practice.

**Color palette — be precise, use only these colors.**

The primary color is a medium professional blue: `#2563EB`. This is Tailwind's `blue-600` and it is the exact tone used by Linear, Vercel's dashboard, and Cloudflare's interface — tools that professional engineers trust. It is not the bright primary blue of Bootstrap which looks dated. It is not the dark navy of older enterprise tools. It is confident and modern.

The primary hover state is one shade darker: `#1D4ED8` (blue-700). Active/pressed state is `#1E40AF` (blue-800).

Background colors: page background is `#F8FAFC` (slate-50, a very slightly blue-tinted white that looks cleaner than pure `#FFFFFF` on a monitor). Card and panel backgrounds are pure `#FFFFFF`. This contrast between the slightly-off-white page and the pure-white cards creates depth without shadows.

Border color is `#E2E8F0` (slate-200). This is the single border color used everywhere — table borders, card borders, input borders, dividers. One shade. No exceptions.

Text colors: primary text is `#0F172A` (slate-900, near-black). Secondary text is `#475569` (slate-600). Muted/placeholder text is `#94A3B8` (slate-400). Never use pure `#000000` for text — it is too harsh on a white background.

Semantic colors for status indication: success is `#16A34A` (green-600) for text and `#DCFCE7` (green-50) for backgrounds. Warning is `#D97706` (amber-600) for text and `#FEF3C7` (amber-50) for backgrounds. Critical/error is `#DC2626` (red-600) for text and `#FEF2F2` (red-50) for backgrounds. Info is `#2563EB` (the primary blue) for text and `#EFF6FF` (blue-50) for backgrounds.

These four semantic colors are used exclusively for alerts, badges, and status indicators. Not for decoration.

**Typography.**

Font family: `Inter` loaded from Google Fonts. Inter was designed specifically for screen interfaces and is what Stripe, Linear, Notion, and most modern SaaS products use. Load only the weights you need: 400 (regular), 500 (medium), 600 (semibold).

Font sizes follow a strict scale: 12px for metadata and tiny labels, 13px for table cell content and secondary text, 14px for body text and form labels, 16px for card titles and section headers, 18px for page titles, 24px for large numbers on the overview cards.

Line height: 1.5 for body text, 1.25 for headings, 1.4 for table rows.

Letter spacing: slightly negative (-0.01em) for headings above 18px makes them feel tighter and more professional. Normal for body text.

**Spacing system.**

Use an 8px base unit. All margins, paddings, and gaps are multiples of 8: 4px, 8px, 12px, 16px, 24px, 32px, 48px, 64px. Never use arbitrary values like 11px or 22px. This discipline is what makes interfaces feel visually harmonious even without explicit design effort.

Card padding: 24px on all sides. Table cell padding: 12px vertical, 16px horizontal. Sidebar padding: 16px. Page content padding: 32px.

**Shadow system.**

Only one shadow level, used only on cards and dropdown menus: `box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04)`. That is it. No large dramatic shadows. No multiple shadow layers. The goal is to lift cards slightly off the page background, not to make them look three-dimensional.

**Border radius.**

Cards: 8px. Buttons: 6px. Badges and tags: 4px. Input fields: 6px. Avatars and icons in circles: 50%. Be consistent — never mix 6px and 8px on the same component type.

**Component states.**

Every interactive element has exactly three states beyond default: hover, focus (with a visible blue ring for accessibility), and disabled. The hover state for buttons lightens or darkens the background by one shade. The focus state adds a 2px blue ring with a 2px offset. The disabled state reduces opacity to 50% and changes the cursor to not-allowed. These are not optional — they are required for professional feel.

---

## Application layout

The layout has three persistent regions that never change regardless of which page you are on.

**The top navigation bar** spans the full width at the top. It is 56px tall with a white background and a single bottom border in the border color. It contains: the product logo and name on the left (a small network icon SVG followed by "Network Copilot" in semibold), the current capture status indicator in the center (a green or red dot with text like "Capturing on eth0 — 2,341 packets/sec" or "No active capture"), and on the right a cluster of controls: the time range selector, a notifications bell with an unread count badge, and a settings gear icon.

**The left sidebar** is 240px wide, fixed, with a white background and a right border. It contains vertical navigation links to each major page. Each link has an icon on the left, the page name, and optionally a badge showing counts (like "3" next to Alerts when there are unread critical alerts). The active link has a blue-50 background and blue-600 text with a 2px left border in blue-600. The sidebar has a collapse button at the bottom that reduces it to 56px showing only icons.

**The main content area** fills the remaining space to the right of the sidebar and below the top bar. It has the slate-50 background. Content inside it lives in a max-width container of 1440px centered, with 32px padding on both sides.

---

## Page 1: Overview Dashboard

This is the landing page and the most frequently viewed. It must convey the current network health at a glance in under 3 seconds.

**Live stats strip** sits at the top of the page. It is a horizontal row of six metric cards, each showing a single number with a label and a trend indicator. The six metrics are: Packets Captured (total since session start), Bandwidth In (current Mbps), Bandwidth Out (current Mbps), Active Flows, Alerts (last hour), and Packet Loss Rate. Each card is pure white with the border and shadow. The number is 24px semibold in slate-900. The label is 12px in slate-500. The trend indicator is a small arrow icon and percentage in either green or red showing change from the previous minute.

These six cards update every second via WebSocket. The numbers animate smoothly using a counter animation rather than jumping instantly — seeing a number tick up from 2,341 to 2,398 looks alive and professional.

**Bandwidth chart** takes up the full width below the stats strip. It is a line chart showing inbound and outbound bandwidth over the last 5 minutes with 1-second granularity. The inbound line is blue-500. The outbound line is slate-400. The chart has a white background, no gridlines except horizontal ones in slate-100, axis labels in 12px slate-400, and a tooltip that appears on hover showing exact values at that timestamp. The tooltip is a white card with a shadow showing timestamp, in value, and out value. The chart is 280px tall. It updates every second by shifting new data in from the right and dropping old data off the left — a scrolling live chart effect.

**Two-column section** below the bandwidth chart. Left column (60% width) contains the active flows table. Right column (40% width) contains the alert feed.

The active flows table shows the top 20 flows by bytes in the current session. Columns: protocol badge (colored pill — TCP is blue, UDP is slate, DNS is amber, TLS is green), source (IP:port), destination (IP:port), bytes (formatted as KB/MB/GB), duration, RTT, and a status indicator. Clicking any row navigates to that flow's detail page. The table has no pagination — it shows only the top 20 and has a "View all flows" link at the bottom.

The alert feed shows the 10 most recent alerts. Each alert item has a colored left border (red for critical, amber for warning, blue for info), the alert title in 13px semibold, the timestamp in 12px slate-500, and a severity badge. Clicking an alert navigates to the Alerts page with that alert highlighted. When a new alert arrives via WebSocket it slides in from the top with a subtle animation and the older items shift down.

**Protocol breakdown section** below the two columns. A horizontal bar showing the percentage split between TCP, UDP, DNS, TLS, HTTP, and Other traffic. Each protocol has its own color (consistent throughout the entire dashboard). The bar is 24px tall with rounded ends. Below the bar, numeric labels show the percentage and actual byte count for each protocol. This does not use Recharts — it is a pure CSS flexbox bar.

**DNS and HTTP panels** side by side at the bottom. The DNS panel shows a small table of the top 5 queried domains with their query count and average resolution time. The HTTP panel shows the top 5 endpoints with their request count and p95 latency. Both panels have a "View all" link that navigates to the respective analytics page. Both update every 10 seconds via TanStack Query polling.

---

## Page 2: Packet Explorer

This is the Wireshark-like page. It is split into two panels stacked vertically.

**The top panel** is the packet list table. It occupies 60% of the viewport height. The columns are: number (packet sequence ID), time (relative timestamp in seconds since capture start, with microsecond precision, e.g. "0.000000", "0.000342"), source (IP:port), destination (IP:port), protocol (colored badge), length (bytes), and info (a one-line summary of the packet content exactly like Wireshark — "TCP SYN → 443", "DNS Query A google.com", "HTTP GET /api/users").

The table is virtualized using TanStack Virtual. With 100,000 packets, only the ~30 visible rows are in the DOM at any time. Scrolling through 100,000 rows is instant.

Row coloring is protocol-based, exactly like Wireshark but more subtle — light colored backgrounds rather than bright ones. DNS rows have an amber-50 background. HTTP rows have a blue-50 background. TCP SYN/FIN/RST rows have a slate-50 background slightly different from normal TCP rows. This coloring helps experts scan quickly.

The packet list has a fixed toolbar above it containing: a BPF filter input (the full-width text field where users type Wireshark-style filters like `tcp port 443` or `host 8.8.8.8`), a filter apply button, a clear button, column visibility toggle, and an export button for downloading the current filtered view as a PCAP file.

The BPF filter input has syntax highlighting as you type — protocol keywords turn blue, IP addresses turn slate, operators stay black. It also shows validation errors inline — if the filter syntax is invalid a red underline appears with an error tooltip.

**The bottom panel** is the packet detail view, occupying the remaining 40%. It appears when a packet is selected in the top panel. It has three tabs.

The first tab is "Packet Details" — a tree view exactly like Wireshark's middle panel. Each protocol layer is a collapsible section. Ethernet frame shows as the first section with src MAC, dst MAC, and EtherType as children. IPv4 shows next with all parsed fields as children. TCP shows next with flags as an expandable subsection (each flag shown as a boolean). Application layer (DNS, HTTP, TLS) shows last. Clicking any field copies its value to clipboard. This tree is rendered as a recursive component.

The second tab is "Raw Bytes" — the hex dump view. Left column shows the byte offset in hex. Middle column shows the raw bytes in groups of 16, separated by spaces, with a gap between byte 8 and byte 9. Right column shows the ASCII representation with dots for non-printable characters. When a field is selected in the detail tree the corresponding bytes in the hex dump are highlighted in blue — exactly like Wireshark. This is the most impressive feature of the packet explorer and worth spending significant time on.

The third tab is "AI Explanation" — an AI-generated plain English explanation of the selected packet. "This is a TCP SYN packet from 10.0.0.1 to 8.8.8.8 on port 443. It is initiating a TLS connection, likely to a Google service. The sequence number 1234567890 will be used to track the order of subsequent packets in this connection." This calls the AI Copilot API and streams the response. It is especially useful for the Learning Mode use case.

**The divider** between the top and bottom panels is draggable. Users can drag it up or down to give more space to the list or the detail view. The position is saved to localStorage.

---

## Page 3: Flow Explorer

The flow explorer shows conversations rather than individual packets.

**The filter bar** at the top has dropdown filters for: time range, protocol, application protocol, source IP input, destination IP input, port input, minimum bytes slider, TCP state dropdown, and a search field that uses the Module 7 query language. All filters are applied simultaneously and update the table in real time as the user types or selects.

**The flow table** has these columns: flow ID (truncated, clickable), start time, duration (formatted as "2.4s" or "1m 32s"), source (IP:port with a flag icon for geolocation if available), destination (IP:port), protocol badge, application badge, bytes (with a mini horizontal bar showing the in/out split), packets, RTT, retransmits, state badge, and a quick-action menu.

The bytes column is particularly well designed — it shows the total formatted bytes with a small stacked bar visualization inside the cell. Blue represents inbound bytes, slate represents outbound bytes. A flow that is 80% download shows a mostly-blue bar. A flow that is 50/50 shows an even split. This lets users immediately see the direction of data transfer without reading numbers.

The state badge shows the TCP flow state: ESTABLISHED is a green badge, CLOSED is a slate badge, RESET is a red badge, SYN_SENT is an amber badge. For UDP flows it shows ACTIVE or EXPIRED.

Clicking a row expands it inline (accordion style) to show a summary of the flow: start and end timestamps, total duration, byte counts in both directions, RTT statistics (avg/min/p95), retransmission count, zero-window events, the application protocol details (SNI for TLS, host for HTTP, query for DNS), and associated alerts. There is a "View packets" button that navigates to the Packet Explorer filtered to this flow's 5-tuple, and an "Analyze with AI" button that opens the AI Copilot with this flow pre-loaded as context.

**The flow timeline** is a small visualization shown inside the expanded row. It is a horizontal timeline showing when packets occurred within the flow. Blue ticks represent forward packets, slate ticks represent reverse packets, red ticks represent retransmitted packets. This gives an immediate sense of the flow's behavior — a bursty download looks different from a steady stream.

**Pagination** uses the keyset pagination from Module 7. The "Load more" button at the bottom of the table appends the next page rather than replacing results. The current count is shown as "Showing 50 of approximately 12,400 flows."

**The flow comparison feature** allows selecting two flows with checkboxes and clicking "Compare" to open a side-by-side comparison panel. This is useful for comparing a slow flow with a fast flow to identify differences. The comparison panel shows both flows' statistics side by side with differences highlighted.

---

## Page 4: DNS Analytics

**The top section** shows four large metric cards in a row: Queries per Second (live), Average Resolution Time (ms), NXDOMAIN Rate (%), and Unique Domains (last hour). Each card shows the current value, a sparkline of the last 5 minutes, and the change from the previous hour.

**Resolution time distribution chart** takes the full width. It is a histogram with resolution time on the x-axis (0ms to 1000ms+) and query count on the y-axis. Bars are blue. A red vertical line marks the p95 threshold. A tooltip on hover shows the exact bucket range and count. This gives an immediate sense of whether DNS performance is bimodal (some queries fast, some very slow) or normally distributed.

**Two panels side by side** below the chart. Left panel: Top Queried Domains table. Columns are rank number, domain name (with a favicon if available), query count, average latency, p95 latency, NXDOMAIN count, and a sparkline of query rate over the last hour. Rows are sorted by query count descending. Right panel: Slowest Domains table. Same columns but sorted by average latency descending. The domain names in both tables are clickable — clicking a domain opens a detail drawer showing the full query history for that domain.

**The NXDOMAIN feed** below the two panels shows recent failed DNS lookups in a list. Each item shows the queried domain name, the client IP that made the request, the timestamp, and whether this domain has been queried multiple times (shown as a "3x" badge). A high volume of NXDOMAIN queries from one client is a suspicious pattern that this view makes immediately obvious.

**DNS query timeline** at the bottom. A scatter plot where x is time and y is resolution time in ms. Each dot is one DNS query. The dot color encodes success (blue) vs NXDOMAIN (red). This view reveals patterns — are the slow queries clustered in time (suggesting a DNS server issue at that moment) or spread out (suggesting certain domains are always slow)?

---

## Page 5: HTTP Analytics

The HTTP analytics page follows the same structure as DNS Analytics but for HTTP traffic.

**Top metric cards**: Requests per Second, Error Rate (%), p95 Latency (ms), and Unique Endpoints.

**Latency distribution histogram** full width showing request duration distribution from 0ms to 5000ms+.

**Two panels**: Top Endpoints (by request count) and Slowest Endpoints (by p95 latency). Each endpoint row shows the HTTP method as a colored badge (GET is blue, POST is green, PUT is amber, DELETE is red), the URL path, host, request count, p50 latency, p95 latency, p99 latency, error count, and a latency trend sparkline.

**Status code breakdown** shown as a horizontal stacked bar (similar to the protocol breakdown on the Overview) with sections for 2xx (green), 3xx (slate), 4xx (amber), and 5xx (red). Below the bar, each status code category shows its count and percentage.

**Error timeline** — a line chart showing error rate over the last hour. The y-axis is error percentage, x-axis is time. A horizontal dashed red line marks the alert threshold. When error rate exceeds the threshold the line turns red. This is the chart users look at first when investigating an HTTP incident.

**Request waterfall** — when a user selects a specific flow in the flow explorer and it is an HTTP flow, this panel shows the request waterfall — a horizontal bar chart where each bar represents one HTTP request in a session, positioned at its start time and sized by its duration. This is the same visualization used in browser DevTools. It makes HTTP/1.1 sequential vs HTTP/2 parallel behavior immediately visible.

---

## Page 6: Network Topology

This page shows the communication graph — which hosts are talking to which other hosts.

**The graph visualization** takes up the full page. Use a force-directed graph layout. Each node is a host (IP address). Node size is proportional to total bytes transferred. Node color is blue for internal IPs (RFC 1918 ranges) and slate for external IPs. Each edge connects two hosts that have communicated. Edge width is proportional to bytes transferred between them. Edge color encodes the dominant protocol.

The graph uses D3's force simulation directly (not through Recharts, which does not support graphs). The simulation has link force (pulls connected nodes together), charge force (pushes all nodes apart), center force (keeps the graph centered), and collision detection (prevents node overlap).

Clicking a node highlights all edges connected to it and shows a panel on the right with that host's statistics: total bytes, number of flows, top destination ports, protocols used, and any associated alerts.

The toolbar above the graph has: a time range selector, a filter to show only internal-to-external traffic or internal-to-internal traffic, a bytes threshold slider to hide low-traffic edges (so the graph does not become a hairball), a search box to highlight a specific IP, and a layout reset button.

The graph is not suitable for very large captures with thousands of unique IPs. When the unique IP count exceeds 200, show a warning and automatically apply the bytes threshold filter to show only the top 50 communicating pairs.

---

## Page 7: Alerts

**The alert list** is the primary view. Each alert is a card, not a table row, because alerts need more visual weight than flow records. The card has a colored left border (4px wide) in the severity color, the severity badge in the top right corner, the alert title in 16px semibold, the description in 14px slate-600, a row of metadata below the description (timestamp, affected IP addresses, observed value vs threshold), and two buttons: "Investigate" and "Dismiss."

"Investigate" opens a full-width drawer from the right side showing the complete alert detail and a pre-populated search query that finds the flows associated with the alert. If the alert is a port scan, the search shows all flows from the scanning IP. If the alert is a retransmission spike, the search shows the flows with the highest retransmission counts.

"Dismiss" marks the alert as acknowledged and moves it to the "Acknowledged" tab with a fade animation. Dismissed alerts are still stored — they are just visually separated.

**Three tabs** at the top: Active (unacknowledged alerts), Acknowledged (dismissed), and All (everything). The active tab shows a count badge with the current unread count.

**Filters above the list**: filter by severity (All, Critical, Warning, Info), filter by alert type (TCP, DNS, HTTP, Network, Security), and a time range filter.

**The alert timeline** is a small chart above the list showing alert frequency over the selected time range. Each severity has its own colored line. A spike in the timeline is immediately obvious and helps users understand whether they are looking at a one-off incident or an ongoing pattern.

**Real-time notifications** appear as toast notifications in the bottom right corner when a new critical alert arrives. The toast has the severity color, the alert title, and two buttons: "View" (navigates to alerts page) and "Dismiss." Toasts stack up to three deep and auto-dismiss after 8 seconds for warnings and never auto-dismiss for critical alerts.

---

## Page 8: AI Copilot

The AI Copilot page is a full-page chat interface.

**The left panel** (30% width) shows the context that the AI has access to. It has three collapsible sections. The first shows the current metrics snapshot — the same JSON that gets sent to the LLM, formatted as a readable table with metric names and values. The second shows recent alerts that are included in context (the last 10 alerts). The third shows the active time range filter.

This left panel is important for trust — users can see exactly what information the AI is working with. When the AI says "DNS latency is elevated," the user can look at the left panel and see the exact number the AI is referring to.

**The right panel** (70% width) is the chat interface. It has the conversation history at the top (scrollable), and a text input at the bottom. The input is a textarea that grows with content up to 4 lines. It has a send button on the right, a clear conversation button, and a model indicator showing which AI model is being used.

AI messages are rendered with markdown support — bold text, inline code, and code blocks render correctly. When the AI generates a search query as part of its response (like "You can investigate this with the query: `src_ip:10.0.0.1 AND retransmits > 5`"), the query is rendered as an inline chip with a "Run search" button that navigates directly to the Flow Explorer with that query applied.

**Suggested prompts** appear as clickable chips below the input when the conversation is empty. Suggested prompts include: "Why is my network slow?", "Show me suspicious traffic", "Explain what happened in the last hour", "Which service is using the most bandwidth?", "Are there any security concerns?", "Explain DNS resolution for google.com."

**The streaming response** from the AI renders token by token, not all at once. As the response streams in, a blinking cursor appears at the end of the last word. This matches the feel of ChatGPT and Claude and makes the AI feel responsive even for longer answers.

**Conversation history** is preserved in the current session and stored in PostgreSQL via the storage layer. A conversation list in a narrow sidebar to the left of the left panel shows past conversations with their first message as the title. Clicking a past conversation loads it.

---

## Page 9: Settings

The settings page has tabbed sections.

**Capture settings tab**: interface selector (dropdown showing all available interfaces from the API), BPF filter for capture (applied globally to reduce captured traffic), snaplen slider (96 to 65535), capture file rotation interval, maximum disk usage for PCAP files.

**Alert thresholds tab**: for each detector from Module 5, a row showing the detector name, a toggle to enable/disable it, the current static threshold with an editable number input, the current baseline value (read-only, computed by the engine), and the sigma multiplier slider.

**Retention tab**: flow retention days, metrics retention days, PCAP file retention, DNS transaction retention, HTTP transaction retention. Each with a number input and a storage estimate showing approximately how much disk space the current setting will use based on current traffic rates.

**Display preferences tab**: default time range for all pages (last 1h, 6h, 24h, 7d), packets per page in the packet explorer, flows per page in the flow explorer, default sort column, whether to show the AI explanation tab by default in the packet explorer.

**API tab**: shows the current API base URL, a generated API key for external access, and a list of recent API calls with their latency for debugging.

---

## Time range selector — used on every page

The time range selector in the top navigation bar is a critical shared component used on every page. It controls the time window for all data displayed across the entire dashboard.

It appears as a button showing the current selection, like "Last 1 hour" or "2024-01-15 14:00 — 15:00." Clicking it opens a popover with two sections. The left section has preset options: Last 5 minutes, Last 15 minutes, Last 1 hour, Last 6 hours, Last 24 hours, Last 7 days. The right section is a date range picker with two calendar inputs for custom ranges.

When the time range changes, all TanStack Query caches for data queries are invalidated and all charts, tables, and metrics on the current page refetch with the new time range. This is managed through Zustand — the time range is global state that every data fetching hook reads from.

The time range is also reflected in the URL as query parameters so sharing a URL preserves the time context.

---

## Real-time update architecture

The dashboard has two modes of data freshness.

**Live mode** is active during an ongoing capture. The overview page's bandwidth chart updates every second. The stats strip updates every second. New alerts appear in real time. This is powered by a WebSocket connection to the backend that pushes metric snapshots and alert events.

**Historical mode** is active when viewing past data. All data comes from PostgreSQL via normal REST API calls. TanStack Query polls every 30 seconds to pick up any newly written data.

The mode switch is automatic — if the selected time range includes the current moment, live mode is active for the most recent portion of the data. If the time range is entirely in the past, historical mode is used.

The WebSocket connection is managed by a single custom hook that the entire application uses. It reconnects automatically with exponential backoff on disconnection. A connection status indicator in the top bar shows whether the WebSocket is connected (green dot), reconnecting (amber dot), or disconnected (red dot).

---

## Loading states and error handling

Every single data-fetching component has three states handled explicitly.

**Loading state**: skeleton screens, not spinners. A skeleton is a gray animated placeholder that matches the shape of the content that will appear. A table skeleton shows the correct number of column headers and 5 rows of gray bars. A chart skeleton shows a gray rectangle. A metric card skeleton shows a gray bar where the number will be. Skeleton screens make the page feel faster because the layout does not shift when data loads.

**Error state**: a consistent error component showing an icon, a message, and a retry button. The message uses the error message from the API response if available, or a generic "Failed to load data" message. Network errors (no connection to backend) show a specific message "Cannot connect to the capture server. Make sure Network Copilot is running."

**Empty state**: when a query returns zero results, show an empty state illustration and a helpful message. For the flow explorer with an active search query, show "No flows matched your search. Try removing some filters." For the alerts page with no alerts, show "No alerts. Your network looks healthy." These are not just text — they include a simple line icon relevant to the context.

---

## Responsive behavior

The dashboard is primarily designed for desktop screens at 1440px width. It must also work at 1280px and 1920px. Mobile is explicitly not a priority — network monitoring is a desktop use case.

At 1280px the sidebar collapses to icon-only mode by default. At 1920px the main content area reaches its 1440px max-width and is centered.

The two-column sections (like the active flows + alert feed on the overview) become single-column on screens below 1100px width. Charts remain full-width at all sizes but reduce in height on smaller screens.

---

## Keyboard shortcuts

Professional tools have keyboard shortcuts. Add these as a global listener and document them on a help overlay (triggered by pressing `?`).

`G O` — go to overview. `G F` — go to flow explorer. `G P` — go to packet explorer. `G D` — go to DNS analytics. `G H` — go to HTTP analytics. `G A` — go to alerts. `G C` — go to AI copilot. `/` — focus the search input on any page that has one. `Escape` — close any open drawer, modal, or popover. `R` — refresh the current page's data. `T` — open the time range selector.

---

## Performance requirements

**Initial load time**: under 2 seconds for the first contentful paint on a localhost connection. Achieved through code splitting (each page is a lazy-loaded chunk), preloading critical data with TanStack Query's `prefetchQuery`, and serving assets with proper cache headers.

**Table rendering**: 100,000 rows in the packet explorer must scroll at 60fps. Achieved through TanStack Virtual — only ~30 DOM nodes exist at any time regardless of dataset size.

**Chart updates**: the live bandwidth chart updates every second and must not cause any visible jank. Recharts re-renders only the changed data points using React's reconciliation. The chart has `isAnimationActive={false}` because 1-second animations interfere with live data.

**Search results**: must appear within 500ms of the user stopping typing. Achieved by debouncing the search input by 300ms and using TanStack Query's `keepPreviousData` option so the previous results stay visible while new results load instead of showing a loading skeleton.

---

## Project structure

```
frontend/
├── public/
│   └── favicon.svg
├── src/
│   ├── api/
│   │   ├── client.ts              ← axios instance
│   │   ├── flows.ts               ← flow API functions
│   │   ├── packets.ts
│   │   ├── metrics.ts
│   │   ├── alerts.ts
│   │   ├── search.ts
│   │   ├── dns.ts
│   │   ├── http.ts
│   │   └── ai.ts
│   ├── components/
│   │   ├── layout/
│   │   │   ├── TopBar.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   └── PageLayout.tsx
│   │   ├── ui/
│   │   │   ├── Badge.tsx
│   │   │   ├── Button.tsx
│   │   │   ├── Card.tsx
│   │   │   ├── Skeleton.tsx
│   │   │   ├── Toast.tsx
│   │   │   ├── Drawer.tsx
│   │   │   ├── Tooltip.tsx
│   │   │   ├── Popover.tsx
│   │   │   ├── EmptyState.tsx
│   │   │   ├── ErrorState.tsx
│   │   │   └── Table.tsx
│   │   ├── charts/
│   │   │   ├── BandwidthChart.tsx
│   │   │   ├── LatencyHistogram.tsx
│   │   │   ├── TimelineChart.tsx
│   │   │   └── SparkLine.tsx
│   │   ├── packets/
│   │   │   ├── PacketTable.tsx
│   │   │   ├── PacketDetailTree.tsx
│   │   │   ├── HexDump.tsx
│   │   │   └── BpfFilterInput.tsx
│   │   ├── flows/
│   │   │   ├── FlowTable.tsx
│   │   │   ├── FlowRow.tsx
│   │   │   ├── FlowTimeline.tsx
│   │   │   └── FlowComparison.tsx
│   │   ├── alerts/
│   │   │   ├── AlertCard.tsx
│   │   │   ├── AlertDrawer.tsx
│   │   │   └── AlertTimeline.tsx
│   │   ├── search/
│   │   │   ├── SearchBar.tsx
│   │   │   └── SearchSuggestions.tsx
│   │   └── ai/
│   │       ├── ChatMessage.tsx
│   │       ├── ContextPanel.tsx
│   │       └── SuggestedPrompts.tsx
│   ├── pages/
│   │   ├── Overview.tsx
│   │   ├── PacketExplorer.tsx
│   │   ├── FlowExplorer.tsx
│   │   ├── DnsAnalytics.tsx
│   │   ├── HttpAnalytics.tsx
│   │   ├── NetworkTopology.tsx
│   │   ├── Alerts.tsx
│   │   ├── AiCopilot.tsx
│   │   └── Settings.tsx
│   ├── store/
│   │   ├── timeRange.ts           ← Zustand slice
│   │   ├── capture.ts
│   │   └── preferences.ts
│   ├── hooks/
│   │   ├── useWebSocket.ts
│   │   ├── useTimeRange.ts
│   │   ├── useKeyboardShortcuts.ts
│   │   └── useVirtualTable.ts
│   ├── types/
│   │   ├── flow.ts
│   │   ├── packet.ts
│   │   ├── alert.ts
│   │   ├── metrics.ts
│   │   └── search.ts
│   ├── utils/
│   │   ├── formatBytes.ts
│   │   ├── formatDuration.ts
│   │   ├── formatIp.ts
│   │   ├── protocolColors.ts
│   │   └── timeRange.ts
│   ├── App.tsx
│   └── main.tsx
├── index.html
├── vite.config.ts
├── tsconfig.json
└── package.json
```

---

## Implementation order

Start with the design system foundation before any page. Build all the primitive UI components — Button, Badge, Card, Skeleton, Table — and verify they look exactly right before touching any data. Every page uses these primitives and if they are wrong the whole dashboard looks wrong.

Then build the layout — TopBar, Sidebar, PageLayout — with placeholder content in the main area. Get routing working so you can navigate between empty pages.

Then build the API client layer — the axios instance and all the typed API functions. Write TypeScript interfaces for every API response shape based on the JSON your backend modules produce.

Then build the Overview page first because it has the most components and forces you to solve the live data problem early. If the overview works with real data the other pages are easier.

Then the Flow Explorer because it is the most used investigative page. Then Packet Explorer. Then DNS and HTTP analytics which share the same pattern. Then Alerts. Then AI Copilot. Then Topology. Then Settings last.

---

## The one visual detail that separates professional from amateur

Protocol badges. Every table in the dashboard shows a protocol badge — a small pill showing TCP, UDP, DNS, TLS, HTTP. Most people make these with random colors or all the same blue. The professional approach is a carefully chosen fixed color palette where each protocol has a consistent color across the entire application: TCP is always blue-100 text blue-700, UDP is always slate-100 text slate-700, DNS is always amber-100 text amber-700, TLS is always green-100 text green-700, HTTP is always purple-100 text purple-700, ICMP is always red-100 text red-700. These colors never change based on context. A user who sees a green badge anywhere in the application immediately knows it is TLS without reading the text. That consistency is what makes an interface feel professional rather than assembled.