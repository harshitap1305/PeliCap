## Module 10 — Reporting System: Final Implementation

---

## What this module does and why it completes the platform

Every module before this one operates in real time or near real time. Module 10 is the only module that produces artifacts — documents that exist independently of the running system, that can be attached to a ticket, stored in a wiki, or presented in a postmortem meeting.

The reporting system answers a fundamentally different question from the rest of the platform. While the dashboard answers "what is happening right now" and the AI Copilot answers "why is this happening," reports answer "what happened, when, why, and what did we do about it" in a form that persists after the incident is resolved and can be understood by people who never opened the dashboard.

The reporting system produces five report types, supports three export formats, allows on-demand generation scoped to a single capture session, and integrates with the AI Copilot to produce professional narrative summaries rather than just tables of numbers.

---

## Technology stack

**WeasyPrint** for PDF generation in Python. It converts HTML and CSS to PDF with full support for page breaks, headers and footers, page numbers, tables, and charts rendered as SVG/PNG. It is pure Python with C dependencies (`pango`, `cairo`), which means it works reliably in Docker without installing a headless browser like Chrome. 

**Jinja2** for HTML templating. Our reports are HTML documents styled with CSS that WeasyPrint converts to PDF. Jinja2 handles loops, conditionals, custom filters (like `format_bytes`, `format_rtt`), and template inheritance cleanly. Each report type has a dedicated Jinja2 template inheriting from a unified `base.html`.

**Matplotlib** for server-side chart generation. We configure Matplotlib to use the `Agg` backend (non-interactive, suitable for servers) and produce charts (Base64 PNGs) with a consistent visual style that matches the dashboard's blue and white palette. 

**python-docx** for Word document export. python-docx generates `.docx` files programmatically, embedding the exact same text, AI narratives, and Matplotlib charts.

**APScheduler** for automatic RCA generation. APScheduler runs a background job inside the Python AI service container that polls the PostgreSQL database for critical ongoing alerts and triggers automatic Root Cause Analysis (RCA) reports.

**FastAPI & asyncpg** for orchestration. The reporting pipeline is exposed via FastAPI endpoints (`/api/reports/*`). Progress is tracked in PostgreSQL, allowing the frontend to poll and display a live progress bar.

*(Note: Email delivery and cron-based scheduled reporting were deliberately omitted from this implementation to keep reports strictly scoped to the application dashboard and per session.)*

---

## The five report types

### Report Type 1: Traffic Summary Report
The traffic summary is the most general report. It describes everything that happened on the network during a specific capture session. It covers total traffic volume, peak bandwidth periods, protocol distribution, top 20 talkers by bytes, and top 20 destinations by bytes.
The narrative section uses the AI Copilot to generate paragraphs describing the traffic patterns in plain English.
*Charts included:* Protocol breakdown pie chart, Top talkers bar chart.

### Report Type 2: DNS Report
The DNS report is focused entirely on DNS behavior. It covers total DNS queries, query rate, unique domain count, resolution time distribution, top domains with query counts and average resolution times.
*Charts included:* DNS query rate timeline.

### Report Type 3: HTTP Performance Report
The HTTP performance report is aimed at diagnosing API performance. It covers request rates, response time distribution, top hosts by request count, and slowest hosts by p95 latency.
*Charts included:* Latency percentiles over time (p50, p95, p99), Error rate over time.

### Report Type 4: Security Report
The security report documents anomalies and potential threats. It covers all security alerts during the session (port scans, traffic spikes, high RTT), with full detail for each alert including the source IP, timeline, severity, and status. This report never makes definitive conclusions about whether traffic is malicious; it describes what was observed and leaves the classification to the security team.
*Charts included:* Alert timeline.

### Report Type 5: Root Cause Analysis (RCA) Report
The RCA report is the most sophisticated report type. It is generated either manually or automatically when a critical alert fires. It covers the incident timeline, affected components, and the probable root cause identified by the AI based on the correlation of metrics, alerts, and flow data.
The AI generates the majority of the content here using a specialized prompt template that organizes findings into: Incident Summary, Timeline, Root Cause Analysis, and Impact Assessment.

---

## Export formats

### PDF (Primary)
The PDF has a cover page with the PeliCap logo, report title, time period, and generation timestamp. This is followed by an executive summary page, and then the main content with charts, tables, and narrative text. It uses a professional typographic hierarchy (A4 size, print CSS, repeated table headers).

### Word Document (.docx)
The Word document uses python-docx. It includes charts as PNG images embedded in the document and tables as native Word tables. The narrative text sections are fully editable.

### Markdown
The Markdown export is a plain text file. It contains the same text content as the PDF, but replaces charts with simple data summaries. It includes a YAML front matter block at the top with metadata, making it perfect for pasting into wikis or GitHub issues.

---

## On-demand generation pipeline

On-demand report generation is triggered from the **Reports** page in the dashboard. The user selects the report type, export format, and whether to include the AI narrative, then clicks Generate.

The backend pipeline executes in 6 stages:
1. **Data Collection**: `asyncpg` queries collect flows, alerts, DNS stats, HTTP stats, and session summaries from PostgreSQL.
2. **Data Processing**: Computes derived values, statistical summaries, and identifies top talkers/domains.
3. **Chart Generation**: Generates Matplotlib PNG charts encoded as base64 strings.
4. **AI Narrative**: Calls the Groq LLM API (`llama-3.3-70b-versatile`) with a specialized reporting prompt to produce structured document prose.
5. **Template Render**: Jinja2 renders the HTML with charts and narratives embedded inline.
6. **Export**: WeasyPrint converts to PDF, python-docx converts to DOCX, or it's formatted as plain Markdown.

The frontend polls `/api/reports/jobs/{job_id}` every 2 seconds to check status, updating a progress bar. Once complete, the report is saved to PostgreSQL and the local filesystem (`/app/reports/`), ready for download.

---

## Auto-RCA Trigger

When a critical alert remains active for more than 5 minutes, the system automatically triggers an RCA report generation. 

This logic runs in `APScheduler` as a background job (`check_and_trigger_rca()`) that executes every 60 seconds. When it detects a qualifying alert (e.g., `severity = 2`, `is_ongoing = TRUE`, older than 5 mins), it spawns a background generation task.

The automatically generated RCA is stored in the `reports` table with `created_by = 'auto'` and appears in the dashboard's reports list with an "Auto-generated" label.

---

## The one thing that determines whether reports get used

**Executive summary quality.** Nobody reads a 20-page network report from beginning to end. Decision makers read the executive summary. If the executive summary is just a list of raw numbers, nobody will read it. If it is clear English prose explaining *what those numbers mean*, it provides immense value.

This is exactly what the AI narrative generation (`ai_narrative/narrative_generator.py`) achieves. By passing full context into a highly specific system prompt, the AI produces the kind of executive summary that a senior engineer would write after reviewing the data.

---

## Completing the platform

With Module 10 complete, all ten modules of PeliCap are implemented. The platform captures raw packets at the wire level, parses every protocol layer, reconstructs flows, computes metrics, detects anomalies automatically, stores everything with intelligent retention, makes everything searchable, visualizes everything in a professional dashboard, answers questions in natural language, and finally, produces professional reports that communicate findings to any audience.