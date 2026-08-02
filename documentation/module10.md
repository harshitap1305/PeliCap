## Module 10 — Reporting System: Complete Implementation Plan

---

## What this module does and why it completes the platform

Every module before this one operates in real time or near real time. Module 10 is the only module that produces artifacts — documents that exist independently of the running system, that can be emailed to a manager, attached to a ticket, stored in a wiki, or presented in a postmortem meeting.

The reporting system answers a fundamentally different question from the rest of the platform. While the dashboard answers "what is happening right now" and the AI Copilot answers "why is this happening," reports answer "what happened, when, why, and what did we do about it" in a form that persists after the incident is resolved and can be understood by people who never opened the dashboard.

There are four types of people who will use the reporting system. Network engineers and DevOps teams who need to document incidents for postmortems. Managers and non-technical stakeholders who want a summary of network health without logging into the dashboard. Security teams who need periodic reports of traffic patterns, anomalies, and potential threats. Students using the platform for learning who want to export an analysis of a captured session as a study document.

The reporting system produces five report types, supports three export formats, allows scheduled and on-demand generation, and integrates with the AI Copilot to produce narrative summaries rather than just tables of numbers.

---

## Technology stack decisions

**WeasyPrint** is the right choice for PDF generation in Python. It converts HTML and CSS to PDF with full support for page breaks, headers and footers, page numbers, tables, and charts rendered as SVG. It is pure Python with no headless browser dependency, which means it works reliably in Docker without installing Chrome. The alternative is Puppeteer or Playwright running a headless Chromium instance to render HTML to PDF — this works but adds 200-400MB to your Docker image and introduces browser dependency complexity. WeasyPrint produces slightly less pixel-perfect output than a browser renderer but is entirely sufficient for professional reports.

**Jinja2** for HTML templating. Your reports are HTML documents styled with CSS that WeasyPrint converts to PDF. Jinja2 is the standard Python templating engine, already familiar from Flask and FastAPI ecosystems, and handles loops, conditionals, filters, and template inheritance cleanly. Each report type has a Jinja2 HTML template.

**Matplotlib** for chart generation within reports. The live dashboard uses Recharts (JavaScript) but PDF reports need server-side chart rendering. Matplotlib generates charts as SVG or PNG that get embedded in the HTML template before WeasyPrint converts it to PDF. Configure Matplotlib to use the `Agg` backend (non-interactive, suitable for servers) and produce charts with a consistent visual style that matches the dashboard's blue and white palette.

**python-docx** for Word document export. Some users prefer editable Word documents over PDFs, especially managers who want to add commentary or insert reports into larger documents. python-docx generates `.docx` files programmatically with styles, tables, headers, and images.

**APScheduler** for scheduled report generation. APScheduler is a Python job scheduling library that supports cron-style schedules, interval-based schedules, and one-time future jobs. It runs inside the Python AI service container alongside FastAPI. It persists job definitions to PostgreSQL so scheduled reports survive service restarts.

**smtplib** with **email.mime** for email delivery of scheduled reports. These are Python standard library modules — no external dependency needed for basic SMTP. For production, wrap them in an async sender using `aiosmtplib`.

**Markdown** Python library for Markdown export. Some users want reports as Markdown files that can be committed to a git repository or pasted into Confluence/Notion. The `markdown` Python library converts Markdown to HTML for preview, but the raw Markdown file is the primary output for this format.

---

## The five report types

### Report Type 1: Traffic Summary Report

The traffic summary is the most general report. It describes everything that happened on the network during a specified time period. This is the report you send to a manager at the end of the week or include in a monthly review.

It covers total traffic volume (bytes in and out, formatted as GB or TB), peak bandwidth periods with timestamps, protocol distribution (percentage breakdown of TCP, UDP, DNS, TLS, HTTP, and other), top 20 talkers by bytes with IP addresses and reverse DNS names where available, top 20 destinations by bytes, new flow rate over time, and comparison to the previous equivalent period (this week versus last week, this month versus last month).

The narrative section uses the AI Copilot to generate three to five paragraphs describing the traffic patterns in plain English. It identifies what was normal, what was unusual, and any notable events. This narrative is generated once during report creation and embedded in the document — it is not regenerated each time the report is viewed.

Charts included: bandwidth over time as a line chart with separate series for inbound and outbound, protocol breakdown as a pie chart (this is the one place a pie chart is appropriate because the shares sum to 100% and there are fewer than 8 categories), top talkers as a horizontal bar chart, and traffic heatmap showing bytes per hour per day of the week.

### Report Type 2: DNS Report

The DNS report is focused entirely on DNS behavior. It is most useful for diagnosing application connectivity issues since almost all application failures involve DNS.

It covers total DNS queries during the period, query rate over time, unique domain count, resolution time distribution (the same histogram from the DNS Analytics page, rendered server-side), top 50 queried domains with query counts and average resolution times, top 10 slowest domains, NXDOMAIN rate over time and the domains that generated the most NXDOMAIN responses, DNS server performance if multiple resolvers are visible, failed queries and their distribution.

The narrative section uses the AI Copilot to describe DNS health, identify any resolution time issues, explain what the NXDOMAIN patterns suggest, and note any domains that appear suspicious based on naming patterns (very long random-looking domain names can indicate DNS-based C2 communication or data exfiltration).

Charts included: resolution time histogram, query rate over time line chart, top domains bar chart sorted by query count, NXDOMAIN rate over time line chart.

### Report Type 3: HTTP Performance Report

The HTTP performance report is aimed at backend engineers and DevOps teams monitoring API performance. It is the report you generate after a latency incident to understand what happened.

It covers request rate over time, response time distribution (p50, p95, p99 over time as separate lines on one chart), error rate over time, top 20 endpoints by request count, top 20 slowest endpoints by p95 latency, status code distribution, payload size distribution for requests and responses, and comparison to baseline where available.

The endpoint performance table is the centerpiece. Each row shows the HTTP method, the URL path, the hostname, request count, p50 latency, p95 latency, p99 latency, error count, error percentage, and average response size. Rows are sortable in the PDF by adding a note "sorted by p95 latency" to the table caption. The slowest endpoints are highlighted with a light amber background.

The narrative section uses the AI Copilot to identify the primary performance bottlenecks, compare performance to baseline, and call out any endpoint-specific issues that stand out.

Charts included: request rate over time, latency percentiles over time (three lines: p50, p95, p99), error rate over time, endpoint latency heatmap showing latency by endpoint and time of day.

### Report Type 4: Security Report

The security report documents anomalies, potential threats, and security-relevant network events. It is the report you attach to a security ticket or include in a periodic security review.

It covers all security alerts during the period (port scans, host scans, SYN floods, abnormal NXDOMAIN rates, traffic spikes), with full detail for each alert including the source IP, timeline of activity, severity, and current status (ongoing or resolved). It covers unusual traffic patterns — connections to unusual ports, connections to IPs with no reverse DNS resolution, protocols seen on non-standard ports (HTTP traffic on port 8443, SSH traffic on a non-22 port). It covers external connection analysis — what external IP ranges the internal network communicated with, with geographic information if available from a GeoIP database. It covers flow statistics for flagged connections.

This report never makes conclusions about whether traffic is malicious. It describes what was observed and leaves the classification to the security team. This is important both for accuracy and for liability.

The narrative section uses the AI Copilot to summarize the security events observed, describe what each pattern could indicate (without asserting it is malicious), and suggest what to investigate further.

Charts included: alert timeline showing when each alert fired and its severity, external connection map (a world map with dots for destination countries — use Matplotlib's Basemap or a simple SVG world map with country highlighting), top external destinations bar chart.

### Report Type 5: Root Cause Analysis Report

The RCA report is the most sophisticated report type. It is generated either manually after an incident or automatically when a critical alert fires and stays active for more than 5 minutes.

It covers the incident timeline — when the first anomaly was detected, how the metrics evolved, when alerts fired, and when conditions returned to normal. It covers the affected components — which flows, hosts, and services were involved. It covers the probable root cause identified by the AI based on the correlation of metrics, alerts, and flow data. It covers the impact assessment — how many flows were affected, what was the user-facing latency degradation, how long did the incident last. It covers recommended remediation steps based on the identified root cause.

The RCA is the one report type where the AI generates the majority of the content rather than just the narrative summary. The AI Copilot receives the full incident timeline, all metrics during the incident period, all flows with elevated anomaly metrics, all alerts that fired, and the baseline metrics from before the incident. It generates a structured analysis following the standard RCA format: what happened, why it happened (root cause), how to prevent it from happening again.

The AI's response for an RCA uses a specialized prompt template that instructs it to organize findings under headings: Incident Summary, Timeline, Root Cause Analysis, Contributing Factors, Impact Assessment, Recommendations. The response is formatted as Markdown which the report system renders into properly styled HTML sections.

Charts included: a timeline chart showing all affected metrics side by side during the incident window (RTT, retransmission rate, error rate, DNS latency all on one chart with a shared time axis — this correlation view is extremely powerful for RCA), bandwidth during the incident, alert timeline.

---

## Export formats

### PDF

PDF is the primary format and the most polished. The PDF has a cover page with the Network Copilot logo, the report type and title, the time period covered, the generation timestamp, and the name of the system that generated it. This is followed by an executive summary page — three to five bullet points summarizing the most important findings, written by the AI. Then the main content with charts, tables, and narrative text. Then an appendix with the full data tables that would be too large for the main body.

The PDF uses a professional typographic hierarchy. The cover page uses a large bold title in the primary blue color. Section headings are 16pt bold in slate-900. Body text is 11pt regular in slate-700. Table headers are 9pt semibold with a slate-100 background. Table body is 9pt regular with alternating white and slate-50 row backgrounds. Chart captions are 9pt italic in slate-500. Page headers show the report title and section name. Page footers show the page number and generation timestamp.

The PDF page size is A4 (international) with configurable US Letter. Margins are 20mm on all sides. Charts are sized to fill the column width while maintaining a 16:9 or 4:3 aspect ratio. Tables that exceed one page have the header row repeated on each page — this is a CSS property (`thead { display: table-header-group }`) that WeasyPrint supports.

### Markdown

The Markdown export is a plain text file with standard Markdown syntax. It contains the same content as the PDF but without the visual styling. Charts are replaced with ASCII art tables of the data they represent. This format is intended for pasting into wikis, GitHub issues, Confluence pages, or any system that renders Markdown.

The Markdown file has a YAML front matter block at the top with metadata: report type, time period, generation timestamp, and a list of key findings. This allows tools like Jekyll or Hugo to process the file and its metadata together.

### Word Document

The Word document uses python-docx with a custom style template. The styles in the template define the visual appearance — heading fonts, table styles, paragraph spacing — and are applied consistently throughout the document. This means users can modify the Word template to match their company's document style and all future reports will automatically follow the new style.

The Word document includes charts as PNG images embedded in the document. It includes tables as native Word tables that users can sort, filter, and edit. The narrative text sections are editable so users can add their own commentary or corrections before sharing.

---

## Report configuration — what users can control

Every report has a set of configuration options that the user sets before generating. These are presented as a form in the dashboard's reporting page.

**Time period**: preset options (last 24 hours, last 7 days, last 30 days) or custom date range with time picker.

**Interface filter**: generate the report for all interfaces or a specific one.

**Top N limits**: how many items to show in top talker tables, domain lists, and endpoint lists. Default is 20, configurable from 10 to 100.

**Include AI narrative**: toggle whether to include AI-generated narrative sections. Users who only want the data without the AI commentary can disable this. Disabling it also makes generation significantly faster since no Grok API calls are needed.

**IP anonymization**: replace the last two octets of all IP addresses with XX.XX in all output. Useful when sharing reports externally. `192.168.1.10` becomes `192.168.XX.XX`.

**Report sections**: checkboxes to include or exclude specific sections. A user generating a DNS report but only caring about the NXDOMAIN analysis can uncheck the resolution time and top domains sections.

**Comparison period**: toggle to include comparison to the equivalent previous period. Doubles the data retrieval time but adds significant context.

**Chart resolution**: standard (charts are smaller, file size is smaller) or high resolution (charts are larger, better for presentations).

---

## Scheduled reports

The scheduling system allows users to configure reports that generate automatically on a schedule and are delivered by email.

Each scheduled report configuration has these fields: report type, configuration options (all the same options as on-demand generation), schedule (daily at a specific time, weekly on a specific day, monthly on a specific date, or cron expression for power users), recipients (list of email addresses), subject line template, and whether to attach the report or include a link to download it.

The schedule is stored in PostgreSQL in a `scheduled_reports` table. APScheduler reads this table on startup and on any change. When a scheduled report fires, APScheduler calls the report generation function with the stored configuration, sends the result to all recipients, and records the execution in a `report_executions` table with the generation time, success or failure status, file size, and any error message.

Failed scheduled reports send a failure notification to the recipients with the error message and a link to the reporting page to regenerate manually.

The scheduler handles time zones correctly. All scheduled times are stored in UTC in the database. The configuration UI lets users select their local time zone and converts to UTC for storage. When displaying the schedule to the user, convert back to their local time zone.

---

## On-demand generation from the dashboard

On-demand report generation is triggered from the Reports page in the dashboard. The user selects the report type, configures the options, and clicks Generate.

The generation process is asynchronous. The frontend sends the generation request and receives a job ID immediately. The backend starts generating in a background task. The frontend polls `GET /api/reports/jobs/{job_id}` every 2 seconds to check status. The job status response includes a progress percentage and the current step description ("Fetching flow data... Generating charts... Composing PDF..."). When the job is complete, the status response includes a download URL.

Progress steps and their approximate percentage completion for a 7-day traffic summary report:

Fetching metrics data (0-15%), fetching flow records (15-30%), fetching DNS and HTTP data (30-40%), fetching alerts (40-45%), generating charts with Matplotlib (45-65%), generating AI narrative (65-80%, this is the slowest step if AI is enabled), composing HTML template (80-90%), converting to PDF with WeasyPrint (90-100%).

The download URL points to `GET /api/reports/{report_id}/download`. The file is streamed from the server with appropriate Content-Type and Content-Disposition headers. Reports are stored in a `reports/` directory in the container with a retention of 7 days — old report files are automatically deleted since users can regenerate them.

---

## The report generation pipeline in detail

The pipeline has six stages that run in sequence for every report generation.

**Stage 1: Data collection.** Call all necessary API endpoints on the C++ backend to collect the raw data for the report. These calls are made concurrently where the data is independent. For a 7-day report, this involves querying TimescaleDB for historical metric aggregates, querying the flows table with appropriate time filters, querying the DNS and HTTP transaction tables, and querying the alerts table. Store all retrieved data in a `ReportData` dataclass that is passed through the remaining stages.

**Stage 2: Data processing.** Compute derived values that the templates need but that were not directly stored. Calculate percentage changes from the comparison period. Compute statistical summaries (mean, median, standard deviation for latency distributions). Identify the top N items from larger datasets. Flag values that exceed thresholds for the highlighting system. This stage is pure computation with no I/O.

**Stage 3: Chart generation.** Generate all charts using Matplotlib. Each chart is produced as an SVG string (not a file) that gets embedded inline in the HTML template. SVG is preferred over PNG because it scales perfectly at any zoom level in the PDF and is smaller in file size for charts with few data points. For charts with many data points (time series with thousands of samples) use PNG at 150 DPI. Store all generated charts in the `ReportData` object as base64-encoded strings or SVG strings ready for template embedding.

Chart style configuration applies consistently across all charts: figure background is white, axes background is white, grid lines are slate-100 (very light), axis labels are slate-600 at 9pt, title is slate-900 at 11pt bold, the primary data series is the same blue-600 as the dashboard, secondary series is slate-400, the bandwidth chart's two series are blue-500 and slate-300, error indicators are red-600. No chart has a legend inside the chart area — legends go below the chart as a caption.

**Stage 4: AI narrative generation.** If the user enabled AI narrative, call the Grok API with a specialized reporting prompt. The reporting prompt is different from the chat prompt — it instructs the AI to produce structured document prose, not conversational text. It includes the processed data as context and specifies the exact sections to generate. The AI response is a Markdown document with section headings. Parse this Markdown into sections and store each section separately so the template can place each narrative in the correct location in the report.

The AI narrative for reports uses `grok-3-beta` rather than `grok-3-mini-beta` because report quality matters more than speed. Users are willing to wait 30-60 seconds for a high-quality report. The prompt for report narratives instructs the AI to write in a professional, objective tone appropriate for business documents, use specific numbers from the data, avoid speculative language, and write in complete paragraphs rather than bullet points (unlike the chat interface where bullet points are preferred).

**Stage 5: Template rendering.** Pass the `ReportData` object (including chart SVGs, AI narrative sections, and all processed data) to the Jinja2 template for the specific report type. The template produces a complete HTML document styled with embedded CSS. The CSS uses print-specific properties: `@page` for page size and margins, `page-break-before` and `page-break-inside: avoid` for controlling where page breaks occur, `@media print` for any print-specific overrides.

The HTML template structure is consistent across all report types: a cover page section, an executive summary section, a series of content sections each with a heading, optional narrative, charts, and tables, and an appendix section. Each content section uses a class that triggers a page break before it in the PDF.

**Stage 6: Export generation.** Take the rendered HTML and convert it to the requested format. For PDF, call WeasyPrint's `HTML(string=html_content).write_pdf()`. For Word, parse the HTML and use python-docx to reconstruct the content as a Word document. For Markdown, extract the text and table content from the HTML and convert it to Markdown syntax. Store the generated file and record the report in the `reports` PostgreSQL table.

---

## PostgreSQL schema for the reporting system

The `reports` table stores metadata about every generated report. Columns: `report_id` as BIGSERIAL, `report_type` as TEXT (traffic_summary, dns, http_performance, security, root_cause_analysis), `title` as TEXT, `time_period_start` as TIMESTAMPTZ, `time_period_end` as TIMESTAMPTZ, `format` as TEXT (pdf, docx, markdown), `file_path` as TEXT, `file_size_bytes` as BIGINT, `generation_time_ms` as INTEGER, `config` as JSONB (the full configuration options used), `ai_narrative_included` as BOOLEAN, `created_at` as TIMESTAMPTZ, `created_by` as TEXT.

The `scheduled_reports` table stores schedule configurations. Columns: `schedule_id` as BIGSERIAL, `report_type` as TEXT, `title` as TEXT, `config` as JSONB, `schedule_cron` as TEXT, `timezone` as TEXT, `recipients` as TEXT ARRAY, `subject_template` as TEXT, `is_active` as BOOLEAN, `last_run_at` as TIMESTAMPTZ, `next_run_at` as TIMESTAMPTZ, `created_at` as TIMESTAMPTZ.

The `report_executions` table stores each execution of a scheduled report. Columns: `execution_id` as BIGSERIAL, `schedule_id` as BIGINT references scheduled_reports, `report_id` as BIGINT references reports (null if generation failed), `started_at` as TIMESTAMPTZ, `completed_at` as TIMESTAMPTZ, `status` as TEXT (running, completed, failed), `error_message` as TEXT.

The `report_jobs` table tracks on-demand generation jobs. Columns: `job_id` as UUID, `status` as TEXT (queued, running, completed, failed), `progress_pct` as SMALLINT, `current_step` as TEXT, `report_id` as BIGINT (null until complete), `started_at` as TIMESTAMPTZ, `completed_at` as TIMESTAMPTZ, `error_message` as TEXT.

---

## Jinja2 template structure

Each report type has its own HTML template file. All templates inherit from a base template that provides the shared structure, CSS, header, footer, and cover page.

The base template defines CSS custom properties at the top: the color palette, typography scale, spacing values, and print-specific properties. It defines the page layout using CSS Grid with a header area, a footer area, and a main content area. The header and footer are fixed using `@page` CSS so they appear on every page.

Each report-specific template extends the base and fills in blocks: the cover page title and subtitle, the executive summary content, and the main content sections.

The Jinja2 filters defined for report templates handle common formatting tasks. A `format_bytes` filter converts raw byte counts to human-readable strings. A `format_duration` filter converts milliseconds to seconds or minutes as appropriate. A `format_timestamp` filter converts UTC timestamps to the user's timezone with a friendly format. A `highlight_if_high` filter adds a CSS class to a table cell if its value exceeds a threshold, enabling the amber highlighting for slow endpoints. A `trend_arrow` filter returns an up arrow, down arrow, or dash based on comparing current value to a previous value.

---

## REST API endpoints

`POST /api/reports/generate` — start on-demand generation. Body contains report_type, time_period_start, time_period_end, format, and all configuration options. Returns a job_id immediately.

`GET /api/reports/jobs/{job_id}` — check generation progress. Returns status, progress percentage, current step, and report_id when complete.

`GET /api/reports` — list generated reports. Supports filtering by report_type, format, and date range. Sorted by created_at descending.

`GET /api/reports/{report_id}` — get report metadata.

`GET /api/reports/{report_id}/download` — download the report file. Returns the file with appropriate Content-Type and Content-Disposition headers.

`DELETE /api/reports/{report_id}` — delete a generated report and its file.

`GET /api/reports/scheduled` — list all scheduled report configurations.

`POST /api/reports/scheduled` — create a new scheduled report.

`PUT /api/reports/scheduled/{schedule_id}` — update a scheduled report configuration.

`DELETE /api/reports/scheduled/{schedule_id}` — delete a scheduled report.

`POST /api/reports/scheduled/{schedule_id}/run-now` — trigger an immediate execution of a scheduled report outside of its schedule.

`GET /api/reports/templates` — list available report types with their configuration options and required data, so the frontend can dynamically build the configuration form.

---

## The Reports page in the dashboard

The Reports page in Module 8's dashboard has three sections.

The first section is the report generator — a form with the report type selector at the top (five cards with icons and descriptions, the selected one highlighted in blue), followed by the configuration options that appear dynamically based on the selected report type, and a Generate button at the bottom.

The second section is the recent reports list — a table showing all previously generated reports with columns for report type, time period, format, file size, generation time, and buttons to download or delete. Clicking the report type or time period link shows a preview.

The third section is the scheduled reports manager — a list of configured schedules with their report type, schedule description ("Every Monday at 09:00"), recipients, last run status, and next scheduled run time. An Add Schedule button opens a modal with the scheduling configuration form.

Report preview works inline in the browser. PDF reports are displayed using the browser's native PDF viewer in an iframe. Word documents show a simplified HTML preview (the same HTML template before WeasyPrint conversion). Markdown documents are rendered as HTML using the marked.js JavaScript library.

---

## RCA automatic generation

When a critical alert remains active for more than 5 minutes, the system automatically triggers an RCA report generation. This happens without user action.

The trigger logic runs in APScheduler as a job that checks every 60 seconds for critical alerts that have been active for 5 minutes and do not already have an associated RCA report. When it finds one, it starts RCA generation with a time window starting 15 minutes before the alert first fired and ending at the current time.

The automatically generated RCA is stored in the reports table with `created_by = 'auto'` to distinguish it from user-initiated reports. A WebSocket notification is sent to the dashboard telling it that an automatic RCA has been generated. The dashboard shows this as a banner notification: "Automatic RCA generated for critical alert: TCP SYN flood towards 10.0.0.5. Click to view."

The automatic RCA is a shorter version of the full RCA report — it focuses on the incident timeline, the metrics correlation, and the root cause analysis, and skips the full data appendix. This keeps generation time under 60 seconds even including the AI narrative generation.

---

## Email delivery

The email delivery system sends scheduled reports to configured recipients.

Email structure: the subject line uses the configured template with variables like `{report_type}`, `{date}`, `{period}`. A sensible default subject template is `[Network Copilot] {report_type} — {period}`. The email body is a brief HTML email with the Network Copilot logo, a one-paragraph summary of the report's key findings (the same executive summary from the report itself), a button to open the full report if the dashboard is accessible at a known URL, and the report file attached if the attachment option is enabled.

The email body is a minimal HTML email using table-based layout for maximum email client compatibility. No CSS Grid, no Flexbox — email clients have terrible CSS support. Inline styles only. Maximum width 600px. Background white. Primary color the same blue-600. The email looks professional but simple.

SMTP configuration is stored in environment variables: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_USE_TLS`, `SMTP_FROM_ADDRESS`. These are loaded from the `.env` file in the Docker Compose setup.

For development and testing, support a `DEBUG_EMAIL_OVERRIDE` environment variable that redirects all outgoing emails to a single test address regardless of the configured recipients. This prevents accidentally emailing real people with test reports during development.

---

## Project structure

```
ai_service/
└── reporting/
    ├── report_generator.py        ← orchestrates all six stages
    ├── report_types/
    │   ├── traffic_summary.py     ← data collection + processing for type 1
    │   ├── dns_report.py          ← type 2
    │   ├── http_performance.py    ← type 3
    │   ├── security_report.py     ← type 4
    │   └── root_cause_analysis.py ← type 5
    ├── data_collection/
    │   ├── metrics_collector.py   ← fetches historical metrics
    │   ├── flow_collector.py      ← fetches flow records
    │   ├── alert_collector.py     ← fetches alerts
    │   └── dns_http_collector.py  ← fetches DNS and HTTP transactions
    ├── charts/
    │   ├── chart_generator.py     ← Matplotlib chart factory
    │   ├── bandwidth_chart.py
    │   ├── latency_chart.py
    │   ├── protocol_chart.py
    │   ├── timeline_chart.py
    │   └── chart_styles.py        ← shared Matplotlib style config
    ├── ai_narrative/
    │   ├── narrative_generator.py ← calls Grok for report prose
    │   └── report_prompts.py      ← report-specific prompt templates
    ├── templates/
    │   ├── base.html              ← base Jinja2 template
    │   ├── traffic_summary.html
    │   ├── dns_report.html
    │   ├── http_performance.html
    │   ├── security_report.html
    │   ├── root_cause_analysis.html
    │   └── email_body.html
    ├── exporters/
    │   ├── pdf_exporter.py        ← WeasyPrint conversion
    │   ├── docx_exporter.py       ← python-docx conversion
    │   └── markdown_exporter.py   ← plain Markdown output
    ├── scheduler/
    │   ├── report_scheduler.py    ← APScheduler setup
    │   └── rca_trigger.py         ← automatic RCA detection
    ├── delivery/
    │   └── email_sender.py        ← SMTP delivery
    ├── storage/
    │   └── report_store.py        ← PostgreSQL operations
    └── api/
        └── report_routes.py       ← FastAPI endpoints
```

---

## Implementation order

Get WeasyPrint installed and producing a test PDF first. A simple "Hello World" PDF from an HTML string confirms that the WeasyPrint and Cairo dependencies are correctly installed in your Docker container. This is the step that most commonly fails due to missing system libraries and you want to find out early.

Then build the base Jinja2 template with the CSS styling but no data. Render it to PDF and confirm the cover page, headers, footers, and page numbers look correct.

Then build the Matplotlib chart generator starting with the bandwidth chart since it is the most common. Generate a test chart as an SVG string and embed it in the base template. Confirm it renders correctly in the PDF.

Then implement the data collection layer for the traffic summary report type. Write a function that calls all the necessary C++ API endpoints and returns a `TrafficSummaryData` dataclass. Print the collected data to verify it is correct before doing anything with it.

Then build the complete traffic summary report end-to-end without AI narrative. Collect data, generate charts, render the Jinja2 template, export to PDF. Review the output carefully — this is where you discover CSS issues and template bugs.

Then add AI narrative generation for the traffic summary. Test the Grok API call with the report context, verify the response is well-formatted prose, integrate it into the template.

Then implement the remaining four report types in order of complexity: DNS report (similar structure to traffic summary), HTTP performance report (more complex endpoint table), security report (different structure with alert-focused content), then RCA (most complex due to AI-heavy content).

Then implement the scheduling system with APScheduler. Test a schedule that fires every minute in development, verify it generates a report and stores it correctly.

Then implement email delivery. Test with the debug email override to verify the email format before enabling real SMTP.

Then implement the dashboard Reports page UI components.

Finally, implement the automatic RCA trigger and test it by injecting a critical alert and waiting for the automatic generation.

---

## The one thing that determines whether reports get used

Executive summary quality. Nobody reads a 20-page network report from beginning to end. Decision makers read the executive summary and maybe look at one or two charts. If the executive summary is a list of raw numbers ("DNS queries: 1,247,832. Average resolution time: 45ms. NXDOMAIN rate: 2.1%") nobody will read it. If the executive summary is three sentences of clear English ("Network performance was normal this week with one notable exception: DNS resolution times spiked to 410ms on Tuesday evening between 19:00 and 21:30, eight times the baseline of 45ms. This affected approximately 2,300 flows to external services. All other metrics including HTTP latency, TCP quality, and traffic volume remained within normal ranges.") every manager will read it and find it valuable.

This is exactly what the AI narrative generation is for. Invest time in the AI prompt for executive summaries specifically. Test it with dozens of different data scenarios. Refine it until it consistently produces the kind of executive summary that a senior engineer would write after reviewing the data. This is the feature that determines whether the reporting system gets used or gets ignored.

---

## Completing the platform

With Module 10 complete, all ten modules of Network Copilot are implemented. The platform captures raw packets at the wire level, parses every protocol layer, reconstructs flows, computes metrics across four dimensions, detects anomalies automatically, stores everything with intelligent retention, makes everything searchable with a custom query language, visualizes everything in a professional dashboard, answers questions in natural language through an AI assistant grounded in real data, and produces professional reports that communicate findings to any audience.

The resume description that was outlined in the original vision now accurately describes something you actually built: an AI-powered network observability platform capable of analyzing live traffic and PCAP captures, reconstructing TCP and UDP flows, detecting retransmissions, DNS bottlenecks and protocol anomalies, providing natural-language root cause analysis through an integrated AI assistant, and generating professional reports for both technical and non-technical audiences.