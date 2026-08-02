"""Report generator — orchestrates the 6-stage pipeline.

Stage 1: Data collection
Stage 2: Data processing
Stage 3: Chart generation
Stage 4: AI narrative generation (optional)
Stage 5: Jinja2 template rendering
Stage 6: Export to PDF / DOCX / Markdown
"""
import asyncio
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Awaitable

import config
from reporting.storage.report_store import store as report_store
from reporting.data_collection.collectors import (
    collect_flows, collect_session_summary,
    collect_alerts, collect_dns_stats, collect_http_stats,
)
from reporting.charts import chart_generator as cg
from reporting.ai_narrative.narrative_generator import generate_narrative
from reporting.ai_narrative.report_prompts import (
    traffic_summary_prompt, dns_report_prompt, http_report_prompt,
    security_report_prompt, rca_prompt,
)
from reporting.exporters.pdf_exporter import export_pdf
from reporting.exporters.markdown_exporter import export_markdown
from reporting.exporters.docx_exporter import export_docx
from jinja2 import Environment, FileSystemLoader, select_autoescape

# ── Jinja2 environment ────────────────────────────────────────────────────────
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(['html']),
)

# Register custom Jinja2 filters
_PROTO_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6'}


def _fmt_bytes(b):
    b = b or 0
    if b >= 1e9: return f"{b/1e9:.2f} GB"
    if b >= 1e6: return f"{b/1e6:.2f} MB"
    if b >= 1e3: return f"{b/1e3:.1f} KB"
    return f"{b:.0f} B"


def _fmt_rtt(us):
    us = us or 0
    if us == 0: return "0 ms"
    if us >= 1000: return f"{us/1000:.1f} ms"
    return f"{us:.0f} µs"


def _fmt_number(n):
    n = n or 0
    if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
    if n >= 1_000: return f"{n/1_000:.1f}k"
    return str(int(n))


def _fmt_ts(ms):
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime('%H:%M:%S')
    except Exception:
        return str(ms)


jinja_env.filters['format_bytes'] = _fmt_bytes
jinja_env.filters['format_rtt'] = _fmt_rtt
jinja_env.filters['format_number'] = _fmt_number
jinja_env.filters['format_ts'] = _fmt_ts
jinja_env.filters['proto_name'] = lambda p: _PROTO_MAP.get(p, f"Proto {p}")

# ── Report type labels ────────────────────────────────────────────────────────
REPORT_LABELS = {
    "traffic_summary": "Traffic Summary Report",
    "dns": "DNS Analysis Report",
    "http_performance": "HTTP Performance Report",
    "security": "Security Report",
    "root_cause_analysis": "Root Cause Analysis",
}

REPORT_TEMPLATES = {
    "traffic_summary": "traffic_summary.html",
    "dns": "dns_report.html",
    "http_performance": "http_performance.html",
    "security": "security_report.html",
    "root_cause_analysis": "root_cause_analysis.html",
}

# ── Progress updater type ─────────────────────────────────────────────────────
ProgressFn = Callable[[int, str], Awaitable[None]]


async def _noop_progress(pct: int, step: str):
    pass


# ── Main pipeline ─────────────────────────────────────────────────────────────

async def generate_report(
    job_id: str,
    report_type: str,
    session_id: str,
    fmt: str,          # "pdf" | "docx" | "markdown"
    include_ai: bool = True,
    top_n: int = 20,
    created_by: str = "user",
    progress_fn: ProgressFn = _noop_progress,
):
    """
    Run the complete 6-stage report generation pipeline.
    Updates the job record in PostgreSQL as it progresses.
    Returns the report_id on success, raises on failure.
    """
    t_start = time.monotonic()
    report_type_label = REPORT_LABELS.get(report_type, report_type)
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    # ── Stage 1: Data collection ─────────────────────────────────────────────
    await progress_fn(5, "Collecting flow data…")
    flows, alerts, summary = await asyncio.gather(
        collect_flows(session_id, limit=500),
        collect_alerts(session_id),
        collect_session_summary(session_id),
    )

    dns_stats = {}
    http_stats = {}
    if report_type in ("dns", "traffic_summary"):
        await progress_fn(15, "Collecting DNS statistics…")
        dns_stats = await collect_dns_stats(session_id)

    if report_type in ("http_performance", "traffic_summary"):
        await progress_fn(20, "Collecting HTTP statistics…")
        http_stats = await collect_http_stats(session_id)

    await progress_fn(30, "Data collection complete.")

    # ── Stage 2: Data processing ─────────────────────────────────────────────
    await progress_fn(35, "Processing data…")
    session_start = summary.get("session_start", "")
    session_end = summary.get("session_end", "")
    start_str = str(session_start)[:19] if session_start else "N/A"
    end_str = str(session_end)[:19] if session_end else "N/A"

    suspicious_flows = [
        f for f in flows
        if (f.get("retransmit_count") or 0) > 5 or (f.get("avg_rtt_us") or 0) > 200_000
    ]

    top_src_labels = [s["ip"] for s in summary.get("top_src_ips", [])[:top_n]]
    top_src_values = [s["bytes"] for s in summary.get("top_src_ips", [])[:top_n]]

    proto_bd = summary.get("protocol_breakdown", [])
    proto_labels = [p["protocol"] for p in proto_bd]
    proto_counts = [p["count"] for p in proto_bd]

    # ── Stage 3: Chart generation ────────────────────────────────────────────
    await progress_fn(40, "Generating charts…")
    charts = {}

    if proto_labels:
        charts["protocol_pie"] = cg.protocol_pie_chart(proto_labels, proto_counts)

    if top_src_labels:
        charts["top_src"] = cg.top_talkers_chart(
            top_src_labels[:10], top_src_values[:10], "Top Source IPs", "Bytes Sent"
        )

    if report_type == "dns" and dns_stats.get("top_domains"):
        dom_labels = [d["domain"] for d in dns_stats["top_domains"][:15] if d.get("domain")]
        dom_counts = [d["count"] for d in dns_stats["top_domains"][:15]]
        if dom_labels:
            charts["dns_rate"] = cg.top_talkers_chart(
                dom_labels, dom_counts, "Top Queried Domains", "Query Count"
            )

    if report_type == "http_performance" and http_stats.get("top_hosts"):
        h_labels = [h["host"] for h in http_stats["top_hosts"][:15] if h.get("host")]
        h_counts = [h["count"] for h in http_stats["top_hosts"][:15]]
        if h_labels:
            charts["top_hosts"] = cg.top_talkers_chart(
                h_labels, h_counts, "Top HTTP Destinations", "Flow Count"
            )

    if report_type == "security" and alerts:
        a_times = [str(a.get("timestamp_ns", ""))[:10] for a in alerts[:20]]
        a_sev = [str(a.get("severity", "INFO")).upper() for a in alerts[:20]]
        a_titles = [str(a.get("title", "")) for a in alerts[:20]]
        if a_times:
            charts["alert_timeline"] = cg.alert_timeline_chart(a_times, a_sev, a_titles)

    if report_type == "root_cause_analysis":
        series = {}
        if flows:
            rtt_series = [float(f.get("avg_rtt_us") or 0) / 1000 for f in flows[:50]]
            retx_series = [float(f.get("retransmit_count") or 0) for f in flows[:50]]
            if any(rtt_series): series["RTT (ms)"] = rtt_series
            if any(retx_series): series["Retransmits"] = retx_series
        if series:
            charts["rca_correlation"] = cg.rca_correlation_chart(
                [str(i) for i in range(len(list(series.values())[0]))], series
            )

    await progress_fn(60, "Charts generated.")

    # ── Stage 4: AI narrative ────────────────────────────────────────────────
    ai_narrative = ""
    if include_ai:
        await progress_fn(62, "Generating AI narrative…")
        prompt_map = {
            "traffic_summary": lambda: traffic_summary_prompt({**summary, "session_start": start_str, "session_end": end_str}),
            "dns": lambda: dns_report_prompt(dns_stats),
            "http_performance": lambda: http_report_prompt(http_stats),
            "security": lambda: security_report_prompt(alerts, flows),
            "root_cause_analysis": lambda: rca_prompt(summary, flows, alerts),
        }
        if report_type in prompt_map:
            max_tok = 1200 if report_type == "root_cause_analysis" else 800
            ai_narrative = await generate_narrative(prompt_map[report_type](), max_tokens=max_tok)
        await progress_fn(78, "AI narrative generated.")

    # ── Stage 5: Template rendering ──────────────────────────────────────────
    await progress_fn(80, "Rendering report template…")

    template_name = REPORT_TEMPLATES.get(report_type, "traffic_summary.html")
    template = jinja_env.get_template(template_name)

    ctx = dict(
        title=report_type_label,
        report_type_label=report_type_label,
        session_id=session_id,
        session_start=start_str,
        session_end=end_str,
        generated_at=now_str,
        format=fmt,
        ai_narrative_included=include_ai and bool(ai_narrative),
        primary_model=config.PRIMARY_MODEL,
        ai_narrative=ai_narrative,
        summary=summary,
        flows=flows,
        alerts=alerts,
        dns_stats=dns_stats,
        http_stats=http_stats,
        suspicious_flows=suspicious_flows,
        charts=charts,
    )
    html_content = template.render(**ctx)

    await progress_fn(88, "Template rendered.")

    # ── Stage 6: Export ──────────────────────────────────────────────────────
    await progress_fn(90, f"Exporting to {fmt.upper()}…")

    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())[:8]
    ext = {"pdf": "pdf", "docx": "docx", "markdown": "md"}.get(fmt, "pdf")
    file_path = os.path.join(config.REPORTS_DIR, f"{report_type}_{file_id}.{ext}")

    if fmt == "pdf":
        export_pdf(html_content, file_path)

    elif fmt == "docx":
        export_docx(
            title=report_type_label,
            report_type_label=report_type_label,
            session_id=session_id,
            session_start=start_str, session_end=end_str,
            summary=summary, ai_narrative=ai_narrative,
            flows=flows, alerts=alerts,
            output_path=file_path,
        )

    elif fmt == "markdown":
        md_content = export_markdown(
            report_type=report_type,
            title=report_type_label,
            session_id=session_id,
            session_start=start_str, session_end=end_str,
            summary=summary, ai_narrative=ai_narrative,
            flows=flows, alerts=alerts,
        )
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

    gen_ms = int((time.monotonic() - t_start) * 1000)
    await progress_fn(95, "Saving report record…")

    report_id = await report_store.save_report(
        report_type=report_type,
        title=report_type_label,
        session_id=session_id,
        time_start=session_start,
        time_end=session_end,
        fmt=fmt,
        file_path=file_path,
        generation_time_ms=gen_ms,
        cfg={"top_n": top_n, "include_ai": include_ai},
        ai_narrative=include_ai and bool(ai_narrative),
        created_by=created_by,
    )

    await progress_fn(100, "Report complete.")
    return report_id
