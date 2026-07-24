"""Context builder — orchestrates async context retrieval for each query type."""
import asyncio
import httpx
from dataclasses import dataclass, field

import config
from classifier.query_classifier import QueryType, extract_ip, extract_domain, extract_port
from context import metrics_fetcher, flow_fetcher, alert_fetcher
from context.context_formatter import format_full_context


@dataclass
class ContextPackage:
    text: str = ""                   # Final formatted text sent to LLM
    raw_summary: dict = field(default_factory=dict)
    raw_alerts: list = field(default_factory=list)
    raw_flows: list = field(default_factory=list)
    missing_sources: list[str] = field(default_factory=list)


async def _build_historical_context(
    query: str,
    query_type: QueryType,
    session_id: str,
) -> ContextPackage:
    """
    Build context for a historical (stopped) session.
    Reads flows and alerts from PostgreSQL via the history endpoints on self.
    The live C++ metrics endpoints are skipped (they return 0 for stopped sessions).
    """
    pkg = ContextPackage()
    base_url = "http://localhost:8001"  # self

    async with httpx.AsyncClient(timeout=8.0) as client:
        tasks: dict = {}
        tasks["flows"] = flow_fetcher.search_flows(
            client, query=query if query_type == QueryType.FLOW_INVESTIGATION else "",
            session_id=session_id, limit=20
        )
        tasks["alerts"] = asyncio.coroutine(
            lambda: client.get(
                f"{base_url}/ai/history/alerts?session_id={session_id}&limit=20"
            ).then(lambda r: r.json() if r.status_code == 200 else [])
        )() if False else asyncio.ensure_future(
            _fetch_hist_alerts(client, base_url, session_id)
        )
        tasks["summary"] = asyncio.ensure_future(
            _fetch_hist_summary(client, base_url, session_id)
        )

        results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values(),
                                                               return_exceptions=True)))

    # Unpack — tolerate individual errors
    pkg.raw_alerts = results.get("alerts") if isinstance(results.get("alerts"), list) else []
    pkg.raw_summary = results.get("summary") if isinstance(results.get("summary"), dict) else {}

    raw_flows_result = results.get("flows", {})
    if isinstance(raw_flows_result, dict):
        pkg.raw_flows = raw_flows_result.get("results", raw_flows_result.get("flows", []))
    elif isinstance(raw_flows_result, list):
        pkg.raw_flows = raw_flows_result

    # Build a synthetic summary header from session aggregate stats
    summary_lines = ["[HISTORICAL SESSION — capture is stopped, live metrics unavailable]"]
    s = pkg.raw_summary
    if s:
        total_flows = s.get("total_flows", 0)
        total_bytes = s.get("total_bytes", 0)
        avg_rtt     = s.get("avg_rtt_us", 0)
        proto_bd    = s.get("protocol_breakdown", [])
        alerts_info = s.get("alerts", {})
        summary_lines.append(f"Total flows stored: {total_flows}")
        if total_bytes:
            mb = total_bytes / 1_000_000
            summary_lines.append(f"Total data transferred: {mb:.1f} MB")
        if avg_rtt:
            summary_lines.append(f"Average RTT: {avg_rtt/1000:.1f} ms")
        if proto_bd:
            parts = ", ".join(f"{p['protocol']}: {p['count']}" for p in proto_bd[:5])
            summary_lines.append(f"Protocol breakdown: {parts}")
        if alerts_info:
            summary_lines.append(
                f"Alerts during session: {alerts_info.get('total', 0)} total "
                f"({alerts_info.get('critical', 0)} critical, "
                f"{alerts_info.get('warning', 0)} warning)"
            )

    if pkg.raw_alerts:
        summary_lines.append("\nRecent alerts:")
        for a in pkg.raw_alerts[:5]:
            summary_lines.append(f"  [{a.get('severity','?')}] {a.get('title','')}: {a.get('description','')[:120]}")

    if pkg.raw_flows:
        summary_lines.append(f"\nSample flows ({len(pkg.raw_flows)} loaded):")
        for f in pkg.raw_flows[:8]:
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.get("protocol", 0), "?")
            size = f.get("payload_bytes", 0) or (f.get("fwd_bytes", 0) + f.get("rev_bytes", 0))
            sni = f.get("tls_sni") or f.get("http_host") or ""
            summary_lines.append(
                f"  {proto} {f.get('src_ip','')}:{f.get('src_port','')} → "
                f"{f.get('dst_ip','')}:{f.get('dst_port','')} "
                f"({size/1000:.1f} KB){' [' + sni + ']' if sni else ''}"
            )

    pkg.text = "\n".join(summary_lines)
    return pkg


async def _fetch_hist_alerts(client: httpx.AsyncClient, base_url: str, session_id: str) -> list:
    try:
        r = await client.get(f"{base_url}/ai/history/alerts?session_id={session_id}&limit=20")
        return r.json() if r.status_code == 200 else []
    except Exception:
        return []


async def _fetch_hist_summary(client: httpx.AsyncClient, base_url: str, session_id: str) -> dict:
    try:
        r = await client.get(f"{base_url}/ai/history/session-summary?session_id={session_id}")
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


async def build(
    query: str,
    query_type: QueryType,
    session_id: str,
    is_live: bool = True,
) -> ContextPackage:
    """Build context package for a given query type. All fetches run concurrently."""
    # Historical sessions: skip live C++ metrics (they return 0), use PostgreSQL
    if not is_live:
        return await _build_historical_context(query, query_type, session_id)

    pkg = ContextPackage()

    async with httpx.AsyncClient(timeout=5.0) as client:

        # ── Base context: always fetched ──────────────────────────────────────
        tasks = {
            "summary":  metrics_fetcher.fetch_metrics_summary(client, window=60),
            "alerts":   alert_fetcher.fetch_alerts(client, session_id=session_id,
                                                   severity="INFO", limit=10),
            "stats":    metrics_fetcher.fetch_capture_stats(client),
        }

        # ── Type-specific additional context ──────────────────────────────────
        if query_type == QueryType.HEALTH_CHECK:
            tasks["network"]  = metrics_fetcher.fetch_metrics_network(client, 60)

        elif query_type == QueryType.PERFORMANCE:
            tasks["summary5"] = metrics_fetcher.fetch_metrics_summary(client, window=300)
            tasks["dns"]      = metrics_fetcher.fetch_metrics_dns(client, 60)
            tasks["http"]     = metrics_fetcher.fetch_metrics_http(client, 60)
            tasks["tcp"]      = metrics_fetcher.fetch_metrics_tcp(client, 60)
            ip = extract_ip(query)
            if ip:
                tasks["flows"] = flow_fetcher.search_flows(
                    client, query=f"src_ip:{ip} OR dst_ip:{ip}",
                    session_id=session_id, limit=10
                )
            else:
                tasks["flows"] = flow_fetcher.fetch_slowest_flows(client, session_id, 10)

        elif query_type == QueryType.FLOW_INVESTIGATION:
            ip = extract_ip(query)
            domain = extract_domain(query)
            port = extract_port(query)
            if ip:
                q = f"src_ip:{ip} OR dst_ip:{ip}"
            elif domain:
                q = domain   # the search engine handles SNI / host matching
            elif port:
                q = f"dst_port:{port} OR src_port:{port}"
            else:
                q = ""
            tasks["flows"] = flow_fetcher.search_flows(
                client, query=q, session_id=session_id, limit=15
            )
            tasks["dns"]  = metrics_fetcher.fetch_metrics_dns(client, 60)
            tasks["http"] = metrics_fetcher.fetch_metrics_http(client, 60)

        elif query_type == QueryType.SECURITY:
            tasks["network"]    = metrics_fetcher.fetch_metrics_network(client, 60)
            tasks["sec_alerts"] = alert_fetcher.fetch_security_alerts(client, session_id)
            tasks["flows"]      = flow_fetcher.search_flows(
                client, query="", session_id=session_id, limit=20
            )

        elif query_type == QueryType.HISTORICAL:
            tasks["dns"]  = metrics_fetcher.fetch_metrics_dns(client, 300)
            tasks["http"] = metrics_fetcher.fetch_metrics_http(client, 300)
            tasks["flows"] = flow_fetcher.search_flows(
                client, query="", session_id=session_id, limit=10
            )

        elif query_type == QueryType.RECOMMENDATION:
            tasks["dns"]   = metrics_fetcher.fetch_metrics_dns(client, 60)
            tasks["http"]  = metrics_fetcher.fetch_metrics_http(client, 60)
            tasks["tcp"]   = metrics_fetcher.fetch_metrics_tcp(client, 60)

        # QueryType.EXPLANATION — minimal context, answer from LLM training knowledge
        # Only base context (summary + alerts) is used.

        # ── Execute all tasks concurrently ────────────────────────────────────
        results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values())))

    # ── Unpack ────────────────────────────────────────────────────────────────
    pkg.raw_summary = results.get("summary") or results.get("summary5") or {}
    pkg.raw_alerts  = results.get("sec_alerts") or results.get("alerts") or []

    raw_flows_result = results.get("flows", {})
    if isinstance(raw_flows_result, dict):
        pkg.raw_flows = raw_flows_result.get("flows", [])
    elif isinstance(raw_flows_result, list):
        pkg.raw_flows = raw_flows_result

    # Track missing sources
    for key, val in results.items():
        if not val:
            pkg.missing_sources.append(key)

    # ── Format into text ──────────────────────────────────────────────────────
    pkg.text = format_full_context(
        summary=pkg.raw_summary,
        alerts=pkg.raw_alerts,
        network=results.get("network"),
        tcp=results.get("tcp"),
        dns=results.get("dns"),
        http=results.get("http"),
        flows=pkg.raw_flows if pkg.raw_flows else None,
    )

    return pkg
