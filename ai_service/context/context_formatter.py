"""Context formatter — converts raw JSON from C++ backend into structured text for the LLM.

The [ELEVATED] annotations are the single most important thing for response quality.
"""
from context.baseline_tracker import tracker


def _fmt(val, digits: int = 1) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:.{digits}f}"
    return str(val)


def format_network(net: dict) -> str:
    bps_in = net.get("bps_in", 0)
    bps_out = net.get("bps_out", 0)

    def human_bps(b):
        if b >= 1e9: return f"{b/1e9:.1f} Gbps"
        if b >= 1e6: return f"{b/1e6:.1f} Mbps"
        if b >= 1e3: return f"{b/1e3:.1f} Kbps"
        return f"{b:.0f} bps"

    lines = [
        "NETWORK (last 60s):",
        f"  Bandwidth : {human_bps(bps_in)} in / {human_bps(bps_out)} out",
        f"  Packets   : {_fmt(net.get('packets_per_sec'), 0)}/sec",
        f"  Active flows: {net.get('active_flows', 'N/A')}",
        f"  New flows : {_fmt(net.get('new_flows_per_sec'), 1)}/sec",
    ]

    talkers = net.get("top_talkers", [])
    if talkers:
        lines.append("  Top talkers:")
        for t in talkers[:5]:
            ip = t.get("ip", "?")
            b = t.get("bytes", 0)
            lines.append(f"    {ip}: {b/1024:.1f} KB")

    return "\n".join(lines)


def format_tcp(tcp: dict) -> str:
    rtt_p50 = tcp.get("rtt_p50_us", 0)
    rtt_p95 = tcp.get("rtt_p95_us", 0)
    rtt_p99 = tcp.get("rtt_p99_us", 0)
    retransmit = tcp.get("retransmission_rate_pct", 0)

    rtt_p50_ms = rtt_p50 / 1000 if rtt_p50 else 0
    rtt_p95_ms = rtt_p95 / 1000 if rtt_p95 else 0

    retransmit_ann = tracker.annotate("tcp_retransmit_pct", retransmit, "%")
    rtt_p50_ann    = tracker.annotate("tcp_rtt_p50_us", rtt_p50, "µs")

    return "\n".join([
        "TCP QUALITY:",
        f"  RTT p50/p95/p99 : {rtt_p50_ms:.1f}ms / {rtt_p95_ms:.1f}ms / {rtt_p99/1000:.1f}ms",
        f"  Retransmission  : {retransmit_ann}",
        f"  Zero windows    : {tcp.get('zero_window_rate', 0):.2f}/sec",
        f"  RST rate        : {tcp.get('rst_per_min', 0):.1f}/min",
        f"  Avg flow dur    : {tcp.get('avg_flow_duration_ms', 0):.0f}ms",
    ])


def format_dns(dns: dict) -> str:
    avg = dns.get("avg_resolution_ms", 0)
    p95 = dns.get("p95_resolution_ms", 0)
    nxd = dns.get("nxdomain_rate_pct", 0)

    avg_ann = tracker.annotate("dns_avg_ms", avg, "ms")
    p95_ann = tracker.annotate("dns_p95_ms", p95, "ms")

    lines = [
        "DNS:",
        f"  Avg resolution : {avg_ann}",
        f"  p95 resolution : {p95_ann}",
        f"  NXDOMAIN rate  : {nxd:.2f}%",
        f"  Query rate     : {dns.get('queries_per_sec', 0):.1f}/sec",
    ]
    slowest = dns.get("slowest_domains", [])
    if slowest:
        lines.append("  Slowest domains:")
        for d in slowest[:3]:
            lines.append(f"    {d.get('domain','?')}: {d.get('avg_ms',0):.0f}ms avg")
    return "\n".join(lines)


def format_http(http: dict) -> str:
    p50 = http.get("latency_p50_ms", 0)
    p95 = http.get("latency_p95_ms", 0)
    p99 = http.get("latency_p99_ms", 0)
    err = http.get("error_rate_pct", 0)

    p50_ann = tracker.annotate("http_p50_ms", p50, "ms")
    p95_ann = tracker.annotate("http_p95_ms", p95, "ms")
    err_ann = tracker.annotate("http_error_pct", err, "%")

    lines = [
        "HTTP/HTTPS:",
        f"  Requests       : {http.get('req_per_sec', 0):.1f}/sec",
        f"  Latency p50/p95/p99: {p50_ann} / {p95_ann} / {p99:.1f}ms",
        f"  Error rate     : {err_ann}",
        f"  Server error   : {http.get('server_error_pct', 0):.2f}%",
    ]
    slowest = http.get("slowest_endpoints", [])
    if slowest:
        lines.append("  Slowest endpoints:")
        for e in slowest[:3]:
            lines.append(f"    {e.get('endpoint','?')}: {e.get('avg_ms',0):.0f}ms avg")
    return "\n".join(lines)


def format_alerts(alerts: list[dict]) -> str:
    if not alerts:
        return "ACTIVE ALERTS: None"
    lines = [f"ACTIVE ALERTS ({len(alerts)}):"]
    sev_map = {0: "INFO", 1: "WARNING", 2: "CRITICAL"}
    for a in alerts[:8]:
        sev = sev_map.get(a.get("severity", 0), "INFO")
        title = a.get("title", "Unknown alert")
        desc = a.get("description", "")
        obs = a.get("observed_value")
        thr = a.get("threshold_value")
        line = f"  [{sev}] {title}"
        if desc:
            line += f" — {desc}"
        if obs is not None and thr is not None:
            line += f" (observed: {obs:.1f}, threshold: {thr:.1f})"
        lines.append(line)
    return "\n".join(lines)


def format_flows(flows: list[dict], label: str = "FLOWS") -> str:
    if not flows:
        return f"{label}: No flows found."
    lines = [f"{label} ({len(flows)} results):"]
    for f in flows[:8]:
        src = f"{f.get('src_ip','?')}:{f.get('src_port','?')}"
        dst = f"{f.get('dst_ip','?')}:{f.get('dst_port','?')}"
        proto = "TCP" if f.get("protocol") == 6 else "UDP" if f.get("protocol") == 17 else "OTHER"
        sni = f.get("tls_sni") or f.get("http_host") or ""
        sni_str = f" ({sni})" if sni else ""
        bytes_total = (f.get("bytes_fwd", 0) or 0) + (f.get("bytes_rev", 0) or 0)
        rtt_us = f.get("rtt_avg_us") or f.get("avg_rtt_us", 0)
        rtt_ms = rtt_us / 1000 if rtt_us else 0
        retx = f.get("retransmit_count", 0) or 0
        dur_ms = f.get("duration_ms") or f.get("duration_us", 0) / 1000

        line = f"  Flow #{f.get('flow_id','?')}: {src} → {dst} [{proto}{sni_str}]"
        line += f"\n    Bytes: {bytes_total/1024:.1f}KB | Duration: {dur_ms:.0f}ms | RTT: {rtt_ms:.1f}ms | Retransmits: {retx}"
        lines.append(line)
    return "\n".join(lines)


def format_full_context(
    summary: dict,
    alerts: list[dict],
    network: dict | None = None,
    tcp: dict | None = None,
    dns: dict | None = None,
    http: dict | None = None,
    flows: list[dict] | None = None,
    flows_label: str = "FLOWS",
) -> str:
    """Assemble all context sections into the final prompt context block."""
    parts = []

    # Use network sub-key from summary if dedicated network dict not provided
    net_data = network or summary.get("network", {})
    tcp_data = tcp or summary.get("tcp", {})
    dns_data = dns or summary.get("dns", {})
    http_data = http or summary.get("http", {})

    if net_data:
        parts.append(format_network(net_data))
    if tcp_data:
        parts.append(format_tcp(tcp_data))
    if dns_data:
        parts.append(format_dns(dns_data))
    if http_data:
        parts.append(format_http(http_data))

    parts.append(format_alerts(alerts))

    if flows:
        parts.append(format_flows(flows, label=flows_label))

    return "\n\n".join(parts)
