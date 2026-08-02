"""Report-specific AI prompt templates.
These produce structured document prose (NOT conversational text).
The AI is instructed to write like a senior network engineer.
"""

REPORT_SYSTEM_PROMPT = """You are a senior network engineer writing a professional network analysis report.
Your writing is objective, factual, and precise. You use specific numbers from the data.
You write in complete paragraphs — not bullet points. Your tone is appropriate for a business document.
You never speculate beyond what the data shows. You identify what is notable without asserting it is malicious.
You always mention specific IP addresses, domains, and metrics when they are available in the data."""


def traffic_summary_prompt(data: dict) -> str:
    total_bytes = data.get("total_bytes", 0)
    total_flows = data.get("total_flows", 0)
    avg_rtt = data.get("avg_rtt_us", 0)
    retransmits = data.get("total_retransmits", 0)
    proto_bd = data.get("protocol_breakdown", [])
    top_src = data.get("top_src_ips", [])[:5]
    session_start = data.get("session_start", "")
    session_end = data.get("session_end", "")

    proto_str = ", ".join(f"{p['protocol']}: {p['count']} flows ({p['bytes']/1e6:.1f}MB)"
                         for p in proto_bd[:5])
    src_str = ", ".join(f"{s['ip']} ({s['bytes']/1e6:.1f}MB)" for s in top_src)

    return f"""Write an executive summary for a network traffic analysis report. Use 3-5 paragraphs.
Cover: overall traffic health, notable patterns, any concerns, and a summary conclusion.

DATA:
  Session period: {session_start} to {session_end}
  Total flows: {total_flows}
  Total data transferred: {total_bytes/1e6:.1f} MB ({total_bytes/1e9:.3f} GB)
  Average RTT: {avg_rtt/1000:.1f} ms
  Total retransmits: {retransmits}
  Protocol breakdown: {proto_str or 'Not available'}
  Top source IPs: {src_str or 'Not available'}

Write the executive summary now:"""


def dns_report_prompt(data: dict) -> str:
    total = data.get("total_dns_flows", 0)
    unique = data.get("unique_domains", 0)
    avg_rtt = data.get("avg_rtt_us", 0)
    top_domains = data.get("top_domains", [])[:10]
    domains_str = "\n".join(f"  - {d['domain']}: {d['count']} queries, avg {d['avg_rtt_ms']}ms"
                            for d in top_domains)

    return f"""Write a DNS analysis narrative for a network report. Use 3-4 paragraphs.
Cover: DNS query volume, resolution performance, notable domains, and any patterns of concern
(such as high query rates to a single domain, very long resolution times, or unusual domain patterns).

DATA:
  Total DNS flows: {total}
  Unique domains queried: {unique}
  Average DNS RTT: {avg_rtt/1000:.1f} ms
  Top queried domains:
{domains_str or '  No DNS data available'}

Write the DNS analysis now:"""


def http_report_prompt(data: dict) -> str:
    total = data.get("total_http_flows", 0)
    avg_rtt = data.get("avg_rtt_us", 0)
    total_bytes = data.get("total_bytes", 0)
    top_hosts = data.get("top_hosts", [])[:10]
    hosts_str = "\n".join(
        f"  - {h['host']}: {h['count']} flows, avg {h['avg_rtt_ms']}ms, {h['total_bytes']/1e6:.1f}MB"
        for h in top_hosts
    )

    return f"""Write an HTTP/web traffic analysis narrative for a network report. Use 3-4 paragraphs.
Cover: overall HTTP traffic volume, notable web services contacted, performance characteristics,
and any latency or connectivity concerns.

DATA:
  Total HTTP/HTTPS flows: {total}
  Average round-trip time: {avg_rtt/1000:.1f} ms
  Total HTTP data transferred: {total_bytes/1e6:.1f} MB
  Top destinations:
{hosts_str or '  No HTTP data available'}

Write the HTTP analysis now:"""


def security_report_prompt(alerts: list, flows: list) -> str:
    alert_summary = "\n".join(
        f"  [{a.get('severity','?')}] {a.get('title','')}: {a.get('description','')[:120]}"
        for a in alerts[:20]
    )
    suspicious_flows = [f for f in flows
                        if f.get("retransmit_count", 0) > 5 or f.get("avg_rtt_us", 0) > 500_000]
    susp_str = "\n".join(
        f"  - {f.get('src_ip')}:{f.get('src_port')} → {f.get('dst_ip')}:{f.get('dst_port')} "
        f"({f.get('retransmit_count',0)} retransmits, {f.get('avg_rtt_us',0)/1000:.0f}ms RTT)"
        for f in suspicious_flows[:10]
    )

    return f"""Write a security-focused network analysis narrative for a network report. Use 3-5 paragraphs.
Describe what was observed. Do NOT assert that any traffic is malicious — describe what each pattern
COULD indicate and suggest further investigation. Be objective and factual.

ALERTS OBSERVED:
{alert_summary or '  No alerts during this session'}

FLOWS WITH ELEVATED METRICS:
{susp_str or '  No flows with elevated retransmits or RTT'}

Write the security analysis now:"""


def rca_prompt(incident_data: dict, flows: list, alerts: list) -> str:
    alert_str = "\n".join(
        f"  [{a.get('severity','?')}] {a.get('title','')} at {a.get('timestamp_ns','')}: "
        f"{a.get('description','')}"
        for a in alerts[:10]
    )
    critical_alerts = [a for a in alerts if str(a.get("severity","")).upper() == "CRITICAL"]
    affected_flows = flows[:20]
    flows_str = "\n".join(
        f"  - {f.get('src_ip')}:{f.get('src_port')} → {f.get('dst_ip')}:{f.get('dst_port')} "
        f"| RTT: {f.get('avg_rtt_us',0)/1000:.0f}ms | Retransmits: {f.get('retransmit_count',0)} "
        f"| Duration: {f.get('duration_ms',0)}ms"
        for f in affected_flows
    )

    return f"""You are writing a Root Cause Analysis (RCA) report for a network incident.
Structure your response with these exact section headings:

## Incident Summary
## Timeline
## Root Cause Analysis
## Contributing Factors
## Impact Assessment
## Recommendations

Use specific data from the incident. Be factual. Write in complete paragraphs under each heading.

INCIDENT DATA:
  Critical alerts fired: {len(critical_alerts)}
  Total alerts: {len(alerts)}

ALL ALERTS:
{alert_str or '  No alert data'}

AFFECTED FLOWS (sample):
{flows_str or '  No flow data available'}

SESSION STATS:
  {incident_data}

Write the complete RCA now:"""
