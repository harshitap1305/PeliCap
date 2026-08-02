"""
PeliCap AI Service — FastAPI application.
Exposes the AI Copilot endpoints on port 8001.
"""
import asyncio
import json
import httpx
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import config
from models.schemas import (
    ChatRequest, ExplainPacketRequest, ExplainFlowRequest,
    AutoAnalyzeRequest, UsageResponse, HealthResponse,
)
from classifier.query_classifier import classify
from context.context_builder import build as build_context
from prompts.system_prompt import SYSTEM_PROMPT
from prompts.templates import build_prompt
from groq.groq_client import stream_chat, simple_completion, get_usage, record_usage
from conversation.conversation_store import store as conv_store
from streaming.sse_handler import stream_to_sse
from processing.response_processor import process as post_process
from rate_limiting.rate_limiter import limiter
from reporting.storage.report_store import store as report_store
from reporting.api.report_routes import router as report_router
from reporting.scheduler.rca_trigger import check_and_trigger_rca



# ── Lifespan ───────────────────────────────────────────────────────────────────
_scheduler: AsyncIOScheduler | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler
    # Initialize conversation DB
    await conv_store.init_db()
    # Initialize reporting DB tables
    await report_store.init_db()
    # Start APScheduler for auto-RCA trigger (every 60 seconds)
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(check_and_trigger_rca, 'interval', seconds=60,
                       id='rca_trigger', replace_existing=True)
    _scheduler.start()
    yield
    # Cleanup
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)


app = FastAPI(title="PeliCap AI Service", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include report routes ──────────────────────────────────────────────────────
app.include_router(report_router)


# ── POST /ai/chat ─────────────────────────────────────────────────────────────
@app.post("/ai/chat")
async def chat(req: ChatRequest):
    """Main streaming chat endpoint. Returns a Server-Sent Events stream."""
    # Rate limit
    allowed, reason = limiter.check(req.session_id)
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)

    # Message length guard
    if len(req.message) > 4000:
        raise HTTPException(status_code=400, detail="Message too long (max 4000 chars).")

    # Get or create conversation
    conv = conv_store.get_or_create(req.session_id, req.conversation_id)
    conversation_id = conv.conversation_id

    # Classify query
    query_type = classify(req.message)

    # Build context (concurrent fetches from C++ backend, or PostgreSQL for historical)
    ctx_pkg = await build_context(req.message, query_type, req.session_id, is_live=req.is_live)

    # Assemble prompt
    user_content = build_prompt(
        query_type,
        ctx_pkg.text,
        req.message,
        ctx_pkg.missing_sources or None,
    )

    # Build messages array for Groq
    history = conv_store.get_history_messages(conversation_id)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history)
    messages.append({"role": "user", "content": user_content})

    # Append user turn to store
    conv_store.append_turn(conversation_id, "user", req.message)

    async def on_complete(full_text: str, finish_reason: str):
        """Called after stream ends — persist conversation turn."""
        conv_store.append_turn(conversation_id, "assistant", full_text)
        proc = post_process(full_text)
        # Fire-and-forget DB persist
        asyncio.create_task(conv_store.persist(conversation_id))

    async def generate():
        # Inject conversation_id as first event so frontend can track it
        yield f"data: {json.dumps({'type': 'start', 'conversation_id': conversation_id, 'query_type': query_type.value})}\n\n"

        groq_gen = stream_chat(messages)
        async for chunk in stream_to_sse(groq_gen, on_complete=on_complete):
            yield chunk

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"X-Conversation-Id": conversation_id,
                                      "Cache-Control": "no-cache"})


# ── GET /ai/conversations ──────────────────────────────────────────────────────
@app.get("/ai/conversations")
async def list_conversations(session_id: str):
    return conv_store.list_by_session(session_id)


# ── GET /ai/conversations/{id} ────────────────────────────────────────────────
@app.get("/ai/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    conv = conv_store.get(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {
        "conversation_id": conv.conversation_id,
        "session_id": conv.session_id,
        "messages": conv.messages,
        "created_at": conv.created_at,
        "updated_at": conv.updated_at,
    }


# ── DELETE /ai/conversations/{id} ────────────────────────────────────────────
@app.delete("/ai/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    deleted = conv_store.delete(conversation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"status": "deleted"}


# ── POST /ai/explain-packet ───────────────────────────────────────────────────
@app.post("/ai/explain-packet")
async def explain_packet(req: ExplainPacketRequest):
    """Returns a plain-English explanation of a single packet."""
    pkt = req.packet

    # ── Transport protocol ────────────────────────────────────────────────────
    proto_num = pkt.get("transport", {}).get("protocol")
    if isinstance(proto_num, str):
        proto_num = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(proto_num.upper(), 0)
    transport = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(proto_num, f"Proto {proto_num}")

    # ── App protocol — try field first, then port lookup ─────────────────────
    app_proto = pkt.get("app_protocol", "")
    if isinstance(app_proto, int):
        _ap_map = {1: "HTTP", 2: "HTTPS/TLS", 5: "DNS", 3: "FTP", 4: "SMTP",
                   6: "SSH", 7: "DHCP", 8: "NTP", 9: "IMAP", 10: "POP3",
                   11: "QUIC", 12: "RDP", 13: "SNMP", 14: "MQTT"}
        app_proto = _ap_map.get(app_proto, "")

    src_port = pkt.get("transport", {}).get("src_port") or 0
    dst_port = pkt.get("transport", {}).get("dst_port") or 0
    src_ip   = pkt.get("network", {}).get("src_ip", "?")
    dst_ip   = pkt.get("network", {}).get("dst_ip", "?")
    length   = pkt.get("length") or pkt.get("frame_length") or 0

    # ── Well-known port → service name (used when app_proto is unknown) ───────
    _WELL_KNOWN = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP",
        110: "POP3", 143: "IMAP", 993: "IMAPS", 587: "SMTP/submission",
        8080: "HTTP-alt", 8443: "HTTPS-alt", 21: "FTP", 23: "Telnet",
        3389: "RDP", 5900: "VNC", 67: "DHCP-server", 68: "DHCP-client",
        123: "NTP", 161: "SNMP", 514: "Syslog", 1883: "MQTT",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    }

    # Determine direction: if src_port is a well-known port (≤1024) this is a RESPONSE
    is_response = src_port in _WELL_KNOWN or (src_port > 0 and src_port <= 1024)
    is_request  = dst_port in _WELL_KNOWN or (dst_port > 0 and dst_port <= 1024)

    service_port = src_port if is_response else dst_port
    service_name = _WELL_KNOWN.get(service_port, "")
    if not app_proto and service_name:
        app_proto = service_name

    direction = "response (server → client)" if is_response and not is_request else \
                "request (client → server)" if is_request else "peer-to-peer"

    # ── Packet size interpretation ────────────────────────────────────────────
    if length == 0:
        size_hint = "unknown size"
    elif length <= 54:
        size_hint = f"{length} bytes (TCP ACK with no payload — pure acknowledgment)"
    elif length <= 78:
        size_hint = f"{length} bytes (TCP handshake segment — SYN, SYN-ACK, or ACK; no application data)"
    elif length <= 200:
        size_hint = f"{length} bytes (small control/header packet — likely HTTP headers or a short response)"
    elif length <= 1500:
        size_hint = f"{length} bytes (data segment with payload)"
    else:
        size_hint = f"{length} bytes (large/jumbo frame)"

    # ── TCP flags ─────────────────────────────────────────────────────────────
    flags_raw = pkt.get("transport", {}).get("flags", {})
    if isinstance(flags_raw, dict):
        active_flags = [k.upper() for k, v in flags_raw.items() if v]
        flags_str = ", ".join(active_flags) if active_flags else "none"
    elif isinstance(flags_raw, int):
        flag_bits = {0x02: "SYN", 0x10: "ACK", 0x01: "FIN", 0x04: "RST",
                     0x08: "PSH", 0x20: "URG"}
        flags_str = ", ".join(name for bit, name in flag_bits.items()
                              if flags_raw & bit) or "none"
    else:
        flags_str = str(flags_raw) if flags_raw else "none"

    # ── App-layer hints ───────────────────────────────────────────────────────
    dns_query  = pkt.get("app", {}).get("dns_query_name") or pkt.get("dns_query_name") or ""
    http_meth  = pkt.get("app", {}).get("http_method") or ""
    tls_sni    = pkt.get("app", {}).get("tls_sni") or ""

    app_hints = []
    if dns_query: app_hints.append(f"DNS query for: {dns_query}")
    if http_meth: app_hints.append(f"HTTP method: {http_meth}")
    if tls_sni:   app_hints.append(f"TLS SNI (destination hostname): {tls_sni}")

    # ── Packet-specific system prompt (not the chatty copilot prompt) ─────────
    packet_system_prompt = (
        "You are a network packet analysis tool. Given packet metadata, produce a precise, "
        "factual 3–4 sentence explanation. Always state: (1) what protocol and service this is, "
        "(2) what the packet is doing (handshake, data, close, query, etc.), "
        "(3) the direction (who is the server, who is the client). "
        "Do not say 'unknown' if the port number already identifies the service. "
        "Be specific — name the port number and what service runs on it."
    )

    prompt = f"""Explain this network packet in plain English for a developer.

PACKET FACTS:
  Transport:   {transport}
  Application: {app_proto or f'port {service_port}' if service_port else 'unknown'}
  Direction:   {direction}
  Source:      {src_ip}:{src_port}
  Destination: {dst_ip}:{dst_port}
  Size:        {size_hint}
  TCP Flags:   {flags_str}
  {chr(10).join(f'  {h}' for h in app_hints) if app_hints else ''}

WELL-KNOWN PORT CONTEXT:
  Port {src_port} = {_WELL_KNOWN.get(src_port, 'ephemeral/unknown')}
  Port {dst_port} = {_WELL_KNOWN.get(dst_port, 'ephemeral/unknown')}

Write your explanation now (3–4 sentences):"""

    try:
        result = await simple_completion(
            [{"role": "system", "content": packet_system_prompt},
             {"role": "user", "content": prompt}],
            max_tokens=280,
        )
        return {"explanation": result}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI service error: {str(e)}")


# ── POST /ai/explain-flow ─────────────────────────────────────────────────────
@app.post("/ai/explain-flow")
async def explain_flow(req: ExplainFlowRequest):
    """Returns a narrative explanation of a complete flow."""
    f = req.flow
    src = f"{f.get('src_ip', '?')}:{f.get('src_port', '?')}"
    dst = f"{f.get('dst_ip', '?')}:{f.get('dst_port', '?')}"
    proto = "TCP" if f.get("protocol") == 6 else "UDP" if f.get("protocol") == 17 else "OTHER"
    sni = f.get("tls_sni") or f.get("http_host") or ""
    bytes_fwd = f.get("fwd_bytes", 0) or 0
    bytes_rev = f.get("rev_bytes", 0) or 0
    rtt_us = f.get("avg_rtt_us") or 0
    retx = f.get("retransmit_count", 0) or 0
    dur_ms = f.get("duration_ms") or (f.get("duration_us", 0) or 0) / 1000

    prompt = f"""Explain this network flow as a concise narrative (4–6 sentences).
Cover: what the connection is, who initiated it, the data transfer pattern, and whether anything is unusual.

FLOW STATISTICS:
  {src} → {dst} [{proto}]
  Application: {sni or 'Unknown'}
  Duration: {dur_ms:.0f}ms
  Bytes sent: {bytes_fwd}B  |  Bytes received: {bytes_rev}B
  RTT average: {rtt_us/1000:.1f}ms
  Retransmits: {retx}
  State: {f.get('state', f.get('tcp_state', 'N/A'))}
"""
    try:
        result = await simple_completion(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": prompt}],
            max_tokens=300,
        )
        return {"explanation": result, "flow_id": f.get("flow_id")}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI service error: {str(e)}")


# ── POST /ai/auto-analyze ─────────────────────────────────────────────────────
@app.post("/ai/auto-analyze")
async def auto_analyze(req: AutoAnalyzeRequest):
    """
    Called by the Overview dashboard every 5 minutes.
    Returns a 1–2 sentence network health summary.
    """
    from context.metrics_fetcher import fetch_metrics_summary
    from context.alert_fetcher import fetch_alerts
    from context.context_formatter import format_full_context

    async with httpx.AsyncClient(timeout=4.0) as client:
        summary, alerts = await asyncio.gather(
            fetch_metrics_summary(client, 60),
            fetch_alerts(client, session_id=req.session_id, severity="WARNING", limit=5),
        )

    ctx = format_full_context(summary=summary, alerts=alerts)
    prompt = f"""Given this 60-second network snapshot, write a 1–2 sentence health summary.
Be specific — mention the most important metric. Use plain English.

{ctx}"""

    try:
        result = await simple_completion(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": prompt}],
            max_tokens=120,
        )
        return {"summary": result, "session_id": req.session_id}
    except Exception as e:
        return {"summary": "AI analysis temporarily unavailable.", "error": str(e)}


# ── GET /ai/usage ─────────────────────────────────────────────────────────────
@app.get("/ai/usage", response_model=UsageResponse)
async def usage():
    return get_usage()


# ── GET /ai/health ────────────────────────────────────────────────────────────
@app.get("/ai/health", response_model=HealthResponse)
async def health():
    groq_status = "reachable"
    backend_status = "reachable"

    # Quick Groq ping
    try:
        await simple_completion(
            [{"role": "user", "content": "ping"}],
            max_tokens=5,
        )
    except Exception:
        groq_status = "unreachable"

    # Quick backend ping
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{config.BACKEND_URL}/api/test")
            if r.status_code != 200:
                backend_status = "unreachable"
    except Exception:
        backend_status = "unreachable"

    overall = "ok" if groq_status == "reachable" and backend_status == "reachable" else "degraded"
    return HealthResponse(groq=groq_status, backend=backend_status, status=overall)


# ── GET /ai/history/alerts?session_id=X&limit=N ──────────────────────────────
@app.get("/ai/history/alerts")
async def history_alerts(session_id: str, limit: int = 500, severity: str | None = None):
    """
    Read alerts from PostgreSQL for a given session.
    Used by the Alerts page when viewing historical (non-live) sessions.
    """
    if not conv_store._pool:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        sev_map = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
        min_sev = sev_map.get((severity or "").upper(), 0)

        async with conv_store._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT alert_id, type, severity, timestamp_ns, title, description,
                       src_ip::text, dst_ip::text, domain, endpoint,
                       observed_value, threshold_value, baseline_value,
                       is_ongoing, session_id
                FROM alerts
                WHERE session_id = $1
                  AND severity >= $2
                ORDER BY timestamp_ns DESC
                LIMIT $3
                """,
                session_id, min_sev, limit
            )

        sev_names = {0: "INFO", 1: "WARNING", 2: "CRITICAL"}
        type_names = {
            0: "UNKNOWN", 1: "TCP_RETRANSMIT_SPIKE", 2: "DNS_LATENCY_SPIKE",
            3: "HTTP_ERROR_SPIKE", 4: "PORT_SCAN_DETECTED", 5: "HOST_SCAN_DETECTED",
            6: "BANDWIDTH_SPIKE", 7: "FLOW_VOLUME_SPIKE", 8: "NXDOMAIN_SPIKE",
        }

        alerts = []
        for r in rows:
            alerts.append({
                "alert_id":        r["alert_id"],
                "type":            type_names.get(r["type"], str(r["type"])),
                "severity":        sev_names.get(r["severity"], "INFO"),
                "timestamp_ns":    r["timestamp_ns"],
                "title":           r["title"],
                "description":     r["description"],
                "src_ip":          r["src_ip"],
                "dst_ip":          r["dst_ip"],
                "domain":          r["domain"],
                "endpoint":        r["endpoint"],
                "observed_value":  r["observed_value"],
                "threshold_value": r["threshold_value"],
                "baseline_value":  r["baseline_value"],
                "is_ongoing":      r["is_ongoing"],
                "session_id":      r["session_id"],
            })
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /ai/history/session-summary?session_id=X ─────────────────────────────
@app.get("/ai/history/session-summary")
async def history_session_summary(session_id: str):
    """
    Returns aggregate stats for a historical session directly from PostgreSQL.
    Provides: total_flows, total_bytes, protocol_breakdown, alert_counts.
    """
    if not conv_store._pool:
        raise HTTPException(status_code=503, detail="Database not connected")
    try:
        async with conv_store._pool.acquire() as conn:
            flow_stats = await conn.fetchrow(
                """
                SELECT
                    COUNT(*)                       AS total_flows,
                    COALESCE(SUM(fwd_bytes + rev_bytes), 0)  AS total_bytes,
                    COALESCE(SUM(fwd_packets + rev_packets), 0) AS total_packets,
                    COALESCE(AVG(avg_rtt_us), 0)   AS avg_rtt_us,
                    COALESCE(AVG(retransmit_count), 0) AS avg_retransmit
                FROM flows WHERE session_id = $1
                """,
                session_id
            )
            proto_rows = await conn.fetch(
                """
                SELECT protocol, COUNT(*) as cnt
                FROM flows WHERE session_id = $1
                GROUP BY protocol ORDER BY cnt DESC
                """,
                session_id
            )
            alert_counts = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) FILTER (WHERE severity = 0)  AS info,
                    COUNT(*) FILTER (WHERE severity = 1)  AS warning,
                    COUNT(*) FILTER (WHERE severity = 2)  AS critical,
                    COUNT(*)                               AS total
                FROM alerts WHERE session_id = $1
                """,
                session_id
            )
            dns_stats = await conn.fetchrow(
                """
                SELECT
                    COALESCE(AVG(avg_rtt_us), 0) AS avg_rtt_us,
                    COUNT(*) AS count
                FROM flows
                WHERE session_id = $1 AND protocol = 17
                """,
                session_id
            )

        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_breakdown = [
            {"protocol": proto_map.get(r["protocol"], str(r["protocol"])), "count": r["cnt"]}
            for r in proto_rows
        ]

        return {
            "session_id":         session_id,
            "total_flows":        flow_stats["total_flows"],
            "total_bytes":        flow_stats["total_bytes"],
            "total_packets":      flow_stats["total_packets"],
            "avg_rtt_us":         float(flow_stats["avg_rtt_us"] or 0),
            "avg_retransmit":     float(flow_stats["avg_retransmit"] or 0),
            "protocol_breakdown": protocol_breakdown,
            "alerts": {
                "info":     alert_counts["info"],
                "warning":  alert_counts["warning"],
                "critical": alert_counts["critical"],
                "total":    alert_counts["total"],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
