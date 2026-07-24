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


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await conv_store.init_db()
    yield


app = FastAPI(title="PeliCap AI Service", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    proto = pkt.get("transport", {}).get("protocol", "Unknown")
    src = f"{pkt.get('network', {}).get('src_ip', '?')}:{pkt.get('transport', {}).get('src_port', '')}"
    dst = f"{pkt.get('network', {}).get('dst_ip', '?')}:{pkt.get('transport', {}).get('dst_port', '')}"

    prompt = f"""Explain this network packet in plain English for a developer who is not a networking expert.
Be concise (3–5 sentences). State: what protocol it is, what it is doing, and what it means in context.

PACKET DATA:
  Protocol: {proto}
  Source: {src}
  Destination: {dst}
  Flags: {pkt.get('transport', {}).get('flags', {})}
  DNS query: {pkt.get('app', {}).get('dns_query_name', 'N/A')}
  HTTP method: {pkt.get('app', {}).get('http_method', 'N/A')}
  TLS SNI: {pkt.get('app', {}).get('tls_sni', 'N/A')}
  Length: {pkt.get('length', 'N/A')} bytes
"""
    try:
        result = await simple_completion(
            [{"role": "system", "content": SYSTEM_PROMPT},
             {"role": "user", "content": prompt}],
            max_tokens=250,
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
    bytes_fwd = f.get("bytes_fwd", 0) or 0
    bytes_rev = f.get("bytes_rev", 0) or 0
    rtt_us = f.get("rtt_avg_us") or 0
    retx = f.get("retransmit_count", 0) or 0
    dur_ms = f.get("duration_ms") or (f.get("duration_us", 0) or 0) / 1000

    prompt = f"""Explain this network flow as a concise narrative (4–6 sentences).
Cover: what the connection is, who initiated it, the data transfer pattern, and whether anything is unusual.

FLOW STATISTICS:
  {src} → {dst} [{proto}]
  Application: {sni or 'Unknown'}
  Duration: {dur_ms:.0f}ms
  Bytes sent: {bytes_fwd/1024:.1f}KB  |  Bytes received: {bytes_rev/1024:.1f}KB
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
