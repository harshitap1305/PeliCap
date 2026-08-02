"""Data collectors for reports.
All collectors fetch data from the C++ backend at BACKEND_URL or directly from PostgreSQL.
Report types call these to collect raw data before chart generation.
"""
import asyncio
from datetime import datetime, timezone
from typing import Optional
import httpx
import asyncpg
import config


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dt(ts: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return None


async def _get_pg_pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=3)


# ── Flow collector ────────────────────────────────────────────────────────────

async def collect_flows(session_id: str, limit: int = 500) -> list[dict]:
    """Fetch all flows for a session from PostgreSQL."""
    try:
        pool = await _get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT flow_id, src_ip, dst_ip, src_port, dst_port,
                       protocol, app_protocol, tls_sni, http_host, dns_query,
                       duration_ms, fwd_bytes, rev_bytes, payload_bytes,
                       avg_rtt_us, retransmit_count, tcp_state, start_time, end_time
                FROM flows
                WHERE session_id = $1
                ORDER BY start_time DESC
                LIMIT $2
            """, session_id, limit)
        await pool.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DataCollector] collect_flows error: {e}")
        return []


async def collect_session_summary(session_id: str) -> dict:
    """Compute aggregate session stats from PostgreSQL flows."""
    try:
        pool = await _get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    COUNT(*)                           AS total_flows,
                    SUM(fwd_bytes + rev_bytes)         AS total_bytes,
                    SUM(fwd_bytes)                     AS total_fwd_bytes,
                    SUM(rev_bytes)                     AS total_rev_bytes,
                    AVG(avg_rtt_us)                    AS avg_rtt_us,
                    SUM(retransmit_count)               AS total_retransmits,
                    MIN(start_time)                    AS session_start,
                    MAX(COALESCE(end_time, start_time)) AS session_end,
                    COUNT(DISTINCT src_ip)              AS unique_src_ips,
                    COUNT(DISTINCT dst_ip)              AS unique_dst_ips
                FROM flows WHERE session_id = $1
            """, session_id)

            # Protocol breakdown
            proto_rows = await conn.fetch("""
                SELECT protocol, COUNT(*) AS cnt, SUM(fwd_bytes + rev_bytes) AS bytes
                FROM flows WHERE session_id = $1
                GROUP BY protocol ORDER BY cnt DESC LIMIT 10
            """, session_id)

            # Top talkers by bytes sent
            top_src = await conn.fetch("""
                SELECT CAST(src_ip AS TEXT) AS ip, SUM(fwd_bytes) AS total_bytes
                FROM flows WHERE session_id = $1
                GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 20
            """, session_id)

            # Top destinations by bytes received
            top_dst = await conn.fetch("""
                SELECT CAST(dst_ip AS TEXT) AS ip, SUM(rev_bytes) AS total_bytes
                FROM flows WHERE session_id = $1
                GROUP BY dst_ip ORDER BY total_bytes DESC LIMIT 20
            """, session_id)

        await pool.close()

        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        return {
            "total_flows": row["total_flows"] or 0,
            "total_bytes": int(row["total_bytes"] or 0),
            "total_fwd_bytes": int(row["total_fwd_bytes"] or 0),
            "total_rev_bytes": int(row["total_rev_bytes"] or 0),
            "avg_rtt_us": float(row["avg_rtt_us"] or 0),
            "total_retransmits": int(row["total_retransmits"] or 0),
            "session_start": row["session_start"],
            "session_end": row["session_end"],
            "unique_src_ips": row["unique_src_ips"] or 0,
            "unique_dst_ips": row["unique_dst_ips"] or 0,
            "protocol_breakdown": [
                {
                    "protocol": proto_map.get(r["protocol"], f"Proto {r['protocol']}"),
                    "count": r["cnt"],
                    "bytes": int(r["bytes"] or 0),
                }
                for r in proto_rows
            ],
            "top_src_ips": [{"ip": r["ip"], "bytes": int(r["total_bytes"] or 0)} for r in top_src],
            "top_dst_ips": [{"ip": r["ip"], "bytes": int(r["total_bytes"] or 0)} for r in top_dst],
        }
    except Exception as e:
        print(f"[DataCollector] collect_session_summary error: {e}")
        return {}


# ── Alert collector ───────────────────────────────────────────────────────────

async def collect_alerts(session_id: str) -> list[dict]:
    """Fetch all alerts for a session from PostgreSQL."""
    try:
        pool = await _get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT alert_id, type, severity, timestamp_ns, title, description,
                       CAST(src_ip AS TEXT) AS src_ip, CAST(dst_ip AS TEXT) AS dst_ip,
                       domain, endpoint, observed_value, threshold_value,
                       baseline_value, is_ongoing
                FROM alerts WHERE session_id = $1
                ORDER BY timestamp_ns DESC
            """, session_id)
        await pool.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DataCollector] collect_alerts error: {e}")
        return []


# ── DNS collector ─────────────────────────────────────────────────────────────

async def collect_dns_stats(session_id: str) -> dict:
    """Compute DNS statistics from flow records (flows with dns_query)."""
    try:
        pool = await _get_pg_pool()
        async with pool.acquire() as conn:
            # Top queried domains
            top_domains = await conn.fetch("""
                SELECT dns_query, COUNT(*) AS cnt, AVG(avg_rtt_us) AS avg_rtt
                FROM flows
                WHERE session_id = $1 AND dns_query IS NOT NULL
                GROUP BY dns_query ORDER BY cnt DESC LIMIT 50
            """, session_id)

            # NXDOMAIN approximation: flows to port 53 with very short duration and small bytes
            dns_summary = await conn.fetchrow("""
                SELECT COUNT(*) AS total_dns_flows,
                       AVG(avg_rtt_us) AS avg_rtt_us,
                       COUNT(DISTINCT dns_query) AS unique_domains
                FROM flows
                WHERE session_id = $1 AND (dst_port = 53 OR dns_query IS NOT NULL)
            """, session_id)

        await pool.close()
        return {
            "total_dns_flows": dns_summary["total_dns_flows"] or 0,
            "unique_domains": dns_summary["unique_domains"] or 0,
            "avg_rtt_us": float(dns_summary["avg_rtt_us"] or 0),
            "top_domains": [
                {
                    "domain": r["dns_query"],
                    "count": r["cnt"],
                    "avg_rtt_ms": round(float(r["avg_rtt"] or 0) / 1000, 2),
                }
                for r in top_domains
            ],
        }
    except Exception as e:
        print(f"[DataCollector] collect_dns_stats error: {e}")
        return {}


# ── HTTP collector ────────────────────────────────────────────────────────────

async def collect_http_stats(session_id: str) -> dict:
    """Compute HTTP statistics from flows with http_host."""
    try:
        pool = await _get_pg_pool()
        async with pool.acquire() as conn:
            top_hosts = await conn.fetch("""
                SELECT http_host, COUNT(*) AS cnt,
                       SUM(fwd_bytes + rev_bytes) AS total_bytes,
                       AVG(avg_rtt_us) AS avg_rtt
                FROM flows
                WHERE session_id = $1 AND http_host IS NOT NULL
                GROUP BY http_host ORDER BY cnt DESC LIMIT 20
            """, session_id)

            http_summary = await conn.fetchrow("""
                SELECT COUNT(*) AS total_http_flows,
                       AVG(avg_rtt_us) AS avg_rtt_us,
                       SUM(fwd_bytes + rev_bytes) AS total_bytes
                FROM flows
                WHERE session_id = $1 AND (http_host IS NOT NULL OR dst_port IN (80, 8080, 443, 8443))
            """, session_id)

        await pool.close()
        return {
            "total_http_flows": http_summary["total_http_flows"] or 0,
            "avg_rtt_us": float(http_summary["avg_rtt_us"] or 0),
            "total_bytes": int(http_summary["total_bytes"] or 0),
            "top_hosts": [
                {
                    "host": r["http_host"],
                    "count": r["cnt"],
                    "total_bytes": int(r["total_bytes"] or 0),
                    "avg_rtt_ms": round(float(r["avg_rtt"] or 0) / 1000, 2),
                }
                for r in top_hosts
            ],
        }
    except Exception as e:
        print(f"[DataCollector] collect_http_stats error: {e}")
        return {}
