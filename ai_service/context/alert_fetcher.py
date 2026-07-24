"""Alert fetcher — calls GET /api/alerts on the C++ backend."""
import httpx
import config


async def fetch_alerts(
    client: httpx.AsyncClient,
    session_id: str,
    severity: str = "INFO",
    limit: int = 10,
    alert_type: str | None = None,
) -> list[dict]:
    try:
        params: dict = {"severity": severity, "limit": limit, "session_id": session_id}
        if alert_type:
            params["type"] = alert_type
        r = await client.get(f"{config.BACKEND_URL}/api/alerts", params=params)
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception:
        return []


async def fetch_security_alerts(client: httpx.AsyncClient, session_id: str) -> list[dict]:
    """Fetch all critical security-related alerts."""
    return await fetch_alerts(
        client, session_id=session_id, severity="INFO", limit=20
    )
