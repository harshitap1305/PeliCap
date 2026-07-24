"""Flow fetcher — calls POST /api/search on the C++ backend."""
import httpx
import config


async def search_flows(
    client: httpx.AsyncClient,
    query: str,
    session_id: str,
    limit: int = 10,
    offset: int = 0,
) -> dict:
    """Run a PeliCap search query and return the result dict."""
    try:
        r = await client.post(
            f"{config.BACKEND_URL}/api/search",
            json={"query": query, "session_id": session_id, "limit": limit, "offset": offset},
        )
        return r.json()
    except Exception:
        return {"flows": [], "total": 0}


async def fetch_flow_by_id(client: httpx.AsyncClient, flow_id: int) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/flows/{flow_id}")
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


async def fetch_slowest_flows(
    client: httpx.AsyncClient, session_id: str, limit: int = 10
) -> dict:
    """Fetch flows sorted by highest RTT (performance investigation)."""
    return await search_flows(
        client,
        query="",          # empty query = all flows
        session_id=session_id,
        limit=limit,
    )
