"""Metrics fetcher — calls the C++ backend metrics endpoints via httpx."""
import httpx
import config
from context.baseline_tracker import tracker


async def fetch_metrics_summary(client: httpx.AsyncClient, window: int = 60) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/metrics/summary", params={"window": window})
        data = r.json()
        tracker.update(data)   # Feed baseline tracker every time we fetch
        return data
    except Exception:
        return {}


async def fetch_metrics_network(client: httpx.AsyncClient, window: int = 60) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/metrics/network", params={"window": window})
        return r.json()
    except Exception:
        return {}


async def fetch_metrics_tcp(client: httpx.AsyncClient, window: int = 60) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/metrics/tcp", params={"window": window})
        return r.json()
    except Exception:
        return {}


async def fetch_metrics_dns(client: httpx.AsyncClient, window: int = 60) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/metrics/dns", params={"window": window})
        return r.json()
    except Exception:
        return {}


async def fetch_metrics_http(client: httpx.AsyncClient, window: int = 60) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/metrics/http", params={"window": window})
        return r.json()
    except Exception:
        return {}


async def fetch_capture_stats(client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"{config.BACKEND_URL}/api/stats")
        return r.json()
    except Exception:
        return {}
