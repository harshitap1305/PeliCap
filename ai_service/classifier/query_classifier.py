"""Query type classifier — keyword + regex, zero LLM calls."""
import re
from enum import Enum


class QueryType(str, Enum):
    HEALTH_CHECK = "health_check"
    PERFORMANCE = "performance"
    FLOW_INVESTIGATION = "flow_investigation"
    SECURITY = "security"
    EXPLANATION = "explanation"
    HISTORICAL = "historical"
    RECOMMENDATION = "recommendation"


# ── Keyword banks ──────────────────────────────────────────────────────────────
_HEALTH = [
    "what's happening", "whats happening", "how is my network", "how is the network",
    "give me a summary", "network health", "is everything okay", "status", "overview",
    "what should i know", "overall", "summary", "how are things",
]

_PERFORMANCE = [
    "slow", "latency", "lag", "why is it", "why is my", "response time",
    "high rtt", "bottleneck", "delay", "taking too long", "timeout", "sluggish",
    "fast", "speed", "performance", "throughput", "bandwidth",
]

_SECURITY = [
    "suspicious", "attack", "scan", "port scan", "intrusion", "malicious",
    "unusual traffic", "security", "threat", "hack", "exploit",
    "should i be worried", "blocked", "blocked ip", "brute force",
    "syn flood", "nxdomain", "unusual", "anomal",
]

_EXPLANATION = [
    "explain", "what is", "what does", "what are", "how does", "teach me",
    "i don't understand", "i dont understand", "what's a", "whats a",
    "why does tcp", "why does udp", "tell me about", "describe",
    "learning mode", "educate", "help me understand",
]

_HISTORICAL = [
    "yesterday", "last night", "earlier today", "this morning", "last hour",
    "what happened", "at 3pm", "at 3 pm", "last week", "compare",
    "before", "previously", "history", "historic", "trend",
]

_RECOMMENDATION = [
    "what should i do", "how do i fix", "recommendation", "next steps",
    "how to resolve", "fix this", "remediat", "how to improve",
    "suggest", "advice", "action", "what can i do",
]

# IP / domain / port patterns → flow investigation
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_PORT_RE = re.compile(r"\bport\s+\d+\b|\btcp\s+\d+\b|\budp\s+\d+\b", re.I)
_FLOW_KEYWORDS = [
    "traffic to", "traffic from", "connection to", "connection from",
    "flows to", "flows from", "what is", "what's", "show me", "investigate",
]


def classify(query: str) -> QueryType:
    """Classify a user query into one of 7 QueryTypes."""
    q = query.lower().strip()

    # Recommendation — check first (often follows a diagnosis)
    if any(kw in q for kw in _RECOMMENDATION):
        return QueryType.RECOMMENDATION

    # Historical — time references
    if any(kw in q for kw in _HISTORICAL):
        return QueryType.HISTORICAL

    # Security
    if any(kw in q for kw in _SECURITY):
        return QueryType.SECURITY

    # Explanation — educational
    if any(kw in q for kw in _EXPLANATION):
        return QueryType.EXPLANATION

    # Performance
    if any(kw in q for kw in _PERFORMANCE):
        return QueryType.PERFORMANCE

    # Flow investigation — IP, domain, or port referenced
    has_ip = bool(_IP_RE.search(q))
    has_port = bool(_PORT_RE.search(q))
    # Domain detection: only trigger if paired with an investigation keyword
    has_domain = bool(_DOMAIN_RE.search(q)) and any(kw in q for kw in _FLOW_KEYWORDS)
    if has_ip or has_port or has_domain:
        return QueryType.FLOW_INVESTIGATION

    # Health check
    if any(kw in q for kw in _HEALTH):
        return QueryType.HEALTH_CHECK

    # Default fallback
    return QueryType.HEALTH_CHECK


def extract_ip(query: str) -> str | None:
    """Extract first IP address from query, if any."""
    m = _IP_RE.search(query)
    return m.group(0) if m else None


def extract_domain(query: str) -> str | None:
    """Extract first domain-like string from query."""
    m = _DOMAIN_RE.search(query)
    return m.group(0) if m else None


def extract_port(query: str) -> int | None:
    """Extract first port number from query."""
    m = re.search(r"\b(?:port|tcp|udp)\s+(\d+)\b", query, re.I)
    return int(m.group(1)) if m else None
