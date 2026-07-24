"""Response post-processor — extracts structured data from completed AI responses."""
import re
from dataclasses import dataclass, field


_SEARCH_RE  = re.compile(r"\[SEARCH:\s*([^\]]+)\]")
_FLOW_ID_RE = re.compile(r"\bflow\s*#?(\d+)\b", re.I)
_IP_RE      = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


@dataclass
class ProcessedResponse:
    text: str
    search_queries: list[str] = field(default_factory=list)
    mentioned_flow_ids: list[int] = field(default_factory=list)
    mentioned_ips: list[str] = field(default_factory=list)


def process(response_text: str) -> ProcessedResponse:
    search_queries  = [m.group(1).strip() for m in _SEARCH_RE.finditer(response_text)]
    mentioned_flows = [int(m.group(1)) for m in _FLOW_ID_RE.finditer(response_text)]
    mentioned_ips   = list(set(_IP_RE.findall(response_text)))

    return ProcessedResponse(
        text=response_text,
        search_queries=search_queries,
        mentioned_flow_ids=mentioned_flows,
        mentioned_ips=mentioned_ips,
    )
