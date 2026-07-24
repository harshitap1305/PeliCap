"""SSE handler — formats streaming tokens into Server-Sent Events.

Emits these event types:
  token       → each text chunk from the LLM
  search_chip → when [SEARCH: ...] is detected mid-stream
  done        → stream complete, with metadata
  error       → on failure
"""
import json
import re


_SEARCH_RE = re.compile(r"\[SEARCH:\s*([^\]]+)\]")


def _sse(event_type: str, data: dict) -> str:
    return f"data: {json.dumps({'type': event_type, **data})}\n\n"


async def stream_to_sse(groq_stream, on_complete=None):
    """
    Async generator that yields SSE-formatted strings.
    `groq_stream` is an async generator yielding (text, finish_reason, usage).
    `on_complete(full_text, finish_reason)` is called after the stream ends.
    """
    full_text = ""
    # Buffer to detect [SEARCH: ...] spanning multiple chunks
    buffer = ""
    finish_reason = "stop"

    try:
        async for chunk_text, fin, usage in groq_stream:
            if fin:
                finish_reason = fin

            if chunk_text:
                full_text += chunk_text
                buffer += chunk_text

                # Check for search chips in the buffer
                for match in _SEARCH_RE.finditer(buffer):
                    query = match.group(1).strip()
                    yield _sse("search_chip", {"query": query})

                # Replace [SEARCH: query] with just the query text in markdown format
                # so the user can read it in the sentence, while still getting the chip
                buffer = _SEARCH_RE.sub(lambda m: f"`{m.group(1).strip()}`", buffer)

                # Keep only last 40 chars as potential partial match
                if len(buffer) > 40:
                    yield _sse("token", {"content": buffer[:-40]})
                    buffer = buffer[-40:]
                # If no partial possible, flush
                elif "[" not in buffer:
                    yield _sse("token", {"content": buffer})
                    buffer = ""

        # Flush remaining buffer
        if buffer:
            # Strip any leftover search chips
            cleaned = _SEARCH_RE.sub("", buffer)
            if cleaned:
                yield _sse("token", {"content": cleaned})

        # Handle truncation
        truncated = finish_reason == "length"
        if truncated:
            notice = "\n\n*Response truncated. Ask a more specific question for a complete answer.*"
            full_text += notice
            yield _sse("token", {"content": notice})

        yield _sse("done", {
            "finish_reason": finish_reason,
            "truncated": truncated,
        })

        if on_complete:
            await on_complete(full_text, finish_reason)

    except Exception as e:
        yield _sse("error", {"message": str(e)})
