"""Groq client — AsyncOpenAI SDK pointed at api.groq.com."""
import asyncio
import time
from openai import AsyncOpenAI, RateLimitError, APIStatusError
import config


def _make_client() -> AsyncOpenAI:
    return AsyncOpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=config.GROQ_API_KEY,
    )


client = _make_client()

# Usage tracking (in-memory, resets on restart)
_usage: dict[str, int] = {"input_tokens_hour": 0, "output_tokens_hour": 0,
                           "input_tokens_day": 0, "output_tokens_day": 0,
                           "hour_reset": int(time.time()) + 3600,
                           "day_reset": int(time.time()) + 86400}


def _maybe_reset_usage():
    now = int(time.time())
    if now > _usage["hour_reset"]:
        _usage["input_tokens_hour"] = 0
        _usage["output_tokens_hour"] = 0
        _usage["hour_reset"] = now + 3600
    if now > _usage["day_reset"]:
        _usage["input_tokens_day"] = 0
        _usage["output_tokens_day"] = 0
        _usage["day_reset"] = now + 86400


def record_usage(input_tokens: int, output_tokens: int):
    _maybe_reset_usage()
    _usage["input_tokens_hour"] += input_tokens
    _usage["output_tokens_hour"] += output_tokens
    _usage["input_tokens_day"] += input_tokens
    _usage["output_tokens_day"] += output_tokens


def get_usage() -> dict:
    _maybe_reset_usage()
    return {
        "input_tokens_hour": _usage["input_tokens_hour"],
        "output_tokens_hour": _usage["output_tokens_hour"],
        "input_tokens_day": _usage["input_tokens_day"],
        "output_tokens_day": _usage["output_tokens_day"],
    }


async def stream_chat(
    messages: list[dict],
    model: str | None = None,
    max_tokens: int | None = None,
):
    """
    Stream a chat completion from Groq. Yields (chunk_text, finish_reason, usage).
    finish_reason is non-None only on the final chunk.
    Implements exponential backoff: 1s → 2s → 4s on rate limit / server errors.
    """
    chosen_model = model or config.PRIMARY_MODEL
    max_tok = max_tokens or config.MAX_TOKENS_RESPONSE

    for attempt in range(3):
        try:
            stream = await client.chat.completions.create(
                model=chosen_model,
                messages=messages,
                max_tokens=max_tok,
                stream=True,
                temperature=0.3,   # Lower = more factual / consistent
            )
            async for chunk in stream:
                delta = chunk.choices[0].delta
                finish = chunk.choices[0].finish_reason
                text = delta.content or ""
                usage = getattr(chunk, "x_groq", None)
                yield text, finish, usage
            return
        except RateLimitError:
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                raise
        except APIStatusError as e:
            if e.status_code >= 500 and attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                raise


async def simple_completion(messages: list[dict], model: str | None = None,
                            max_tokens: int = 300) -> str:
    """Non-streaming call for short tasks (auto-analysis summary, conversation summary)."""
    chosen_model = model or config.FAST_MODEL
    for attempt in range(3):
        try:
            resp = await client.chat.completions.create(
                model=chosen_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.3,
                stream=False,
            )
            usage = resp.usage
            if usage:
                record_usage(usage.prompt_tokens, usage.completion_tokens)
            return resp.choices[0].message.content or ""
        except (RateLimitError, APIStatusError):
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
            else:
                raise
    return ""
