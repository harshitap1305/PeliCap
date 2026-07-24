"""Prompt templates — one per query type, wraps context + user question."""
from classifier.query_classifier import QueryType


def build_prompt(query_type: QueryType, context_text: str, user_query: str,
                 missing_sources: list[str] | None = None) -> str:
    """
    Combine the context block with the appropriate template for this query type.
    Returns the final user-turn message content to send to the LLM.
    """
    note = ""
    if missing_sources:
        note = f"\nNOTE: The following data sources were unavailable: {', '.join(missing_sources)}. Answer with available data only.\n"

    templates = {
        QueryType.HEALTH_CHECK: _health_check,
        QueryType.PERFORMANCE: _performance,
        QueryType.FLOW_INVESTIGATION: _flow_investigation,
        QueryType.SECURITY: _security,
        QueryType.EXPLANATION: _explanation,
        QueryType.HISTORICAL: _historical,
        QueryType.RECOMMENDATION: _recommendation,
    }

    fn = templates.get(query_type, _health_check)
    return fn(context_text, user_query, note)


def _health_check(ctx: str, q: str, note: str) -> str:
    return f"""NETWORK CONTEXT:
{ctx}
{note}
USER QUESTION: {q}

Provide a concise health summary. Lead with overall status (healthy / degraded / critical). List the 2–3 most important findings with specific numbers from the context. If everything looks normal, say so clearly. Include one [SEARCH: ...] query if something is worth investigating."""


def _performance(ctx: str, q: str, note: str) -> str:
    return f"""PERFORMANCE CONTEXT (last 5 minutes):
{ctx}
{note}
USER QUESTION: {q}

Diagnose the performance issue. Identify the primary bottleneck with specific evidence from the numbers above. Rank contributing factors by impact. Include at least one [SEARCH: ...] query to investigate further. End with a brief ranked action list."""


def _flow_investigation(ctx: str, q: str, note: str) -> str:
    return f"""NETWORK CONTEXT + MATCHING FLOWS:
{ctx}
{note}
USER QUESTION: {q}

Explain what these flows show. Describe the communication pattern, performance characteristics, and anything unusual or notable. Include a [SEARCH: ...] query if deeper investigation is warranted."""


def _security(ctx: str, q: str, note: str) -> str:
    return f"""SECURITY CONTEXT:
{ctx}
{note}
USER QUESTION: {q}

Analyze the security posture based on this data. Report what is observable without speculating about intent. Prioritize findings by severity. Include [SEARCH: ...] queries for each finding so the user can investigate directly in the Flow Explorer."""


def _explanation(ctx: str, q: str, note: str) -> str:
    ctx_section = f"RELEVANT DATA:\n{ctx}\n\n" if ctx.strip() else ""
    return f"""{ctx_section}USER QUESTION: {q}

Explain this networking concept clearly. If the user referenced specific data, explain it in that context. Use concrete examples. The user is technical — use correct terminology and do not over-simplify."""


def _historical(ctx: str, q: str, note: str) -> str:
    return f"""HISTORICAL NETWORK CONTEXT:
{ctx}
{note}
USER QUESTION: {q}

Describe what happened during this time period. Identify the most significant events. Compare to available baseline where possible. Be specific about timing and scale."""


def _recommendation(ctx: str, q: str, note: str) -> str:
    return f"""CURRENT NETWORK STATE:
{ctx}
{note}
USER QUESTION: {q}

Provide specific, actionable recommendations. Number each recommendation. For each: state the problem it addresses, the recommended action, and the expected outcome. Do not recommend actions that cannot be verified from the traffic data shown above."""
