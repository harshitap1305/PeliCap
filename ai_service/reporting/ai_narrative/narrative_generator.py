"""AI narrative generator for reports.
Calls Groq using the PRIMARY_MODEL (llama-3.3-70b-versatile) for high-quality report prose.
"""
from groq.groq_client import simple_completion
from reporting.ai_narrative.report_prompts import REPORT_SYSTEM_PROMPT


async def generate_narrative(user_prompt: str, max_tokens: int = 800) -> str:
    """
    Call Groq to generate a report narrative section.
    Uses the primary (large) model for maximum quality.
    Returns the generated text, or an empty string on failure.
    """
    try:
        import config
        text = await simple_completion(
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            model=config.PRIMARY_MODEL,
            max_tokens=max_tokens,
        )
        return text or ""
    except Exception as e:
        print(f"[NarrativeGenerator] AI call failed: {e}")
        return ""
