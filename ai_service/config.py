"""Configuration — reads all environment variables."""
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env from project root when running locally

GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "")
BACKEND_URL: str = os.environ.get("BACKEND_URL", "http://localhost:8080")
PG_DSN: str = os.environ.get("PG_DSN", "postgresql://palicap:palicap@localhost:5434/palicap")

# Models
PRIMARY_MODEL: str = os.environ.get("PRIMARY_MODEL", "llama-3.3-70b-versatile")
FAST_MODEL: str = os.environ.get("FAST_MODEL", "llama-3.1-8b-instant")

# Token / response limits
MAX_TOKENS_RESPONSE: int = int(os.environ.get("MAX_TOKENS_RESPONSE", "2000"))
MAX_CONTEXT_CHARS: int = 24_000   # ~6000 tokens @ 4 chars/token
MAX_HISTORY_CHARS: int = 32_000   # ~8000 tokens

# Rate limiting (per session_id)
RATE_LIMIT_PER_MINUTE: int = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "10"))
RATE_LIMIT_PER_HOUR: int = int(os.environ.get("RATE_LIMIT_PER_HOUR", "100"))

# Baseline tracking
BASELINE_WINDOW: int = int(os.environ.get("BASELINE_WINDOW", "20"))  # num recent snapshots
