"""Conversation store — in-memory + PostgreSQL persistence.

Each conversation is a list of {role, content} dicts (OpenAI message format).
PostgreSQL table: ai_conversations (see sql/002_ai_conversations.sql)
"""
import asyncio
import json
import uuid
import time
from dataclasses import dataclass, field
from typing import Optional
import asyncpg
import config


@dataclass
class Conversation:
    conversation_id: str
    session_id: str
    messages: list[dict] = field(default_factory=list)  # OpenAI format
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class ConversationStore:
    def __init__(self):
        self._mem: dict[str, Conversation] = {}    # conversation_id → Conversation
        self._pool: Optional[asyncpg.Pool] = None

    async def init_db(self):
        """Create asyncpg connection pool. Called once on startup."""
        try:
            self._pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=5)
            # Ensure table exists
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS ai_conversations (
                        conversation_id TEXT PRIMARY KEY,
                        session_id      TEXT NOT NULL,
                        messages        JSONB NOT NULL DEFAULT '[]',
                        created_at      DOUBLE PRECISION NOT NULL,
                        updated_at      DOUBLE PRECISION NOT NULL
                    )
                """)
                await conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ai_conv_session ON ai_conversations(session_id)"
                )
        except Exception as e:
            print(f"[ConversationStore] DB init failed (will use in-memory only): {e}")
            self._pool = None

    def new_conversation(self, session_id: str) -> str:
        """Create a new conversation and return its ID."""
        cid = str(uuid.uuid4())
        self._mem[cid] = Conversation(
            conversation_id=cid,
            session_id=session_id,
        )
        return cid

    def get_or_create(self, session_id: str, conversation_id: Optional[str]) -> Conversation:
        if conversation_id and conversation_id in self._mem:
            return self._mem[conversation_id]
        # Create new
        cid = conversation_id or str(uuid.uuid4())
        conv = Conversation(conversation_id=cid, session_id=session_id)
        self._mem[cid] = conv
        return conv

    def append_turn(self, conversation_id: str, role: str, content: str):
        """Append a message turn to the conversation."""
        conv = self._mem.get(conversation_id)
        if conv is None:
            return
        conv.messages.append({"role": role, "content": content})
        conv.updated_at = time.time()

    def get_history_messages(self, conversation_id: str) -> list[dict]:
        """Return the OpenAI-format messages list, truncated to MAX_HISTORY_CHARS."""
        conv = self._mem.get(conversation_id)
        if not conv:
            return []
        return _truncate_history(conv.messages)

    def list_by_session(self, session_id: str) -> list[dict]:
        return [
            {
                "conversation_id": c.conversation_id,
                "session_id": c.session_id,
                "message_count": len(c.messages),
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            }
            for c in self._mem.values()
            if c.session_id == session_id
        ]

    def get(self, conversation_id: str) -> Optional[Conversation]:
        return self._mem.get(conversation_id)

    def delete(self, conversation_id: str) -> bool:
        if conversation_id in self._mem:
            del self._mem[conversation_id]
            asyncio.create_task(self._delete_pg(conversation_id))
            return True
        return False

    async def persist(self, conversation_id: str):
        """Save/update a conversation in PostgreSQL asynchronously."""
        if not self._pool:
            return
        conv = self._mem.get(conversation_id)
        if not conv:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO ai_conversations
                        (conversation_id, session_id, messages, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (conversation_id) DO UPDATE
                        SET messages   = EXCLUDED.messages,
                            updated_at = EXCLUDED.updated_at
                """,
                    conv.conversation_id,
                    conv.session_id,
                    json.dumps(conv.messages),
                    conv.created_at,
                    conv.updated_at,
                )
        except Exception as e:
            print(f"[ConversationStore] persist failed: {e}")

    async def load_from_db(self, session_id: str):
        """Restore conversations for a session from PostgreSQL into memory."""
        if not self._pool:
            return
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM ai_conversations WHERE session_id = $1 ORDER BY updated_at DESC LIMIT 50",
                    session_id,
                )
            for row in rows:
                cid = row["conversation_id"]
                if cid not in self._mem:
                    self._mem[cid] = Conversation(
                        conversation_id=cid,
                        session_id=row["session_id"],
                        messages=json.loads(row["messages"]),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                    )
        except Exception as e:
            print(f"[ConversationStore] load_from_db failed: {e}")

    async def _delete_pg(self, conversation_id: str):
        if not self._pool:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM ai_conversations WHERE conversation_id = $1", conversation_id
                )
        except Exception:
            pass


def _truncate_history(messages: list[dict]) -> list[dict]:
    """
    Truncate message history to MAX_HISTORY_CHARS.
    Strategy: keep first message + last 5 messages, drop middle if needed.
    """
    if not messages:
        return []

    total_chars = sum(len(m.get("content", "")) for m in messages)

    if total_chars <= config.MAX_HISTORY_CHARS:
        return list(messages)

    # Keep first + last 5
    if len(messages) <= 6:
        return list(messages)

    kept = [messages[0]] + messages[-5:]
    dropped = len(messages) - 6
    summary_msg = {
        "role": "system",
        "content": f"[{dropped} earlier messages omitted to fit context window]"
    }
    return [messages[0], summary_msg] + messages[-5:]


# Module-level singleton
store = ConversationStore()
