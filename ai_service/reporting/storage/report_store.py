"""Report storage — asyncpg operations.
Creates and manages the reports, report_jobs PostgreSQL tables.
Follows the same pattern as conversation_store.py.
"""
import asyncio
import json
import os
import uuid
from typing import Optional
import asyncpg
import config


class ReportStore:
    def __init__(self):
        self._pool: Optional[asyncpg.Pool] = None

    async def init_db(self):
        """Create connection pool and ensure tables exist. Called once on startup."""
        try:
            self._pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=5)
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS report_jobs (
                        job_id         UUID PRIMARY KEY,
                        status         TEXT NOT NULL DEFAULT 'queued',
                        progress_pct   SMALLINT DEFAULT 0,
                        current_step   TEXT,
                        report_id      BIGINT,
                        started_at     TIMESTAMPTZ DEFAULT NOW(),
                        completed_at   TIMESTAMPTZ,
                        error_message  TEXT
                    )
                """)
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS reports (
                        report_id            BIGSERIAL PRIMARY KEY,
                        report_type          TEXT NOT NULL,
                        title                TEXT NOT NULL,
                        session_id           TEXT,
                        time_period_start    TIMESTAMPTZ,
                        time_period_end      TIMESTAMPTZ,
                        format               TEXT NOT NULL,
                        file_path            TEXT,
                        file_size_bytes      BIGINT,
                        generation_time_ms   INTEGER,
                        config               JSONB,
                        ai_narrative_included BOOLEAN DEFAULT FALSE,
                        created_at           TIMESTAMPTZ DEFAULT NOW(),
                        created_by           TEXT DEFAULT 'user'
                    )
                """)
            # Ensure reports dir exists
            os.makedirs(config.REPORTS_DIR, exist_ok=True)
            print("[ReportStore] DB initialized.")
        except Exception as e:
            print(f"[ReportStore] DB init failed (in-memory fallback): {e}")
            self._pool = None

    # ── Job tracking ──────────────────────────────────────────────────────────

    async def create_job(self) -> str:
        """Create a new generation job and return its UUID."""
        job_id = str(uuid.uuid4())
        if self._pool:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO report_jobs (job_id, status) VALUES ($1, 'queued')",
                    job_id
                )
        return job_id

    async def update_job(self, job_id: str, status: str, progress_pct: int,
                         current_step: str, report_id: int | None = None,
                         error_message: str | None = None):
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute("""
                UPDATE report_jobs
                SET status=$2, progress_pct=$3, current_step=$4,
                    report_id=$5, error_message=$6,
                    completed_at = CASE WHEN $2 IN ('completed','failed') THEN NOW() ELSE NULL END
                WHERE job_id=$1
            """, job_id, status, progress_pct, current_step, report_id, error_message)

    async def get_job(self, job_id: str) -> Optional[dict]:
        if not self._pool:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM report_jobs WHERE job_id=$1", job_id)
        if not row:
            return None
        return dict(row)

    # ── Report metadata ───────────────────────────────────────────────────────

    async def save_report(self, report_type: str, title: str, session_id: str,
                          time_start, time_end, fmt: str, file_path: str,
                          generation_time_ms: int, cfg: dict,
                          ai_narrative: bool, created_by: str = "user") -> int:
        """Insert a completed report record and return its ID."""
        if not self._pool:
            return -1
        file_size = os.path.getsize(file_path) if file_path and os.path.exists(file_path) else 0
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO reports
                    (report_type, title, session_id, time_period_start, time_period_end,
                     format, file_path, file_size_bytes, generation_time_ms, config,
                     ai_narrative_included, created_by)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                RETURNING report_id
            """,
                report_type, title, session_id, time_start, time_end,
                fmt, file_path, file_size, generation_time_ms,
                json.dumps(cfg), ai_narrative, created_by
            )
        return row["report_id"]

    async def list_reports(self, session_id: str | None = None,
                           report_type: str | None = None,
                           limit: int = 50) -> list[dict]:
        if not self._pool:
            return []
        clauses = []
        params = []
        idx = 1
        if session_id:
            clauses.append(f"session_id=${idx}"); params.append(session_id); idx += 1
        if report_type:
            clauses.append(f"report_type=${idx}"); params.append(report_type); idx += 1
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit); idx += 1
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM reports {where} ORDER BY created_at DESC LIMIT ${idx - 1}",
                *params
            )
        return [dict(r) for r in rows]

    async def get_report(self, report_id: int) -> Optional[dict]:
        if not self._pool:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM reports WHERE report_id=$1", report_id)
        return dict(row) if row else None

    async def delete_report(self, report_id: int) -> bool:
        """Delete the DB record and file on disk."""
        report = await self.get_report(report_id)
        if not report:
            return False
        # Delete file
        path = report.get("file_path")
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        if self._pool:
            async with self._pool.acquire() as conn:
                await conn.execute("DELETE FROM reports WHERE report_id=$1", report_id)
        return True

    # Cleanup old report files (>7 days)
    async def cleanup_old_reports(self):
        """Remove reports older than 7 days."""
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT report_id, file_path FROM reports WHERE created_at < NOW() - INTERVAL '7 days'"
            )
            for row in rows:
                await self.delete_report(row["report_id"])


# Singleton
store = ReportStore()
