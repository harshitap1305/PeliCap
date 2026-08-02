"""Auto-RCA trigger — APScheduler job that checks every 60s for critical alerts
that have been active for more than 5 minutes and auto-generates an RCA report.
"""
import asyncio
import asyncpg
import config
from reporting.storage.report_store import store as report_store
from reporting.report_generator import generate_report


async def check_and_trigger_rca():
    """
    Runs every 60s. Finds critical, ongoing alerts with no existing auto-RCA report.
    Triggers RCA generation for each matching session.
    """
    try:
        pool = await asyncpg.create_pool(config.PG_DSN, min_size=1, max_size=2)
        async with pool.acquire() as conn:
            # Find sessions with critical ongoing alerts older than 5 minutes.
            # severity is SMALLINT in PostgreSQL: CRITICAL=2, WARNING=1, INFO=0
            rows = await conn.fetch("""
                SELECT DISTINCT session_id::TEXT AS session_id, COUNT(*) AS critical_count
                FROM alerts
                WHERE severity = 2
                  AND is_ongoing = TRUE
                  AND (timestamp_ns / 1e6) < (EXTRACT(EPOCH FROM NOW()) * 1000 - 300000)
                GROUP BY session_id
            """)

            # Find sessions that already have a recent auto-RCA report
            already_done = set()
            if rows:
                session_ids = [str(r["session_id"]) for r in rows]
                existing = await conn.fetch("""
                    SELECT DISTINCT session_id FROM reports
                    WHERE created_by = 'auto'
                      AND report_type = 'root_cause_analysis'
                      AND created_at > NOW() - INTERVAL '1 hour'
                      AND session_id = ANY($1)
                """, session_ids)
                already_done = {r["session_id"] for r in existing}

        await pool.close()

        for row in rows:
            sid = str(row["session_id"])
            if sid in already_done:
                continue

            print(f"[RCA Trigger] Auto-generating RCA for session {sid} "
                  f"({row['critical_count']} critical alerts)")

            job_id = await report_store.create_job()
            asyncio.create_task(
                _run_auto_rca(job_id, sid)
            )

    except Exception as e:
        print(f"[RCA Trigger] check failed: {e}")


async def _run_auto_rca(job_id: str, session_id: str):
    try:
        await report_store.update_job(job_id, "running", 0, "Auto-RCA starting…")

        async def progress(pct, step):
            await report_store.update_job(job_id, "running", pct, step)

        report_id = await generate_report(
            job_id=job_id,
            report_type="root_cause_analysis",
            session_id=session_id,
            fmt="pdf",
            include_ai=True,
            created_by="auto",
            progress_fn=progress,
        )

        await report_store.update_job(job_id, "completed", 100, "Auto-RCA complete.",
                                      report_id=report_id)
        print(f"[RCA Trigger] Auto-RCA complete. report_id={report_id}")

    except Exception as e:
        await report_store.update_job(job_id, "failed", 0, str(e), error_message=str(e))
        print(f"[RCA Trigger] Auto-RCA failed: {e}")
