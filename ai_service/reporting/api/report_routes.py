"""FastAPI report routes — all /api/reports/* endpoints."""
import asyncio
import os
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
import config
from reporting.storage.report_store import store as report_store
from reporting.report_generator import generate_report, REPORT_LABELS, REPORT_TEMPLATES

router = APIRouter(prefix="/api/reports", tags=["reports"])


# ── Request models ────────────────────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    report_type: str      # traffic_summary | dns | http_performance | security | root_cause_analysis
    session_id: str
    format: str = "pdf"   # pdf | docx | markdown
    include_ai: bool = True
    top_n: int = 20


# ── Background task helper ────────────────────────────────────────────────────

async def _run_generation(job_id: str, req: GenerateReportRequest):
    try:
        await report_store.update_job(job_id, "running", 0, "Starting report generation…")

        async def progress(pct, step):
            await report_store.update_job(job_id, "running", pct, step)

        report_id = await generate_report(
            job_id=job_id,
            report_type=req.report_type,
            session_id=req.session_id,
            fmt=req.format,
            include_ai=req.include_ai,
            top_n=req.top_n,
            created_by="user",
            progress_fn=progress,
        )

        await report_store.update_job(job_id, "completed", 100, "Report ready.",
                                      report_id=report_id)

    except Exception as e:
        print(f"[ReportRoutes] generation failed for job {job_id}: {e}")
        await report_store.update_job(job_id, "failed", 0, str(e), error_message=str(e))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/generate")
async def start_generation(req: GenerateReportRequest, background_tasks: BackgroundTasks):
    """Start on-demand report generation. Returns job_id immediately."""
    if req.report_type not in REPORT_LABELS:
        raise HTTPException(status_code=400, detail=f"Unknown report_type: {req.report_type}")
    if req.format not in ("pdf", "docx", "markdown"):
        raise HTTPException(status_code=400, detail=f"Unknown format: {req.format}")

    job_id = await report_store.create_job()
    background_tasks.add_task(_run_generation, job_id, req)
    return {"job_id": job_id, "status": "queued"}


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Poll report generation progress."""
    job = await report_store.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("")
async def list_reports(session_id: Optional[str] = None,
                       report_type: Optional[str] = None,
                       limit: int = 50):
    """List generated reports. Optionally filter by session_id or report_type."""
    reports = await report_store.list_reports(session_id=session_id,
                                               report_type=report_type,
                                               limit=limit)
    # Convert non-JSON-serializable fields
    for r in reports:
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = v.isoformat()
    return reports


@router.get("/{report_id}")
async def get_report_metadata(report_id: int):
    """Get metadata for a specific report."""
    report = await report_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    for k, v in report.items():
        if hasattr(v, 'isoformat'):
            report[k] = v.isoformat()
    return report


@router.get("/{report_id}/download")
async def download_report(report_id: int, inline: bool = False):
    """Download the report file."""
    report = await report_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    file_path = report.get("file_path")
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    fmt = report.get("format", "pdf")
    media_type_map = {
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "markdown": "text/markdown",
    }
    filename_ext = {"pdf": "pdf", "docx": "docx", "markdown": "md"}.get(fmt, "pdf")
    filename = f"{report.get('report_type', 'report')}_{report_id}.{filename_ext}"

    disposition = "inline" if inline else "attachment"

    return FileResponse(
        path=file_path,
        media_type=media_type_map.get(fmt, "application/octet-stream"),
        filename=filename,
        headers={"Content-Disposition": f'{disposition}; filename="{filename}"'},
    )


@router.delete("/{report_id}")
async def delete_report(report_id: int):
    """Delete a generated report and its file."""
    deleted = await report_store.delete_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"deleted": report_id}


@router.get("/templates/list")
async def list_templates():
    """Return all available report types with their config options."""
    return [
        {
            "report_type": rt,
            "label": label,
            "description": _descriptions.get(rt, ""),
            "formats": ["pdf", "docx", "markdown"],
            "options": {
                "include_ai": {"type": "boolean", "default": True,
                               "label": "Include AI narrative"},
                "top_n": {"type": "number", "default": 20, "min": 10, "max": 100,
                          "label": "Top N items in tables"},
            }
        }
        for rt, label in REPORT_LABELS.items()
    ]


_descriptions = {
    "traffic_summary": "Overview of all network traffic: volume, protocols, top talkers.",
    "dns": "DNS query analysis: top domains, resolution times, NXDOMAIN patterns.",
    "http_performance": "HTTP/HTTPS traffic analysis: top destinations, latency.",
    "security": "Security-focused: alerts, suspicious flows, unusual traffic patterns.",
    "root_cause_analysis": "AI-driven incident RCA: timeline, root cause, recommendations.",
}
