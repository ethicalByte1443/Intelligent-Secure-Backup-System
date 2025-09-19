# main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import time
import os
import io
import csv
import json
from utils.dlp import scan_directory
from routes import backup_routes  # 👈 import new routes



app = FastAPI(title="SecureAI Backup - DLP v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    print(f"{request.method} {request.url.path} -> {response.status_code} ({duration:.3f}s)")
    return response



app.include_router(backup_routes.router)


@app.get("/")
def root():
    return {"message": "SecureAI Backup - DLP v2 running"}

@app.post("/scan")
def scan_endpoint(payload: dict):
    root_path = payload.get("rootPath")
    if not root_path:
        raise HTTPException(status_code=400, detail="rootPath not provided")
    if not os.path.exists(root_path):
        raise HTTPException(status_code=400, detail=f"Path '{root_path}' does not exist")
    findings = scan_directory(root_path)

    # count total files scanned
    total_files = 0
    for _root, _dirs, files in os.walk(root_path):
        total_files += len(files)

    return {
        "scanned_path": os.path.abspath(root_path),
        "total_files_scanned": total_files,
        "matching_files_count": len(findings),
        "findings": findings,
    }

@app.post("/export")
def export_endpoint(payload: dict):
    """
    Accepts JSON payload with:
    {
      "format": "json" | "csv",
      "data": <the scan response object>
    }
    Returns a file download (StreamingResponse) with proper content-type.
    """
    fmt = (payload.get("format") or "json").lower()
    data = payload.get("data")
    if not data:
        raise HTTPException(status_code=400, detail="No data provided to export")

    if fmt == "json":
        b = json.dumps(data, indent=2).encode("utf-8")
        return StreamingResponse(io.BytesIO(b), media_type="application/json", headers={
            "Content-Disposition": "attachment; filename=scan_report.json"
        })

    if fmt == "csv":
        # create CSV in memory with columns: file,path,hit_type,hit_values,confidence,context_score,risk_score,risk_label
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["file_path", "hit_type", "hit_values", "confidence", "context_score", "risk_score", "risk_label"])
        findings = data.get("findings", {})
        for fp, info in findings.items():
            hits = info.get("hits", {})
            confidence = info.get("confidence", "")
            context_score = info.get("context_score", "")
            risk_score = info.get("risk_score", "")
            risk_label = info.get("risk_label", "")
            if not hits:
                writer.writerow([fp, "", "", confidence, context_score, risk_score, risk_label])
            else:
                for htype, hvals in hits.items():
                    writer.writerow([fp, htype, ";".join(hvals), confidence, context_score, risk_score, risk_label])
        b = output.getvalue().encode("utf-8")
        return StreamingResponse(io.BytesIO(b), media_type="text/csv", headers={
            "Content-Disposition": "attachment; filename=scan_report.csv"
        })

    raise HTTPException(status_code=400, detail="Unsupported format")


