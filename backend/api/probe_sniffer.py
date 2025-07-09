from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from attacks import probe_sniffer

router = APIRouter(
    prefix="/api/probe-sniffer",
    tags=["Probe Request Sniffer"]
)

class ProbeSnifferStartRequest(BaseModel):
    interface: str

class ProbeSnifferStatusResponse(BaseModel):
    running: bool
    pid: Optional[int] = None
    error: Optional[str] = None
    message: Optional[str] = None
    stats: Optional[dict] = None

class ProbeSnifferLogResponse(BaseModel):
    logs: List[str]

@router.post("/start", response_model=ProbeSnifferStatusResponse)
async def start_probe_sniffer_attack(request: ProbeSnifferStartRequest, background_tasks: BackgroundTasks):
    result = probe_sniffer.start_probe_sniffer(request.interface)
    if "error" in result:
        return ProbeSnifferStatusResponse(running=False, error=result["error"])
    
    return ProbeSnifferStatusResponse(
        running=True, 
        pid=result.get("pid"),
        message=result.get("message")
    )

@router.post("/stop", response_model=ProbeSnifferStatusResponse)
async def stop_probe_sniffer_attack():
    result = probe_sniffer.stop_probe_sniffer()
    if result.get("error"):
        return ProbeSnifferStatusResponse(running=False, error=result["error"])
    return ProbeSnifferStatusResponse(running=False, message=result.get("message"))

@router.get("/status", response_model=ProbeSnifferStatusResponse)
async def get_probe_sniffer_status():
    status = probe_sniffer.get_status()
    running = status.get("running", False)
    pid = status.get("pid")
    stats = status.get("stats", {})
    return ProbeSnifferStatusResponse(running=running, pid=pid, stats=stats)

@router.get("/logs", response_model=ProbeSnifferLogResponse)
async def get_probe_sniffer_logs(lines: int = 50):
    logs = probe_sniffer.get_logs(lines)
    return ProbeSnifferLogResponse(logs=logs)

@router.get("/interfaces", response_model=List[str])
async def list_network_interfaces():
    return probe_sniffer.list_interfaces() 