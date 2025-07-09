from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List
from . import evil_twin_attack

router = APIRouter(
    prefix="/api/evil-twin",
    tags=["Evil Twin Attack"]
)

class EvilTwinStartRequest(BaseModel):
    ssid: str
    interface: str
    channel: str

class EvilTwinStatusResponse(BaseModel):
    running: bool
    pid: Optional[int] = None
    error: Optional[str] = None

class EvilTwinLogResponse(BaseModel):
    logs: List[str]

@router.post("/start", response_model=EvilTwinStatusResponse)
async def start_evil_twin_attack(request: EvilTwinStartRequest):
    """
    Start the Evil Twin attack with the given parameters.
    """
    result = evil_twin_attack.start_evil_twin(request.ssid, request.interface, request.channel)
    if "error" in result:
        return EvilTwinStatusResponse(running=False, error=result["error"])
    pids = result.get("pids", {})
    # Return the first PID for display (or None)
    pid = next(iter(pids.values()), None)
    return EvilTwinStatusResponse(running=True, pid=pid)

@router.post("/stop", response_model=EvilTwinStatusResponse)
async def stop_evil_twin_attack():
    """
    Stop the Evil Twin attack and clean up processes.
    """
    result = evil_twin_attack.stop_evil_twin()
    if result.get("errors"):
        return EvilTwinStatusResponse(running=False, error="; ".join(result["errors"]))
    return EvilTwinStatusResponse(running=False)

@router.get("/status", response_model=EvilTwinStatusResponse)
async def get_evil_twin_status():
    """
    Get the current status of the Evil Twin attack.
    """
    status = evil_twin_attack.get_status()
    running = status.get("running", False)
    pids = status.get("pids", {})
    pid = next(iter(pids.values()), None)
    return EvilTwinStatusResponse(running=running, pid=pid)

@router.get("/logs", response_model=EvilTwinLogResponse)
async def get_evil_twin_logs(lines: int = 50):
    """
    Get the last N lines of Evil Twin attack logs.
    """
    logs = evil_twin_attack.get_logs(lines)
    return EvilTwinLogResponse(logs=logs)

@router.get("/interfaces", response_model=List[str])
async def list_network_interfaces():
    """
    List available network interfaces (optional).
    """
    return evil_twin_attack.list_interfaces()

@router.post("/kill-adapter-and-restart-network")
async def kill_adapter_and_restart_network():
    """
    Kill all processes using the connected wireless adapter and restart NetworkManager.
    """
    result = evil_twin_attack.kill_adapter_processes_and_restart_network_manager()
    return result 