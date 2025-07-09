from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from attacks import wifi_blocker_attack

router = APIRouter(
    prefix="/api/wifi-blocker",
    tags=["Wi-Fi Blocker Attack"]
)

class WiFiBlockerStartRequest(BaseModel):
    interface: str
    target_ips: Optional[List[str]] = None

class WiFiBlockerScanRequest(BaseModel):
    interface: str

class WiFiBlockerStatusResponse(BaseModel):
    running: bool
    pid: Optional[int] = None
    error: Optional[str] = None
    targets: Optional[List[str]] = None
    message: Optional[str] = None

class WiFiBlockerLogResponse(BaseModel):
    logs: List[str]

class ClientInfo(BaseModel):
    ip: str
    mac: str

class WiFiBlockerScanResponse(BaseModel):
    clients: List[ClientInfo]

@router.post("/scan", response_model=WiFiBlockerScanResponse)
async def scan_clients(request: WiFiBlockerScanRequest):
    clients = wifi_blocker_attack.scan_clients(request.interface)
    return WiFiBlockerScanResponse(clients=clients)

@router.post("/start", response_model=WiFiBlockerStatusResponse)
async def start_wifi_blocker_attack(request: WiFiBlockerStartRequest, background_tasks: BackgroundTasks):
    result = wifi_blocker_attack.start_wifi_blocker(request.interface, request.target_ips)
    if "error" in result:
        return WiFiBlockerStatusResponse(running=False, error=result["error"])
    
    return WiFiBlockerStatusResponse(
        running=True, 
        pid=result.get("pid"),
        targets=result.get("targets"),
        message=result.get("message")
    )

@router.post("/stop", response_model=WiFiBlockerStatusResponse)
async def stop_wifi_blocker_attack():
    result = wifi_blocker_attack.stop_wifi_blocker()
    if result.get("error"):
        return WiFiBlockerStatusResponse(running=False, error=result["error"])
    return WiFiBlockerStatusResponse(running=False, message=result.get("message"))

@router.get("/status", response_model=WiFiBlockerStatusResponse)
async def get_wifi_blocker_status():
    status = wifi_blocker_attack.get_status()
    running = status.get("running", False)
    pid = status.get("pid")
    return WiFiBlockerStatusResponse(running=running, pid=pid)

@router.get("/logs", response_model=WiFiBlockerLogResponse)
async def get_wifi_blocker_logs(lines: int = 50):
    logs = wifi_blocker_attack.get_logs(lines)
    return WiFiBlockerLogResponse(logs=logs)

@router.get("/interfaces", response_model=List[str])
async def list_network_interfaces():
    return wifi_blocker_attack.list_interfaces() 