from fastapi import APIRouter, HTTPException
from typing import List, Dict
import evil_twin_attack

router = APIRouter(prefix="/api/evil-twin", tags=["evil-twin"])

@router.post("/start")
async def start_evil_twin():
    """Start Evil Twin attack - only when explicitly called by user."""
    result = evil_twin_attack.start_evil_twin("Free WiFi", "wlan0", "1")
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.post("/stop")
async def stop_evil_twin():
    """Stop Evil Twin attack."""
    result = evil_twin_attack.stop_evil_twin()
    return result

@router.get("/status")
async def get_status():
    """Get Evil Twin attack status."""
    return evil_twin_attack.get_status()

@router.get("/logs")
async def get_logs(lines: int = 50):
    """Get Evil Twin attack logs."""
    return {"logs": evil_twin_attack.get_logs(lines)}

@router.get("/interfaces")
async def list_interfaces():
    """List available network interfaces."""
    return {"interfaces": evil_twin_attack.list_interfaces()}

@router.get("/diagnose/{interface}")
async def diagnose_interface(interface: str):
    """Get detailed diagnostic information about an interface."""
    return evil_twin_attack.get_interface_info(interface)

@router.get("/capabilities/{interface}")
async def check_interface_capabilities(interface: str):
    """Check if an interface supports AP mode and other requirements."""
    return evil_twin_attack.check_interface_capabilities(interface) 