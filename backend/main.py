from typing import Union, List
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, BackgroundTasks
import asyncio
import json
import time
import os
import sys

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from attacks.DeauthenticationFrameInjection import DeauthAttack
from attacks.ICMPEchoRequestFlood import ICMPFloodAttack
from attacks.MITMAttack import MITMAttack
from attacks.HandshakeCapture import HandshakeCaptureAttack
from helpers.scanner import scan_access_points_basic, scan_access_points_advanced
from models import (
    deauthRequest, 
    APScanRequest, 
    DeauthAttackRequest, 
    ICMPFloodRequest,
    MITMAttackRequest,
    HandshakeCaptureRequest,
    AttackStatusResponse,
    ClientDiscoveryResponse
)

app = FastAPI(
    title="Airstrike API",
    description="A comprehensive WiFi penetration testing API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"], 
)

# Register Evil Twin API router
from evil_twin.api import router as evil_twin_router
app.include_router(evil_twin_router)

# Register Wi-Fi Blocker API router
from api.wifi_blocker import router as wifi_blocker_router
app.include_router(wifi_blocker_router)

# Store active attacks
active_attacks = {}

# Root endpoints
@app.get("/")
def read_root():
    return {
        "message": "Airstrike API v2.0.0",
        "description": "WiFi Penetration Testing Backend",
        "endpoints": {
            "docs": "/docs",
            "scan_aps": "/scan/access-points",
            "active_attacks": "/attacks/active",
            "deauth": "/attacks/deauth",
            "icmp": "/attacks/icmp-flood",
            "mitm": "/attacks/mitm",
            "handshake": "/attacks/handshake-capture"
        },
        "status": "ready"
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "active_attacks": len(active_attacks)
    }

# Access Point Scanning
@app.post("/scan/access-points")
def scan_aps(request: APScanRequest):
    """Scan for WiFi access points"""
    try:
        if request.advanced:
            access_points = scan_access_points_advanced(request.interface, request.duration)
        else:
            access_points = scan_access_points_basic(request.interface)
        
        return {
            "success": True,
            "interface": request.interface,
            "access_points": access_points,
            "count": len(access_points),
            "scan_type": "advanced" if request.advanced else "basic"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e),
            "access_points": [],
            "count": 0
        })

# Client Discovery
@app.post("/attacks/icmp-flood/discover")
async def discover_network_clients(request: ICMPFloodRequest):
    """Discover clients on the network using improved ARP scanning"""
    try:
        # Use provided interface or auto-detect
        interface = request.interface if request.interface else None
        attack = ICMPFloodAttack(interface=interface)
        clients = await attack.discover_clients()
        
        return {
            "success": True,
            "interface": attack.interface,
            "clients": clients,
            "count": len(clients),
            "network_range": attack.network_range
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e),
            "clients": [],
            "count": 0
        })

@app.get("/attacks/icmp-flood/targets")
def get_icmp_targets(interface: str = None):
    """Get targets in selection format (like reference script)"""
    try:
        attack = ICMPFloodAttack(interface=interface)
        targets = attack.get_targets_for_selection()
        
        return {
            "success": True,
            "interface": attack.interface,
            "targets": targets,
            "count": len(targets),
            "network_range": attack.network_range
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e),
            "targets": [],
            "count": 0
        })

# MITM Attack Endpoints
@app.post("/attacks/mitm/discover")
def discover_mitm_clients(request: MITMAttackRequest):
    """Discover clients for MITM attack"""
    try:
        attack = MITMAttack(interface=request.interface)
        
        # Check network connection
        if not attack.check_network_connection():
            raise HTTPException(status_code=400, detail={
                "success": False,
                "error": "Interface not connected to network or no IP address",
                "clients": [],
                "count": 0
            })
        
        # Discover clients
        clients = attack.discover_network_clients()
        
        return {
            "success": True,
            "interface": request.interface,
            "clients": clients,
            "count": len(clients),
            "network_info": {
                "our_ip": attack.our_ip,
                "gateway_ip": attack.gateway_ip,
                "network_range": attack.network_range
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e),
            "clients": [],
            "count": 0
        })

@app.post("/attacks/mitm/start")
def start_mitm_attack(request: MITMAttackRequest):
    """Start MITM attack"""
    try:
        if not request.target_ips:
            raise HTTPException(status_code=400, detail={
                "success": False,
                "error": "No target IPs specified"
            })
        
        attack_id = f"mitm_{int(time.time())}"
        
        attack = MITMAttack(interface=request.interface)
        active_attacks[attack_id] = attack
        
        success, message = attack.start_attack(request.target_ips)
        
        if success:
            return {
                "success": True,
                "attack_id": attack_id,
                "message": message,
                "targets": request.target_ips
            }
        else:
            del active_attacks[attack_id]
            raise HTTPException(status_code=500, detail={
                "success": False,
                "error": message
            })
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.post("/attacks/mitm/stop/{attack_id}")
def stop_mitm_attack(attack_id: str):
    """Stop MITM attack"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        success, message = attack.stop_attack()
        
        if success:
            del active_attacks[attack_id]
            return {
                "success": True,
                "message": message,
                "attack_id": attack_id
            }
        else:
            raise HTTPException(status_code=500, detail={
                "success": False,
                "error": message
            })
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.get("/attacks/mitm/status/{attack_id}")
def get_mitm_status(attack_id: str):
    """Get MITM attack status"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        stats = attack.get_current_stats()
        
        return {
            "success": True,
            "attack_id": attack_id,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.get("/attacks/mitm/traffic/{attack_id}")
def get_mitm_traffic(attack_id: str, limit: int = 50):
    """Get captured traffic from MITM attack"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        traffic = attack.get_captured_traffic(limit)
        
        return {
            "success": True,
            "attack_id": attack_id,
            "traffic": traffic,
            "count": len(traffic)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.post("/attacks/deauth/start")
async def start_deauth_attack(request: DeauthAttackRequest):
    """Start deauthentication attack"""
    try:
        attack_id = f"deauth_{int(time.time())}"
        attack = DeauthAttack(
            interface=request.interface,
            ssid=request.ssid,
            bssid=request.bssid,
            channel=request.channel
        )
        active_attacks[attack_id] = attack
        asyncio.create_task(attack.start_attack())
        return {
            "success": True,
            "attack_id": attack_id,
            "message": "Deauthentication attack started",
            "target": {
                "ssid": request.ssid,
                "bssid": request.bssid,
                "channel": request.channel
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })


@app.post("/attacks/deauth/stop/{attack_id}")
async def stop_deauth_attack(attack_id: str):
    """Stop deauthentication attack"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        await attack.stop_attack()
        del active_attacks[attack_id]
        
        return {
            "success": True,
            "message": "Deauth attack stopped",
            "attack_id": attack_id
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.get("/attacks/deauth/status/{attack_id}")
def get_deauth_status(attack_id: str):
    """Get deauthentication attack status"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        stats = attack.get_current_stats()
        
        return {
            "success": True,
            "attack_id": attack_id,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

# ICMP Flood Attack Endpoints (HTTP only)
@app.post("/attacks/icmp-flood/start")
def start_icmp_flood(request: ICMPFloodRequest, background_tasks: BackgroundTasks):
    """Start ICMP flood attack"""
    try:
        if not request.target_ip:
            raise HTTPException(status_code=400, detail="target_ip is required")
        
        attack_id = f"icmp_{int(time.time())}"
        attack = ICMPFloodAttack(interface=request.interface, use_hping3=getattr(request, 'use_hping3', False))
        active_attacks[attack_id] = attack

        # Use the SYNC WRAPPER for the async attack
        background_tasks.add_task(
            attack.start_attack_bg,
            request.target_ip,
            request.packet_size,
            request.delay
        )
        
        return {
            "success": True,
            "attack_id": attack_id,
            "message": "ICMP flood attack started",
            "target": request.target_ip,
            "packet_size": request.packet_size,
            "delay": request.delay
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.post("/attacks/icmp-flood/stop/{attack_id}")
async def stop_icmp_flood(attack_id: str):
    """Stop ICMP flood attack"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        await attack.stop_attack()
        del active_attacks[attack_id]
        
        return {
            "success": True,
            "message": "ICMP flood stopped",
            "attack_id": attack_id
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.get("/attacks/icmp-flood/status/{attack_id}")
def get_icmp_flood_status(attack_id: str):
    """Get ICMP flood attack status"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        stats = attack.get_current_stats()
        
        return {
            "success": True,
            "attack_id": attack_id,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

# Handshake Capture Attack Endpoints
@app.post("/attacks/handshake-capture/start")
async def start_handshake_capture(request: HandshakeCaptureRequest):
    """Start handshake capture attack"""
    try:
        attack_id = f"handshake_{int(time.time())}"
        attack = HandshakeCaptureAttack(
            interface=request.interface,
            ssid=request.ssid,
            bssid=request.bssid,
            channel=request.channel,
            wordlist=request.wordlist,
            timeout=request.timeout,
            deauth_count=request.deauth_count,
            deauth_interval=request.deauth_interval
        )
        active_attacks[attack_id] = attack
        
        # Start the attack with proper error handling
        async def run_attack_with_error_handling():
            try:
                print(f"[API] Starting handshake capture attack {attack_id}")
                result = await attack.start_attack()
                print(f"[API] Handshake capture attack {attack_id} completed with result: {result}")
                return result
            except Exception as e:
                print(f"[API] Handshake capture attack {attack_id} failed with error: {e}")
                # Remove the attack from active_attacks if it failed
                if attack_id in active_attacks:
                    del active_attacks[attack_id]
                raise e
        
        asyncio.create_task(run_attack_with_error_handling())
        
        return {
            "success": True,
            "attack_id": attack_id,
            "message": "Handshake capture attack started",
            "target": {
                "ssid": request.ssid,
                "bssid": request.bssid,
                "channel": request.channel,
                "wordlist": request.wordlist
            }
        }
    except Exception as e:
        print(f"[API] Error starting handshake capture attack: {e}")
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.post("/attacks/handshake-capture/stop/{attack_id}")
async def stop_handshake_capture(attack_id: str):
    """Stop handshake capture attack"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        await attack.stop_attack()
        del active_attacks[attack_id]
        
        return {
            "success": True,
            "message": "Handshake capture attack stopped",
            "attack_id": attack_id
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.get("/attacks/handshake-capture/status/{attack_id}")
def get_handshake_capture_status(attack_id: str):
    """Get handshake capture attack status"""
    try:
        if attack_id not in active_attacks:
            raise HTTPException(status_code=404, detail={
                "success": False,
                "error": "Attack not found"
            })
        
        attack = active_attacks[attack_id]
        stats = attack.get_current_stats()
        
        return {
            "success": True,
            "attack_id": attack_id,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

# General Attack Management
@app.get("/attacks/active")
def get_active_attacks():
    """Get list of all active attacks"""
    try:
        attacks_info = {}
        for attack_id, attack in active_attacks.items():
            attack_type = "deauth" if "deauth" in attack_id else "icmp" if "icmp" in attack_id else "mitm" if "mitm" in attack_id else "handshake" if "handshake" in attack_id else "unknown"
            attacks_info[attack_id] = {
                "type": attack_type,
                "stats": attack.get_current_stats()
            }
        
        return {
            "success": True,
            "active_attacks": attacks_info,
            "count": len(attacks_info),
            "timestamp": time.time()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

@app.post("/attacks/stop-all")
async def stop_all_attacks():
    """Stop all active attacks"""
    try:
        stopped_attacks = []
        
        for attack_id, attack in list(active_attacks.items()):
            try:
                if hasattr(attack, 'stop_attack'):
                    if "mitm" in attack_id:
                        attack.stop_attack()
                    else:
                        await attack.stop_attack()
                stopped_attacks.append(attack_id)
                del active_attacks[attack_id]
            except Exception as e:
                print(f"Error stopping attack {attack_id}: {e}")
        
        return {
            "success": True,
            "message": f"Stopped {len(stopped_attacks)} attacks",
            "stopped_attacks": stopped_attacks
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "success": False,
            "error": str(e)
        })

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application"""
    print("🚀 Airstrike API v2.0.0 Starting...")
    print("📡 WiFi Penetration Testing Backend Ready")
    print("📚 API Documentation: http://localhost:8000/docs")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on shutdown"""
    print("🛑 Shutting down Airstrike API...")
    
    # Stop all active attacks
    for attack_id, attack in list(active_attacks.items()):
        try:
            if "mitm" in attack_id:
                attack.stop_attack()
            else:
                await attack.stop_attack()
            print(f"✅ Stopped attack: {attack_id}")
        except Exception as e:
            print(f"❌ Error stopping attack {attack_id}: {e}")
    
    active_attacks.clear()
    print("✅ Cleanup complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
