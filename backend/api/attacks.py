@router.post("/handshake-capture/start")
async def start_handshake_capture(
    request: HandshakeCaptureRequest,
    websocket: WebSocket = Depends(get_websocket)
):
    """
    Start a handshake capture attack with enhanced configuration options
    
    Features:
    - Monitor mode setup and channel management
    - Client discovery and targeted deauth
    - Robust handshake capture with airodump-ng
    - Enhanced handshake validation (4 EAPOL messages)
    - Password cracking with aircrack-ng
    - Real-time progress updates and status reporting
    - Comprehensive error handling and logging
    - Automatic managed mode restoration
    """
    try:
        # Validate required fields
        if not request.interface:
            raise HTTPException(status_code=400, detail="Interface is required")
        if not request.ssid:
            raise HTTPException(status_code=400, detail="SSID is required")
        if not request.bssid:
            raise HTTPException(status_code=400, detail="BSSID is required")
        if not request.channel:
            raise HTTPException(status_code=400, detail="Channel is required")
        
        # Validate BSSID format (relaxed validation)
        bssid = request.bssid.lower().replace('-', ':')
        if len(bssid.split(':')) != 6:
            raise HTTPException(status_code=400, detail="Invalid BSSID format")
        
        # Set default values for optional parameters
        wordlist = request.wordlist or "/usr/share/wordlists/rockyou.txt"
        timeout = request.timeout or 60
        deauth_count = request.deauth_count or 5
        deauth_interval = request.deauth_interval or 2.0
        output_dir = request.output_dir or "/tmp/airstrike_captures"
        restore_managed = request.restore_managed if request.restore_managed is not None else True
        
        # Validate wordlist exists
        if not os.path.exists(wordlist):
            raise HTTPException(
                status_code=400, 
                detail=f"Wordlist not found: {wordlist}. Please provide a valid wordlist path."
            )
        
        # Check if attack is already running
        if hasattr(websocket, 'handshake_attack') and websocket.handshake_attack and websocket.handshake_attack.running:
            return {
                "status": "error",
                "message": "Handshake capture attack is already running",
                "attack_id": id(websocket.handshake_attack)
            }
        
        # Create and start the attack
        attack = HandshakeCaptureAttack(
            interface=request.interface,
            ssid=request.ssid,
            bssid=bssid,
            channel=request.channel,
            wordlist=wordlist,
            timeout=timeout,
            deauth_count=deauth_count,
            deauth_interval=deauth_interval,
            websocket=websocket,
            output_dir=output_dir,
            restore_managed=restore_managed
        )
        
        # Store attack reference
        websocket.handshake_attack = attack
        
        # Start the attack
        success = await attack.start_attack()
        
        if success:
            return {
                "status": "success",
                "message": f"Handshake capture attack started on {request.ssid} ({bssid})",
                "attack_id": id(attack),
                "configuration": {
                    "interface": request.interface,
                    "ssid": request.ssid,
                    "bssid": bssid,
                    "channel": request.channel,
                    "wordlist": wordlist,
                    "timeout": timeout,
                    "deauth_count": deauth_count,
                    "deauth_interval": deauth_interval,
                    "output_dir": output_dir,
                    "restore_managed": restore_managed
                }
            }
        else:
            return {
                "status": "error",
                "message": "Failed to start handshake capture attack",
                "errors": attack.error_log
            }
            
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Unexpected error starting handshake capture: {str(e)}"
        print(f"[API] {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@router.post("/handshake-capture/stop")
async def stop_handshake_capture(websocket: WebSocket = Depends(get_websocket)):
    """
    Stop the currently running handshake capture attack
    
    Returns:
    - Final attack statistics
    - Handshake capture status
    - Password cracking results
    - Error log if any
    """
    try:
        if not hasattr(websocket, 'handshake_attack') or not websocket.handshake_attack:
            return {
                "status": "error",
                "message": "No handshake capture attack is currently running"
            }
        
        attack = websocket.handshake_attack
        
        if not attack.running:
            return {
                "status": "info",
                "message": "Handshake capture attack is not currently running",
                "final_stats": attack.get_current_stats()
            }
        
        # Stop the attack
        final_stats = await attack.stop_attack()
        
        # Clear the attack reference
        websocket.handshake_attack = None
        
        return {
            "status": "success",
            "message": "Handshake capture attack stopped successfully",
            "final_stats": final_stats,
            "summary": {
                "handshake_captured": final_stats.get('handshake_captured', False),
                "password_found": final_stats.get('password_found'),
                "cracking_status": final_stats.get('cracking_status'),
                "total_packets_sent": final_stats.get('packets_sent', 0),
                "eapol_packets": final_stats.get('eapol_packets', 0),
                "clients_discovered": final_stats.get('clients_discovered', 0),
                "duration_seconds": final_stats.get('duration', 0),
                "errors": final_stats.get('errors', 0)
            }
        }
        
    except Exception as e:
        error_msg = f"Error stopping handshake capture attack: {str(e)}"
        print(f"[API] {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@router.get("/handshake-capture/status")
async def get_handshake_capture_status(websocket: WebSocket = Depends(get_websocket)):
    """
    Get the current status of the handshake capture attack
    
    Returns:
    - Real-time attack statistics
    - Progress information
    - Handshake validation details
    - Client discovery status
    - Error information
    """
    try:
        if not hasattr(websocket, 'handshake_attack') or not websocket.handshake_attack:
            return {
                "status": "not_running",
                "message": "No handshake capture attack is currently running"
            }
        
        attack = websocket.handshake_attack
        stats = attack.get_current_stats()
        
        return {
            "status": "success",
            "attack_running": attack.running,
            "current_stats": stats,
            "detailed_status": {
                "target": {
                    "ssid": stats.get('ssid'),
                    "bssid": stats.get('bssid'),
                    "channel": stats.get('channel')
                },
                "progress": {
                    "percentage": stats.get('progress', 0),
                    "stage": _get_progress_stage(stats.get('progress', 0)),
                    "duration_seconds": stats.get('duration', 0)
                },
                "handshake": {
                    "captured": stats.get('handshake_captured', False),
                    "eapol_packets": stats.get('eapol_packets', 0),
                    "eapol_messages": stats.get('eapol_messages', {}),
                    "validation_status": _get_handshake_validation_status(stats.get('eapol_messages', {}))
                },
                "cracking": {
                    "status": stats.get('cracking_status', 'not_started'),
                    "password_found": stats.get('password_found'),
                    "wordlist": attack.wordlist if hasattr(attack, 'wordlist') else None
                },
                "network_activity": {
                    "packets_sent": stats.get('packets_sent', 0),
                    "clients_discovered": stats.get('clients_discovered', 0),
                    "clients_targeted": stats.get('clients_targeted', 0),
                    "errors": stats.get('errors', 0)
                },
                "capture": {
                    "output_directory": attack.output_dir if hasattr(attack, 'output_dir') else None,
                    "capture_file": attack.capture_file if hasattr(attack, 'capture_file') else None
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Error getting handshake capture status: {str(e)}"
        print(f"[API] {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

def _get_progress_stage(progress):
    """Convert progress percentage to human-readable stage"""
    if progress == 0:
        return "not_started"
    elif progress <= 10:
        return "initializing"
    elif progress <= 20:
        return "monitor_mode_setup"
    elif progress <= 30:
        return "channel_setup"
    elif progress <= 40:
        return "client_discovery"
    elif progress <= 50:
        return "capture_started"
    elif progress <= 60:
        return "deauth_active"
    elif progress <= 70:
        return "monitoring_handshake"
    elif progress <= 80:
        return "handshake_captured"
    elif progress <= 90:
        return "cracking_password"
    else:
        return "completed"

def _get_handshake_validation_status(eapol_messages):
    """Get detailed handshake validation status"""
    if not eapol_messages:
        return "no_eapol_packets"
    
    present_messages = [msg for msg, present in eapol_messages.items() if present]
    missing_messages = [msg for msg, present in eapol_messages.items() if not present]
    
    if len(present_messages) == 4:
        return "complete_4way_handshake"
    elif len(present_messages) > 0:
        return f"partial_handshake_{len(present_messages)}_of_4_missing_{missing_messages}"
    else:
        return "no_valid_eapol_messages" 