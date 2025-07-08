from typing import Optional
from pydantic import BaseModel, Field

class HandshakeCaptureRequest(BaseModel):
    """
    Enhanced Handshake Capture Attack Request Model
    
    Features comprehensive configuration options for:
    - Target network identification
    - Attack timing and intensity
    - Output management
    - Interface mode restoration
    - Password cracking settings
    """
    interface: str = Field(..., description="Wireless interface to use for the attack")
    ssid: str = Field(..., description="Target network SSID")
    bssid: str = Field(..., description="Target network BSSID (MAC address)")
    channel: int = Field(..., description="Target network channel", ge=1, le=165)
    
    # Optional attack configuration
    wordlist: Optional[str] = Field(
        default="/usr/share/wordlists/rockyou.txt",
        description="Path to wordlist for password cracking"
    )
    timeout: Optional[int] = Field(
        default=60,
        description="Timeout in seconds for handshake capture",
        ge=10,
        le=300
    )
    deauth_count: Optional[int] = Field(
        default=5,
        description="Number of deauth packets to send per burst",
        ge=1,
        le=50
    )
    deauth_interval: Optional[float] = Field(
        default=2.0,
        description="Interval between deauth bursts in seconds",
        ge=0.5,
        le=10.0
    )
    
    # Enhanced configuration options
    output_dir: Optional[str] = Field(
        default="/tmp/airstrike_captures",
        description="Directory to store capture files and results"
    )
    restore_managed: Optional[bool] = Field(
        default=True,
        description="Whether to restore interface to managed mode after attack"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "interface": "wlan0",
                "ssid": "TestNetwork",
                "bssid": "00:11:22:33:44:55",
                "channel": 6,
                "wordlist": "/usr/share/wordlists/rockyou.txt",
                "timeout": 60,
                "deauth_count": 5,
                "deauth_interval": 2.0,
                "output_dir": "/tmp/airstrike_captures",
                "restore_managed": True
            }
        } 