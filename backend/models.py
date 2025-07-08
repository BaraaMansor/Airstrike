from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

# Legacy models
class AttackRequest(BaseModel):
    """Defines the request body for a generic attack requiring a target."""
    target: str = Field(description="Target identifier")

class DhcpFloodRequest(BaseModel):
    """Defines the request body for the DHCP Flood attack, requiring a network interface."""
    interface: str = Field(description="Network interface for DHCP flood")
   
class deauthRequest(BaseModel):
    """Legacy deauth request model"""
    interface: str = Field(description="WiFi interface")
    bssid: str = Field(description="Target BSSID")

# Access Point Scanning
class APScanRequest(BaseModel):
    """Request model for AP scanning"""
    interface: str = Field(description="WiFi interface to use for scanning")
    duration: int = Field(default=30, description="Scan duration in seconds", ge=5, le=300)
    advanced: bool = Field(default=True, description="Use advanced scanning (airodump-ng)")

# Deauthentication Attack
class DeauthAttackRequest(BaseModel):
    """Request model for deauthentication attack"""
    interface: str = Field(description="WiFi interface in monitor mode")
    ssid: str = Field(description="Target network SSID")
    bssid: str = Field(description="Target network BSSID (MAC address)", pattern=r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    channel: int = Field(description="WiFi channel of target network", ge=1, le=14)

# ICMP Flood Attack
class ICMPFloodRequest(BaseModel):
    """Request model for ICMP flood attack"""
    interface: str = Field(description="Network interface connected to AP")
    target_ip: Optional[str] = Field(None, description="Target IP address for flood attack")
    packet_size: int = Field(default=64, description="ICMP packet size in bytes", ge=28, le=65507)
    delay: float = Field(default=0.001, description="Delay between packets in seconds", ge=0.0, le=1.0)
    use_hping3: bool = Field(default=False, description="Use hping3 for ICMP flood instead of Scapy")

# MITM Attack
class MITMAttackRequest(BaseModel):
    """Request model for MITM attack"""
    interface: str = Field(description="Network interface connected to AP")
    target_ips: List[str] = Field(description="List of target IP addresses")

# Handshake Capture Attack
class HandshakeCaptureRequest(BaseModel):
    """Request model for handshake capture attack"""
    interface: str = Field(description="WiFi interface in monitor mode")
    ssid: str = Field(description="Target network SSID")
    bssid: str = Field(description="Target network BSSID (MAC address)", pattern=r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    channel: int = Field(description="WiFi channel of target network", ge=1, le=14)
    wordlist: str = Field(default="/usr/share/wordlists/rockyou.txt", description="Path to wordlist for cracking")
    timeout: int = Field(default=60, description="Capture timeout in seconds", ge=30, le=300)
    deauth_count: int = Field(default=5, description="Number of deauth packets per burst", ge=1, le=20)
    deauth_interval: float = Field(default=2.0, description="Interval between deauth bursts in seconds", ge=0.5, le=10.0)

# Response Models
class NetworkClient(BaseModel):
    """Model for discovered network client"""
    ip: str = Field(description="Client IP address")
    mac: str = Field(description="Client MAC address")
    method: Optional[str] = Field(None, description="Discovery method used")
    status: Optional[str] = Field(None, description="Client status (active/inactive)")
    response_time: Optional[float] = Field(None, description="Ping response time in ms")
    hostname: Optional[str] = Field(None, description="Client hostname")

class ClientDiscoveryResponse(BaseModel):
    """Response model for client discovery"""
    success: bool = Field(description="Operation success status")
    interface: str = Field(description="Interface used for discovery")
    clients: List[NetworkClient] = Field(description="List of discovered clients")
    count: int = Field(description="Number of clients found")
    error: Optional[str] = Field(None, description="Error message if failed")

class AttackStats(BaseModel):
    """Model for attack statistics"""
    packets_sent: Optional[int] = Field(None, description="Total packets sent")
    duration: Optional[int] = Field(None, description="Attack duration in seconds")
    packets_per_second: Optional[float] = Field(None, description="Packets per second rate")
    errors: Optional[int] = Field(None, description="Number of errors encountered")
    status: Optional[str] = Field(None, description="Current attack status")
    target_ip: Optional[str] = Field(None, description="Target IP address")
    ssid: Optional[str] = Field(None, description="Target SSID")
    bssid: Optional[str] = Field(None, description="Target BSSID")
    channel: Optional[int] = Field(None, description="Target channel")
    clients_discovered: Optional[int] = Field(None, description="Number of clients discovered")
    bytes_sent: Optional[int] = Field(None, description="Total bytes sent")
    mbps: Optional[float] = Field(None, description="Data rate in Mbps")
    running: Optional[bool] = Field(None, description="Attack running status")
    target_count: Optional[int] = Field(None, description="Number of targets")
    packets_captured: Optional[int] = Field(None, description="Packets captured")
    dns_requests: Optional[int] = Field(None, description="DNS requests captured")
    http_requests: Optional[int] = Field(None, description="HTTP requests captured")
    # Handshake capture specific fields
    eapol_packets: Optional[int] = Field(None, description="Number of EAPOL packets captured")
    handshake_captured: Optional[bool] = Field(None, description="Whether 4-way handshake was captured")
    cracking_status: Optional[str] = Field(None, description="Status of password cracking")
    password_found: Optional[str] = Field(None, description="Password if found")
    wordlist_used: Optional[str] = Field(None, description="Wordlist used for cracking")
    capture_file: Optional[str] = Field(None, description="Path to captured handshake file")

class AttackStatusResponse(BaseModel):
    """Response model for attack status"""
    success: bool = Field(description="Operation success status")
    attack_id: str = Field(description="Attack identifier")
    stats: AttackStats = Field(description="Attack statistics")
    error: Optional[str] = Field(None, description="Error message if failed")

class AccessPoint(BaseModel):
    """Model for discovered access point"""
    bssid: str = Field(description="Access point BSSID")
    ssid: str = Field(description="Access point SSID")
    channel: Optional[str] = Field(None, description="WiFi channel")
    signal: Optional[int] = Field(None, description="Signal strength")
    power: Optional[int] = Field(None, description="Power level")
    encrypted: Optional[bool] = Field(None, description="Encryption status")
    privacy: Optional[str] = Field(None, description="Security type")
    cipher: Optional[str] = Field(None, description="Cipher type")
    auth: Optional[str] = Field(None, description="Authentication type")

class APScanResponse(BaseModel):
    """Response model for access point scanning"""
    success: bool = Field(description="Operation success status")
    interface: str = Field(description="Interface used for scanning")
    access_points: List[AccessPoint] = Field(description="List of discovered access points")
    count: int = Field(description="Number of access points found")
    scan_type: str = Field(description="Type of scan performed")
    error: Optional[str] = Field(None, description="Error message if failed")

# Traffic Capture Models
class TrafficEntry(BaseModel):
    """Model for captured traffic entry"""
    timestamp: str = Field(description="Capture timestamp")
    type: str = Field(description="Traffic type (DNS, HTTP, etc.)")
    source_ip: str = Field(description="Source IP address")
    details: str = Field(description="Traffic details")
    domain: Optional[str] = Field(None, description="Domain name for DNS")
    host: Optional[str] = Field(None, description="Host for HTTP")
    path: Optional[str] = Field(None, description="Path for HTTP")
    method: Optional[str] = Field(None, description="HTTP method")
    credentials: Optional[bool] = Field(None, description="Possible credentials detected")
