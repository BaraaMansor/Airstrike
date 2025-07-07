#!/usr/bin/env python3
"""
Backend server startup script
"""

import os
import sys
import subprocess
import uvicorn

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("❌ Must run as root for network operations!")
        print("Run: sudo python3 start_backend.py")
        sys.exit(1)

def check_dependencies():
    """Check if all dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import scapy
        import netifaces
        import websockets
        print("✅ All dependencies found")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Install with: pip install -r requirements.txt")
        return False

def main():
    print("🚀 Starting Airstrike Backend Server...")
    print("=" * 50)
    
    # Check prerequisites
    check_root()
    
    if not check_dependencies():
        sys.exit(1)
    
    print("📡 Host: 0.0.0.0")
    print("🔌 Port: 8000")
    print("📚 Documentation: http://localhost:8000/docs")
    print("🔗 WebSocket endpoints available")
    print("🌐 CORS enabled for frontend on port 3000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            access_log=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
