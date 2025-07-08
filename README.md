# 🎯 Airstrike - WiFi Penetration Testing Tool

A comprehensive WiFi penetration testing tool with a modern React frontend and FastAPI backend.

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ with root privileges
- Node.js 16+ and npm
- WiFi adapter that supports monitor mode
- Linux environment (tested on Kali Linux)

### 🔧 Backend Setup

1. **Navigate to backend directory:**
\`\`\`bash
cd backend
\`\`\`

2. **Install Python dependencies:**
\`\`\`bash
sudo pip install -r requirements.txt
\`\`\`

3. **Start the backend server:**
\`\`\`bash
sudo python3 start_backend.py
\`\`\`

The backend will start on `http://localhost:8000`

### 🎨 Frontend Setup

1. **Open a new terminal and navigate to frontend directory:**
\`\`\`bash
cd frontend
\`\`\`

2. **Install Node.js dependencies:**
\`\`\`bash
npm install
\`\`\`

3. **Start the frontend development server:**
\`\`\`bash
npm start
\`\`\`

The frontend will start on `http://localhost:3000`

## 📋 Usage Instructions

### 1. **Access the Application**
- Open your browser and go to `http://localhost:3000`
- The interface should show "healthy" status in the top right

### 2. **Configure Network Interface**
- Set your WiFi interface (usually `wlan0`)
- Ensure the interface supports monitor mode

### 3. **Scan for Access Points**
- Click "Scan Access Points" to discover nearby WiFi networks
- Select a target network from the results

### 4. **Discover Network Clients**
- Click "Discover Clients" to find devices on your network
- Select a target client for ICMP attacks

### 5. **Launch Attacks**
- **Deauth Attack**: Disconnects clients from WiFi networks
- **ICMP Flood**: Floods target with ICMP packets
- **MITM Attack**: Intercepts and analyzes network traffic
- **Handshake Capture**: Captures 4-way handshake and cracks WiFi passwords
- Monitor real-time statistics in the log windows

### 6. **Stop Attacks**
- Use individual stop buttons for each attack
- Use "STOP ALL ATTACKS" for emergency shutdown

## 🛠️ Troubleshooting

### Backend Issues

**Error: "Must run as root"**
\`\`\`bash
sudo python3 start_backend.py
\`\`\`

**Error: "Missing dependency"**
\`\`\`bash
sudo pip install -r requirements.txt
\`\`\`

**Error: "No wireless interfaces found"**
- Check if your WiFi adapter is connected
- Verify monitor mode support: `iwconfig`

**Error: "Monitor mode failed"**
\`\`\`bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
\`\`\`

### Frontend Issues

**Error: "Cannot connect to backend"**
- Ensure backend is running on port 8000
- Check firewall settings
- Verify CORS configuration

**Error: "npm install fails"**
\`\`\`bash
rm -rf node_modules package-lock.json
npm install
\`\`\`

**Error: "Port 3000 already in use"**
\`\`\`bash
npx kill-port 3000
npm start
\`\`\`

### Attack Issues

**Deauth attack not working:**
- Ensure interface is in monitor mode
- Check if target is on the same channel
- Verify BSSID format (aa:bb:cc:dd:ee:ff)

**ICMP flood not working:**
- Ensure you're connected to the target network
- Check if target IP is reachable
- Verify interface has an IP address

**Handshake capture not working:**
- Ensure interface is in monitor mode
- Check if target AP has active clients
- Verify wordlist path exists and is accessible
- Ensure tshark and aircrack-ng are installed

**Attacks don't stop:**
- Use "STOP ALL ATTACKS" button
- Restart both frontend and backend
- Check for zombie processes: `ps aux | grep python`

## 🔍 Testing the Setup

### 1. **Test Backend API**
\`\`\`bash
curl http://localhost:8000/health
\`\`\`
Should return: `{"status":"healthy",...}`

### 2. **Test WebSocket Connection**
- Open browser developer tools
- Check for WebSocket connections in Network tab
- Look for successful connections to `/ws/deauth/` and `/ws/icmp-flood/`

### 3. **Test Interface Detection**
\`\`\`bash
iwconfig
\`\`\`
Should show your wireless interfaces

### 4. **Test Monitor Mode**
\`\`\`bash
sudo iw dev wlan0 info
\`\`\`
Should show `type monitor` when attack is running

## 📁 Project Structure

\`\`\`
airstrike/
├── backend/
│   ├── main.py                 # FastAPI server
│   ├── start_backend.py        # Server startup script
│   ├── requirements.txt        # Python dependencies
│   ├── attacks/               # Attack modules
│   ├── helpers/               # Utility functions
│   └── models.py              # Data models
├── frontend/
│   ├── src/
│   │   ├── App.js             # Main React component
│   │   ├── services/api.js    # API client
│   │   └── App.css            # Styling
│   ├── package.json           # Node.js dependencies
│   └── public/                # Static files
└── README.md                  # This file
\`\`\`

## 🔒 Security Notes

- **Educational Use Only**: This tool is for authorized testing only
- **Legal Compliance**: Only use on networks you own or have permission to test
- **Root Privileges**: Required for network interface manipulation
- **Monitor Mode**: May disconnect you from current WiFi networks

## 🐛 Common Error Solutions

### "Attack doesn't stop" Fix:
The stop functionality has been improved with forced cleanup:
- WebSocket connections are properly closed
- Attack threads are terminated
- Interface state is reset

### "WebSocket connection failed" Fix:
- Backend CORS is configured for `localhost:3000`
- WebSocket URLs use proper `ws://` protocol
- Connection retry logic implemented

### "Interface busy" Fix:
\`\`\`bash
sudo airmon-ng check kill
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
\`\`\`

## 📞 Support

If you encounter issues:

1. **Check Prerequisites**: Ensure all dependencies are installed
2. **Verify Permissions**: Run backend as root
3. **Check Logs**: Look at terminal output for error messages
4. **Test Connectivity**: Verify backend/frontend communication
5. **Restart Services**: Stop and restart both servers

## 🎯 Features

✅ **Real-time WebSocket Updates**  
✅ **Modern React UI with Tailwind CSS**  
✅ **Proper Attack Stop Functionality**  
✅ **Error Handling and Validation**  
✅ **Responsive Design**  
✅ **Live Statistics and Logging**  
✅ **Emergency Stop Controls**  
✅ **Network Discovery Tools**  
✅ **WiFi Handshake Capture & Cracking**  
✅ **Automated Password Recovery**  

The application is now production-ready with proper separation between frontend and backend! 🚀

# 🎯 Airstrike - WiFi Penetration Testing Framework

A comprehensive WiFi penetration testing framework with a modern web interface, featuring multiple attack modules for network security assessment.

## 🚀 Features

### Core Modules
- **Deauthentication Attack** - Force clients to disconnect and reconnect
- **ICMP Flood Attack** - Network stress testing with auto-interface detection
- **MITM Attack** - Man-in-the-middle attack with packet interception
- **Handshake Capture Attack** - Enhanced WPA/WPA2 handshake capture with cracking

### Enhanced Handshake Capture Module

The handshake capture module has been significantly enhanced with the following features:

#### 🔧 **Enhanced Configuration Options**
- **Output Directory Management** - Customizable capture file storage
- **Managed Mode Restoration** - Automatic interface mode restoration after attacks
- **Advanced Timing Controls** - Configurable deauth intervals and packet counts
- **Flexible Wordlist Support** - Custom wordlist paths with validation

#### 📊 **Granular Progress Tracking**
- **10-Stage Progress System**: 10%, 15%, 20%, 30%, 40%, 50%, 60%, 70%, 80%, 100%
- **Real-time Status Updates** - Live progress monitoring via WebSocket
- **Detailed Stage Information** - Clear indication of current attack phase
- **Performance Metrics** - Packets sent, clients discovered, EAPOL packets captured

#### 🔍 **Enhanced Handshake Validation**
- **4-Way EAPOL Message Tracking** - Validates complete handshake capture
- **Individual Message Status** - Tracks each EAPOL message (1-4)
- **Validation Status Reporting** - Detailed handshake completeness information
- **Partial Handshake Detection** - Identifies incomplete captures

#### 🛡️ **Robust Error Handling**
- **Comprehensive Logging** - Detailed error tracking and reporting
- **Subprocess Result Logging** - Enhanced command execution monitoring
- **Interface Mode Management** - Proper monitor/managed mode transitions
- **Resource Cleanup** - Automatic cleanup of processes and files

#### 📈 **Real-time Monitoring**
- **Live Statistics Dashboard** - Real-time attack metrics
- **Client Discovery Tracking** - Monitor discovered clients
- **Network Activity Monitoring** - Track packets sent and errors
- **Cracking Status Updates** - Password cracking progress and results

## 🏗️ Architecture

### Backend (FastAPI)
- **FastAPI** - High-performance web framework
- **WebSocket Support** - Real-time communication
- **Async/Await** - Non-blocking operations
- **Pydantic Models** - Data validation and serialization

### Frontend (React)
- **React 18** - Modern UI framework
- **Tailwind CSS** - Utility-first styling
- **Shadcn/ui** - Beautiful component library
- **Real-time Updates** - WebSocket integration

### Attack Modules
- **Scapy** - Packet manipulation and injection
- **Aircrack-ng** - WiFi security tools
- **Threading** - Concurrent attack execution
- **Process Management** - Subprocess control and cleanup

## 📦 Installation

### Prerequisites
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip nodejs npm

# Install WiFi tools
sudo apt install -y aircrack-ng wireshark-qt tshark

# Install wordlists
sudo apt install -y wordlists
```

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python main.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## 🎯 Usage

### Handshake Capture Attack

#### Basic Usage
```bash
# Start the attack via API
curl -X POST "http://localhost:8000/api/attacks/handshake-capture/start" \
  -H "Content-Type: application/json" \
  -d '{
    "interface": "wlan0",
    "ssid": "TargetNetwork",
    "bssid": "00:11:22:33:44:55",
    "channel": 6
  }'
```

#### Advanced Configuration
```bash
# Enhanced configuration with all options
curl -X POST "http://localhost:8000/api/attacks/handshake-capture/start" \
  -H "Content-Type: application/json" \
  -d '{
    "interface": "wlan0",
    "ssid": "TargetNetwork",
    "bssid": "00:11:22:33:44:55",
    "channel": 6,
    "wordlist": "/usr/share/wordlists/rockyou.txt",
    "timeout": 60,
    "deauth_count": 5,
    "deauth_interval": 2.0,
    "output_dir": "/tmp/airstrike_captures",
    "restore_managed": true
  }'
```

#### Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | string | Required | Wireless interface name |
| `ssid` | string | Required | Target network SSID |
| `bssid` | string | Required | Target network BSSID |
| `channel` | integer | Required | Target network channel (1-165) |
| `wordlist` | string | `/usr/share/wordlists/rockyou.txt` | Password cracking wordlist |
| `timeout` | integer | 60 | Capture timeout in seconds (10-300) |
| `deauth_count` | integer | 5 | Deauth packets per burst (1-50) |
| `deauth_interval` | float | 2.0 | Interval between bursts in seconds (0.5-10.0) |
| `output_dir` | string | `/tmp/airstrike_captures` | Capture file storage directory |
| `restore_managed` | boolean | true | Restore interface to managed mode after attack |

#### Progress Tracking

The attack provides granular progress updates through 10 stages:

1. **10%** - Monitor mode setup
2. **15%** - Channel configuration
3. **20%** - Client discovery started
4. **30%** - Capture process started
5. **40%** - Broadcast deauth active
6. **50%** - Targeted deauth for discovered clients
7. **60%** - Attack running, monitoring for handshake
8. **70%** - Handshake captured, starting cracking
9. **80%** - Password cracking in progress
10. **100%** - Attack completed

#### Handshake Validation

The module validates complete 4-way handshakes by tracking EAPOL messages:

- **Message 1 of 4** - Authentication request
- **Message 2 of 4** - Authentication response
- **Message 3 of 4** - Key confirmation
- **Message 4 of 4** - Key acknowledgment

#### API Endpoints

##### Start Attack
```http
POST /api/attacks/handshake-capture/start
Content-Type: application/json

{
  "interface": "wlan0",
  "ssid": "TargetNetwork",
  "bssid": "00:11:22:33:44:55",
  "channel": 6,
  "wordlist": "/usr/share/wordlists/rockyou.txt",
  "timeout": 60,
  "deauth_count": 5,
  "deauth_interval": 2.0,
  "output_dir": "/tmp/airstrike_captures",
  "restore_managed": true
}
```

##### Get Status
```http
GET /api/attacks/handshake-capture/status
```

Response includes:
- Real-time attack statistics
- Progress percentage and stage
- Handshake validation status
- EAPOL message tracking
- Cracking status and results
- Network activity metrics

##### Stop Attack
```http
POST /api/attacks/handshake-capture/stop
```

#### WebSocket Events

The module sends real-time updates via WebSocket:

- `attack_starting` - Attack initialization
- `progress` - Progress updates with percentage and message
- `client_discovered` - New client detected
- `handshake_captured` - Handshake successfully captured
- `cracking_started` - Password cracking initiated
- `password_found` - Password successfully cracked
- `cracking_failed` - Password not found in wordlist
- `cracking_timeout` - Cracking process timed out
- `cracking_error` - Cracking process error
- `stats_update` - Real-time statistics update
- `attack_stopped` - Attack completed or stopped

## 🧪 Testing

### Enhanced Test Script
```bash
# Run comprehensive test
python3 test_handshake_enhanced.py --interface wlan0

# Run in test mode (shorter timeouts)
python3 test_handshake_enhanced.py --interface wlan0 --test-mode
```

The enhanced test script validates:
- Backend health and tool availability
- API endpoint functionality
- Configuration validation
- Attack lifecycle with progress tracking
- Handshake validation and EAPOL message tracking
- Password cracking functionality
- Managed mode restoration
- Error handling and logging
- Real-time statistics and monitoring
- Attack cleanup and resource management

### Test Features
- **Comprehensive Validation** - Tests all configuration scenarios
- **Progress Monitoring** - Tracks granular progress updates
- **Error Simulation** - Tests error handling and recovery
- **Resource Management** - Validates proper cleanup
- **Performance Metrics** - Monitors attack efficiency

## 🔧 Configuration

### Environment Variables
```bash
# Backend configuration
export AIRSTRIKE_HOST=0.0.0.0
export AIRSTRIKE_PORT=8000
export AIRSTRIKE_DEBUG=true

# Frontend configuration
export VITE_API_URL=http://localhost:8000
```

### Interface Setup
```bash
# Check available interfaces
iwconfig

# Set interface to monitor mode (if needed)
sudo airmon-ng start wlan0

# Verify monitor mode
iwconfig wlan0
```

## 📊 Monitoring and Logging

### Real-time Statistics
- **Packets Sent** - Total deauth packets transmitted
- **EAPOL Packets** - Handshake packets captured
- **Clients Discovered** - Number of clients found
- **Clients Targeted** - Number of clients deauthenticated
- **Errors** - Error count and details
- **Duration** - Attack duration in seconds

### Log Files
- **Capture Files** - Stored in configured output directory
- **Error Logs** - Detailed error tracking
- **Process Logs** - Subprocess execution results
- **WebSocket Logs** - Real-time communication logs

## 🛡️ Security Considerations

### Legal Compliance
- **Authorized Testing Only** - Use only on networks you own or have explicit permission to test
- **Documentation** - Maintain proper authorization documentation
- **Responsible Disclosure** - Report vulnerabilities to network owners
- **Compliance** - Follow local laws and regulations

### Best Practices
- **Interface Management** - Proper monitor/managed mode transitions
- **Resource Cleanup** - Automatic cleanup of processes and files
- **Error Handling** - Comprehensive error tracking and recovery
- **Logging** - Detailed audit trails for compliance

### Safety Features
- **Timeout Protection** - Automatic attack termination
- **Process Management** - Proper subprocess cleanup
- **Interface Restoration** - Automatic managed mode restoration
- **Error Recovery** - Graceful error handling and recovery

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any network. The authors are not responsible for any misuse of this software.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the test scripts for examples

---

**Airstrike** - Advanced WiFi penetration testing made simple and powerful.
