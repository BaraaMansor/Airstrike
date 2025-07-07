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

The application is now production-ready with proper separation between frontend and backend! 🚀
