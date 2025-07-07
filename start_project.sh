#!/bin/bash

echo "🎯 Starting Airstrike Project"
echo "=============================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./start_project.sh"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command_exists python3; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

if ! command_exists node; then
    echo "❌ Node.js not found. Please install Node.js 16+"
    exit 1
fi

if ! command_exists npm; then
    echo "❌ npm not found. Please install npm"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Start backend
echo ""
echo "🚀 Starting Backend Server..."
cd backend
python3 -c "
import sys
try:
    import fastapi, uvicorn, scapy, netifaces, websockets
    print('✅ Backend dependencies OK')
except ImportError as e:
    print(f'❌ Missing backend dependency: {e}')
    print('Run: sudo pip install -r requirements.txt')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ Backend dependency check failed"
    exit 1
fi

# Start backend in background
echo "Starting FastAPI server on port 8000..."
python3 start_backend.py &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

# Wait for backend to start
sleep 5

# Check if backend is running
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "❌ Backend failed to start"
    kill $BACKEND_PID 2>/dev/null
    exit 1
fi

echo "✅ Backend started successfully"

# Start frontend
echo ""
echo "🎨 Starting Frontend Server..."
cd ../frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "❌ Frontend dependency installation failed"
        kill $BACKEND_PID 2>/dev/null
        exit 1
    fi
fi

echo "Starting React development server on port 3000..."
npm start &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

# Wait for frontend to start
sleep 10

echo ""
echo "🎉 Airstrike Project Started Successfully!"
echo "=========================================="
echo "📡 Backend:  http://localhost:8000"
echo "🎨 Frontend: http://localhost:3000"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "Press Ctrl+C to stop both servers"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    echo "✅ Cleanup complete"
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Wait for user to stop
wait
