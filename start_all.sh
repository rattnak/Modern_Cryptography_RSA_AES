#!/bin/bash

# Colors for better output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================"
echo -e "${BLUE}Starting Complete RSA + AES Cryptography Application${NC}"
echo "======================================================================"
echo ""

# Function to cleanup background processes on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all servers...${NC}"
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    exit 0
}

# Set up trap to catch Ctrl+C
trap cleanup SIGINT SIGTERM

echo -e "${GREEN}Step 1: Starting Backend (Flask - RSA + AES)${NC}"
echo "----------------------------------------------------------------------"

# Activate virtual environment and start Flask server
source venv/bin/activate
python3 api/app.py > backend.log 2>&1 &
BACKEND_PID=$!

echo "  ✓ Backend server starting on http://localhost:8080"
echo "  ✓ PID: $BACKEND_PID"
echo "  ✓ Logs: backend.log"
echo ""

# Wait for backend to be ready
echo "  Waiting for backend to be ready..."
sleep 3

# Check if backend is running
if curl -s http://localhost:8080/api/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Backend is ready!${NC}"
else
    echo -e "  ${YELLOW}⚠ Backend might not be ready yet (this is normal)${NC}"
fi
echo ""

echo -e "${GREEN}Step 2: Starting Frontend (React + Vite)${NC}"
echo "----------------------------------------------------------------------"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies (first time only)..."
    npm install > /dev/null 2>&1
fi

# Start React development server
npm run dev > frontend.log 2>&1 &
FRONTEND_PID=$!

echo "  ✓ Frontend server starting on http://localhost:5173"
echo "  ✓ PID: $FRONTEND_PID"
echo "  ✓ Logs: frontend.log"
echo ""

sleep 3

echo "======================================================================"
echo -e "${GREEN}✓ Application is running!${NC}"
echo "======================================================================"
echo ""
echo "Backend  (Flask): http://localhost:8080"
echo "Frontend (React): http://localhost:5173"
echo ""
echo "API Endpoints:"
echo "  RSA:"
echo "    - POST /api/generate-keys"
echo "    - POST /api/encrypt"
echo "    - POST /api/decrypt"
echo "    - POST /api/sign"
echo "    - POST /api/verify"
echo "    - POST /api/import-keys"
echo ""
echo "  AES:"
echo "    - POST /api/aes/generate-key"
echo "    - POST /api/aes/encrypt"
echo "    - POST /api/aes/decrypt"
echo ""
echo "Logs:"
echo "  Backend:  tail -f backend.log"
echo "  Frontend: tail -f frontend.log"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all servers${NC}"
echo "======================================================================"

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID
