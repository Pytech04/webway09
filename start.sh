#!/bin/bash
# Start script for production deployment (Render, Heroku, etc)
# Starts Flask backend and Node.js proxy server

echo "Starting Wayback Forensic Scraper..."

# Use PORT env var from Render, default to 5000
PORT=${PORT:-5000}

# Start Flask in background on port 5001
echo "Starting Flask backend on port 5001..."
python server.py &
FLASK_PID=$!

# Wait for Flask to initialize
sleep 3

# Start Node.js proxy on the assigned PORT
echo "Starting Node.js proxy on port $PORT..."
PORT=$PORT NODE_ENV=production node dist/index.js &
NODE_PID=$!

# Cleanup function
cleanup() {
    echo "Shutting down servers..."
    kill $FLASK_PID 2>/dev/null
    kill $NODE_PID 2>/dev/null
    exit
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

# Wait for both processes
wait
