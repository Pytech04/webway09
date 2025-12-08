#!/bin/bash

# Start Flask backend in background
echo "Starting Flask backend on port 5001..."
python server.py &
FLASK_PID=$!

# Wait for Flask to start
sleep 2

# Start Node.js proxy + Vite frontend
echo "Starting Node.js proxy + Vite on port 5000..."
NODE_ENV=development tsx server/index-flask.ts &
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
