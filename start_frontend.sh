#!/bin/bash

# SentinelTrace AI Frontend - Simple HTTP Server

echo ""
echo "====================================================="
echo "  SentinelTrace AI Frontend Server"
echo "====================================================="
echo ""
echo "Starting web server on port 8001..."
echo ""
echo "Frontend URL: http://localhost:8001"
echo ""
echo "Press Ctrl+C to stop the server."
echo ""

cd frontend
python3 -m http.server 8001 --bind 127.0.0.1
