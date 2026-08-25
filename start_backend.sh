#!/bin/bash

# SentinelTrace AI - Quick Start Script for Linux/Mac

echo ""
echo "====================================================="
echo "  SentinelTrace AI - Email Threat Detection Platform"
echo "  Smart India Hackathon 2026 - SIH26106"
echo "====================================================="
echo ""

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -q

# Clear screen
clear

echo ""
echo "====================================================="
echo "  Starting SentinelTrace AI Backend..."
echo "====================================================="
echo ""
echo "Backend URL: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server."
echo ""

# Start backend
cd backend
python main.py
