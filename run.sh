#!/bin/bash
mkdir -p models logs proxy
echo "Starting Web Access Behavior Monitor — port 8002"
python web_access.py
