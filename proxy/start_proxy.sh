#!/bin/bash
echo "==========================================="
echo " CyberTraffic AI — mitmproxy Interceptor"
echo "==========================================="
echo " Proxy listening on: 127.0.0.1:8080"
echo " Browser proxy setting: 127.0.0.1 port 8080"
echo " CA cert install: visit http://mitm.it"
echo "==========================================="
mitmproxy --listen-port 8080 -s proxy/traffic_interceptor.py
