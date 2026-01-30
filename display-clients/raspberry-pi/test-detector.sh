#!/bin/bash
# ============================================================================
# Flock Squawk - Simple Test Script (No Display Required)
# ============================================================================
# Use this to verify the detector is sending data before setting up the display
#
# Usage: bash test-detector.sh [/dev/ttyACM0]
# ============================================================================

PORT="${1:-auto}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     FLOCK SQUAWK - DETECTOR TEST                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Auto-detect port if not specified
if [[ "$PORT" == "auto" ]]; then
    echo "Searching for detector..."
    for p in /dev/ttyACM* /dev/ttyUSB*; do
        if [[ -e "$p" ]]; then
            PORT="$p"
            break
        fi
    done
    
    if [[ "$PORT" == "auto" ]]; then
        echo -e "${RED}ERROR: No serial device found!${NC}"
        echo ""
        echo "Make sure the Flock detector is connected via USB."
        echo "Available ports:"
        ls -la /dev/tty{ACM,USB}* 2>/dev/null || echo "  (none found)"
        exit 1
    fi
fi

echo -e "${GREEN}Found detector on: $PORT${NC}"
echo ""
echo "Listening for data... (Press Ctrl+C to stop)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check if we can access the port
if [[ ! -r "$PORT" ]]; then
    echo -e "${RED}ERROR: Cannot read from $PORT${NC}"
    echo "Try: sudo chmod 666 $PORT"
    echo "Or log out/in after running the setup script."
    exit 1
fi

# Simple Python script to parse and display data
python3 << PYTHON
import serial
import json
import sys
from datetime import datetime

port = "$PORT"
baud = 115200

print(f"Connecting to {port} @ {baud} baud...")

try:
    ser = serial.Serial(port, baud, timeout=1)
except serial.SerialException as e:
    print(f"ERROR: {e}")
    sys.exit(1)

print("Connected! Waiting for data...\n")

detection_count = 0

while True:
    try:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if not line:
            continue
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Check if it's JSON
        if line.startswith('{'):
            try:
                data = json.loads(line)
                
                # Detection event
                if 'protocol' in data:
                    detection_count += 1
                    protocol = data.get('protocol', 'unknown').upper()
                    mac = data.get('mac_address', 'unknown')
                    rssi = data.get('rssi', '?')
                    method = data.get('detection_method', 'unknown')
                    
                    print(f"\033[91m{'═' * 60}\033[0m")
                    print(f"\033[91m  ⚠️  DETECTION #{detection_count} @ {timestamp}\033[0m")
                    print(f"\033[91m{'═' * 60}\033[0m")
                    print(f"  Protocol: {protocol}")
                    print(f"  MAC:      {mac}")
                    print(f"  Method:   {method}")
                    print(f"  RSSI:     {rssi} dBm")
                    
                    if data.get('ssid'):
                        print(f"  SSID:     {data['ssid']}")
                    if data.get('device_name'):
                        print(f"  Name:     {data['device_name']}")
                    if data.get('threat_score'):
                        print(f"  Threat:   {data['threat_score']}%")
                    
                    print()
                else:
                    # Other JSON (maybe status)
                    print(f"[{timestamp}] JSON: {line[:80]}...")
                    
            except json.JSONDecodeError:
                print(f"[{timestamp}] {line}")
        else:
            # Regular log output
            if '[BLE] scan' in line:
                print(f"\033[90m[{timestamp}] {line}\033[0m")  # Dim for scan messages
            elif 'DETECT' in line or 'ALERT' in line:
                print(f"\033[93m[{timestamp}] {line}\033[0m")  # Yellow for alerts
            else:
                print(f"[{timestamp}] {line}")
                
    except KeyboardInterrupt:
        print(f"\n\nTest complete. Total detections: {detection_count}")
        break
    except Exception as e:
        print(f"Error: {e}")
        continue

ser.close()
PYTHON
