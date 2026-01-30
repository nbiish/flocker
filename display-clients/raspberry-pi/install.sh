#!/bin/bash
# Flock Squawk Display Client - Raspberry Pi Setup Script
# Run this script to install dependencies and configure the display

set -euo pipefail

echo "=================================="
echo "Flock Squawk Display Client Setup"
echo "=================================="
echo

# Check if running on Raspberry Pi
if [[ ! -f /proc/device-tree/model ]] || ! grep -qi "raspberry" /proc/device-tree/model 2>/dev/null; then
    echo "Warning: This doesn't appear to be a Raspberry Pi"
    echo "Continuing anyway..."
fi

# Update package list
echo "[1/4] Updating package list..."
sudo apt-get update -qq

# Install system dependencies
echo "[2/4] Installing system dependencies..."
sudo apt-get install -y -qq \
    python3-pygame \
    python3-serial \
    python3-pip \
    python3-venv

# Create virtual environment (optional but recommended)
echo "[3/4] Setting up Python environment..."
if [[ ! -d venv ]]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Add user to dialout group for serial access
echo "[4/4] Configuring serial port access..."
if ! groups "$USER" | grep -q dialout; then
    sudo usermod -a -G dialout "$USER"
    echo "Added $USER to dialout group (requires logout/login to take effect)"
fi

echo
echo "=================================="
echo "Installation Complete!"
echo "=================================="
echo
echo "To run the display client:"
echo "  source venv/bin/activate"
echo "  python3 flock_display.py"
echo
echo "Options:"
echo "  --port /dev/ttyUSB0   Specify serial port"
echo "  --fullscreen          Run fullscreen"
echo
echo "To auto-start on boot, add to /etc/rc.local or create a systemd service."
echo
