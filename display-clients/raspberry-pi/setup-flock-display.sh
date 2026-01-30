#!/bin/bash
# ============================================================================
# Flock Squawk Display - Raspberry Pi One-Click Setup
# ============================================================================
# 
# Usage: 
#   1. Copy this folder to a USB drive
#   2. Plug USB into Raspberry Pi
#   3. Open terminal and run:
#      bash /media/pi/USB_DRIVE/raspberry-pi/setup-flock-display.sh
#
# Or if you copied the folder to the Pi:
#      bash ~/Downloads/raspberry-pi/setup-flock-display.sh
#
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     FLOCK SQUAWK DISPLAY - RASPBERRY PI SETUP                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# ============================================================================
# CONFIGURATION
# ============================================================================

INSTALL_DIR="$HOME/flock-squawk-display"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$HOME/Desktop"

# ============================================================================
# MAIN SETUP
# ============================================================================

print_header

echo "This script will:"
echo "  1. Install required packages (pygame, pyserial)"
echo "  2. Copy display client to $INSTALL_DIR"
echo "  3. Create a desktop shortcut for easy launching"
echo "  4. Configure serial port permissions"
echo ""
read -p "Continue? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

echo ""

# Step 1: Update and install system packages
echo -e "${BLUE}[1/5] Installing system packages...${NC}"
sudo apt-get update -qq
sudo apt-get install -y -qq python3-pygame python3-serial python3-pip
print_step "System packages installed"

# Step 2: Install Python packages
echo -e "${BLUE}[2/5] Installing Python packages...${NC}"
pip3 install --user --quiet pygame pyserial 2>/dev/null || true
print_step "Python packages installed"

# Step 3: Copy files to install directory
echo -e "${BLUE}[3/5] Installing Flock Squawk Display...${NC}"
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/flock_display.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/" 2>/dev/null || true
print_step "Files copied to $INSTALL_DIR"

# Step 4: Create launcher script
echo -e "${BLUE}[4/5] Creating launcher scripts...${NC}"

# Main launcher script
cat > "$INSTALL_DIR/start-display.sh" << 'LAUNCHER'
#!/bin/bash
# Flock Squawk Display Launcher

cd "$(dirname "$0")"

# Find the detector serial port
find_port() {
    for port in /dev/ttyACM* /dev/ttyUSB*; do
        if [[ -e "$port" ]]; then
            echo "$port"
            return 0
        fi
    done
    return 1
}

# Check if detector is connected
PORT=$(find_port)
if [[ -z "$PORT" ]]; then
    zenity --error --title="Flock Squawk" \
           --text="No detector found!\n\nPlease connect the Flock detector via USB and try again." \
           2>/dev/null || echo "ERROR: No detector found. Connect via USB and try again."
    exit 1
fi

echo "Found detector on $PORT"

# Launch the display
exec python3 flock_display.py --port "$PORT" --fullscreen
LAUNCHER
chmod +x "$INSTALL_DIR/start-display.sh"

# Windowed mode launcher
cat > "$INSTALL_DIR/start-display-windowed.sh" << 'LAUNCHER2'
#!/bin/bash
# Flock Squawk Display Launcher (Windowed)

cd "$(dirname "$0")"

# Find the detector serial port
for port in /dev/ttyACM* /dev/ttyUSB*; do
    if [[ -e "$port" ]]; then
        exec python3 flock_display.py --port "$port"
    fi
done

echo "ERROR: No detector found. Connect via USB and try again."
read -p "Press Enter to close..."
LAUNCHER2
chmod +x "$INSTALL_DIR/start-display-windowed.sh"

print_step "Launcher scripts created"

# Step 5: Create desktop shortcut
echo -e "${BLUE}[5/5] Creating desktop shortcut...${NC}"

mkdir -p "$DESKTOP_DIR"

cat > "$DESKTOP_DIR/Flock-Squawk-Display.desktop" << DESKTOP
[Desktop Entry]
Name=Flock Squawk Display
Comment=Surveillance Device Detection Display
Exec=$INSTALL_DIR/start-display.sh
Icon=security-high
Terminal=false
Type=Application
Categories=Utility;Security;
StartupNotify=true
DESKTOP

chmod +x "$DESKTOP_DIR/Flock-Squawk-Display.desktop"

# Also create windowed version
cat > "$DESKTOP_DIR/Flock-Squawk-Windowed.desktop" << DESKTOP2
[Desktop Entry]
Name=Flock Squawk (Windowed)
Comment=Surveillance Device Detection Display (Windowed Mode)
Exec=$INSTALL_DIR/start-display-windowed.sh
Icon=security-medium
Terminal=true
Type=Application
Categories=Utility;Security;
DESKTOP2

chmod +x "$DESKTOP_DIR/Flock-Squawk-Windowed.desktop"

print_step "Desktop shortcuts created"

# Configure serial permissions
echo -e "${BLUE}Configuring permissions...${NC}"
if ! groups "$USER" | grep -q dialout; then
    sudo usermod -a -G dialout "$USER"
    print_warn "Added $USER to dialout group - LOGOUT REQUIRED"
    NEEDS_LOGOUT=true
else
    print_step "Serial permissions already configured"
    NEEDS_LOGOUT=false
fi

# ============================================================================
# DONE!
# ============================================================================

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETE!                                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Installed to: $INSTALL_DIR"
echo ""
echo "Desktop shortcuts created:"
echo "  • Flock Squawk Display (fullscreen)"
echo "  • Flock Squawk Windowed (for testing)"
echo ""

if [[ "${NEEDS_LOGOUT:-false}" == "true" ]]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  IMPORTANT: You must LOG OUT and log back in for serial     ║${NC}"
    echo -e "${YELLOW}║  port permissions to take effect!                           ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "Log out now? [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo "Logging out in 3 seconds..."
        sleep 3
        loginctl terminate-user "$USER" 2>/dev/null || pkill -KILL -u "$USER"
    fi
else
    echo "To start:"
    echo "  1. Connect the Flock detector via USB"
    echo "  2. Double-click 'Flock Squawk Display' on Desktop"
    echo ""
    echo "Or run from terminal:"
    echo "  $INSTALL_DIR/start-display.sh"
fi
