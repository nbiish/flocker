#!/usr/bin/env python3
"""
Flock Squawk Display Client - Raspberry Pi

Connects to the Flock detector via USB serial and displays
detections on an attached screen using pygame.

Usage:
    python3 flock_display.py [--port /dev/ttyUSB0] [--fullscreen]

Requirements:
    pip install pygame pyserial
"""

import argparse
import json
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import pygame
import serial
import serial.tools.list_ports

# ============================================================================
# CONFIGURATION
# ============================================================================

# Display settings
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 480  # Standard for 7" RPi displays
FPS = 30

# Colors
COLOR_BG = (15, 15, 25)
COLOR_HEADER = (30, 60, 120)
COLOR_ALERT_BG = (100, 20, 20)
COLOR_TEXT = (255, 255, 255)
COLOR_DIM = (100, 100, 100)
COLOR_OK = (50, 200, 50)
COLOR_WARN = (255, 200, 50)
COLOR_ALERT = (255, 50, 50)
COLOR_ACCENT = (100, 150, 255)

# Alert timing
ALERT_FLASH_MS = 200
ALERT_DURATION_S = 10
DETECTION_TIMEOUT_S = 30

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Detection:
    timestamp: float = 0
    protocol: str = ""
    mac_address: str = ""
    ssid: str = ""
    device_name: str = ""
    rssi: int = -100
    signal_strength: str = ""
    threat_score: int = 0
    detection_method: str = ""
    device_type: str = "FLOCK_SAFETY"
    raw_json: dict = field(default_factory=dict)
    
    @property
    def identifier(self) -> str:
        if self.ssid:
            return self.ssid
        if self.device_name:
            return self.device_name
        return self.mac_address
    
    @property
    def is_active(self) -> bool:
        return (time.time() - self.timestamp) < DETECTION_TIMEOUT_S

# ============================================================================
# SERIAL READER
# ============================================================================

class DetectorSerial:
    def __init__(self, ports: list, baud: int = 115200):
        self.ports = ports
        self.baud = baud
        self.serials: list[serial.Serial] = []
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.detection_queue = deque(maxlen=100)
        self.connected = False
        
    def find_detectors(self) -> list[str]:
        """Auto-detect all connected Flock detector USB serial ports."""
        found_ports = []
        ports = serial.tools.list_ports.comports()
        for port in ports:
            # Look for common ESP32 USB identifiers
            if any(x in (port.description or "").lower() for x in 
                   ["cp210", "ch340", "ftdi", "usb serial", "esp32", "xiao"]):
                found_ports.append(port.device)
            elif any(x in (port.vid or 0, port.pid or 0) for x in 
                   [(0x10C4, 0xEA60), (0x1A86, 0x7523), (0x303A, 0x1001)]):
                found_ports.append(port.device)
        return found_ports
    
    def connect(self) -> bool:
        """Connect to the detectors."""
        try:
            if not self.ports or self.ports == ["auto"]:
                self.ports = self.find_detectors()
                if not self.ports:
                    print("Could not auto-detect any detectors. Available ports:")
                    for p in serial.tools.list_ports.comports():
                        print(f"  {p.device}: {p.description}")
                    return False
            
            print(f"Connecting to detectors: {', '.join(self.ports)} @ {self.baud} baud...")
            
            self.serials = []
            for port in self.ports:
                try:
                    s = serial.Serial(port, self.baud, timeout=0.1)
                    self.serials.append(s)
                    print(f"Connected to {port}")
                except serial.SerialException as e:
                    print(f"Failed to connect to {port}: {e}")
            
            if not self.serials:
                self.connected = False
                return False
                
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            self.connected = False
            return False
    
    def start(self):
        """Start the reader thread."""
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the reader thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        for s in self.serials:
            s.close()
    
    def _read_loop(self):
        """Background thread to read serial data from all detectors."""
        buffers = {s: "" for s in self.serials}
        
        while self.running:
            data_read = False
            for s in self.serials:
                try:
                    if s.in_waiting:
                        data = s.read(s.in_waiting).decode('utf-8', errors='ignore')
                        buffers[s] += data
                        data_read = True
                        
                        # Process complete lines
                        while '\n' in buffers[s]:
                            line, buffers[s] = buffers[s].split('\n', 1)
                            line = line.strip()
                            if line.startswith('{'):
                                self._process_json(line)
                except serial.SerialException:
                    pass
            
            if not data_read:
                time.sleep(0.01)
    
    def _process_json(self, json_str: str):
        """Parse JSON detection and add to queue."""
        try:
            data = json.loads(json_str)
            if 'protocol' in data:
                detection = Detection(
                    timestamp=time.time(),
                    protocol=data.get('protocol', ''),
                    mac_address=data.get('mac_address', ''),
                    ssid=data.get('ssid', ''),
                    device_name=data.get('device_name', ''),
                    rssi=data.get('rssi', -100),
                    signal_strength=data.get('signal_strength', ''),
                    threat_score=data.get('threat_score', 0),
                    detection_method=data.get('detection_method', ''),
                    device_type=data.get('device_type', 'FLOCK_SAFETY'),
                    raw_json=data
                )
                self.detection_queue.append(detection)
                print(f"Detection: {detection.protocol} - {detection.identifier} ({detection.rssi} dBm)")
        except json.JSONDecodeError as e:
            pass  # Ignore non-JSON output
    
    def get_latest_detection(self) -> Optional[Detection]:
        """Get the most recent detection."""
        if self.detection_queue:
            return self.detection_queue[-1]
        return None

# ============================================================================
# DISPLAY
# ============================================================================

class FlockDisplay:
    def __init__(self, fullscreen: bool = False, radar_mode: bool = False):
        pygame.init()
        pygame.font.init()
        
        flags = pygame.FULLSCREEN if fullscreen else 0
        if fullscreen:
            info = pygame.display.Info()
            self.width = info.current_w
            self.height = info.current_h
        else:
            self.width = WINDOW_WIDTH
            self.height = WINDOW_HEIGHT
        
        self.screen = pygame.display.set_mode((self.width, self.height), flags)
        pygame.display.set_caption("Flock Squawk Display")
        
        # Fonts
        self.font_large = pygame.font.Font(None, 72)
        self.font_medium = pygame.font.Font(None, 48)
        self.font_small = pygame.font.Font(None, 32)
        self.font_tiny = pygame.font.Font(None, 24)
        
        # State
        self.current_detection: Optional[Detection] = None
        self.total_detections = 0
        self.detection_history: deque = deque(maxlen=10)
        self.alert_start_time = 0
        self.radar_angle = 0
        self.connected = False
        self.tiny_mode = False
        self.radar_mode = radar_mode
        self.scan_line_y = 0
        self.scan_direction = 1
        
    def draw_header(self):
        """Draw the header bar."""
        header_height = 30 if self.tiny_mode else 60
        pygame.draw.rect(self.screen, COLOR_HEADER, (0, 0, self.width, header_height))
        
        title_text = "FLOCK" if self.tiny_mode else "FLOCK SQUAWK"
        title = self.font_medium.render(title_text, True, COLOR_TEXT)
        self.screen.blit(title, (10, 5) if self.tiny_mode else (20, 10))
        
        # Connection status
        status_color = COLOR_OK if self.connected else COLOR_ALERT
        circle_pos = (self.width - 20, 15) if self.tiny_mode else (self.width - 40, 30)
        circle_radius = 6 if self.tiny_mode else 12
        pygame.draw.circle(self.screen, status_color, circle_pos, circle_radius)
        
        # Time
        if not self.tiny_mode:
            time_str = datetime.now().strftime("%H:%M:%S")
            time_surf = self.font_small.render(time_str, True, COLOR_DIM)
            self.screen.blit(time_surf, (self.width - 150, 18))
    
    def draw_idle_screen(self):
        """Draw the idle/scanning screen."""
        # Status text
        status = self.font_large.render("SCANNING", True, COLOR_OK)
        center_y = self.height // 2 - 20 if self.tiny_mode else 120
        status_rect = status.get_rect(center=(self.width // 2, center_y))
        self.screen.blit(status, status_rect)
        
        if self.radar_mode:
            self._draw_radar()
        else:
            self._draw_scanner_bar()
        
        # Stats
        if not self.tiny_mode:
            stats_y = self.height - 80
            stats = [
                f"Detections: {self.total_detections}",
                f"Uptime: {self._format_uptime()}",
            ]
            for i, stat in enumerate(stats):
                surf = self.font_small.render(stat, True, COLOR_DIM)
                self.screen.blit(surf, (20, stats_y + i * 30))
        else:
             # Tiny stats
            stat = f"Det: {self.total_detections}"
            surf = self.font_tiny.render(stat, True, COLOR_DIM)
            self.screen.blit(surf, (5, self.height - 25))

    def _draw_radar(self):
        """Draw the rotating radar animation."""
        # Radar animation
        center_y_radar = self.height // 2 + 20 if self.tiny_mode else self.height // 2 + 40
        center = (self.width // 2, center_y_radar)
        radius = min(self.width, self.height) // (3 if self.tiny_mode else 4)
        
        # Radar circles
        for r in [radius, radius * 2 // 3, radius // 3]:
            pygame.draw.circle(self.screen, COLOR_DIM, center, r, 1)
        
        # Cross hairs
        pygame.draw.line(self.screen, COLOR_DIM, 
                        (center[0] - radius, center[1]), 
                        (center[0] + radius, center[1]), 1)
        pygame.draw.line(self.screen, COLOR_DIM, 
                        (center[0], center[1] - radius), 
                        (center[0], center[1] + radius), 1)
        
        # Sweep line
        import math
        end_x = center[0] + int(math.cos(math.radians(self.radar_angle)) * radius)
        end_y = center[1] + int(math.sin(math.radians(self.radar_angle)) * radius)
        pygame.draw.line(self.screen, COLOR_OK, center, (end_x, end_y), 2)
        
        # Sweep trail (fading)
        for i in range(30):
            alpha = 255 - i * 8
            angle = self.radar_angle - i * 2
            ex = center[0] + int(math.cos(math.radians(angle)) * radius)
            ey = center[1] + int(math.sin(math.radians(angle)) * radius)
            color = (0, min(255, 100 + alpha // 3), 0)
            pygame.draw.line(self.screen, color, center, (ex, ey), 1)
        
        self.radar_angle = (self.radar_angle + 3) % 360

    def _draw_scanner_bar(self):
        """Draw a simple singular bar scanner animation."""
        bar_height = 4 if self.tiny_mode else 8
        bar_width = self.width * 0.8
        bar_x = (self.width - bar_width) // 2
        
        # Define scan area
        scan_top = self.height // 2 + 10
        scan_bottom = self.height - (30 if self.tiny_mode else 80)
        scan_height = scan_bottom - scan_top
        
        # Initialize position if needed
        if self.scan_line_y < scan_top or self.scan_line_y > scan_bottom:
            self.scan_line_y = scan_top
            
        # Draw bounds
        pygame.draw.rect(self.screen, COLOR_DIM, (bar_x, scan_top, bar_width, scan_height), 1)
        
        # Draw moving bar
        pygame.draw.rect(self.screen, COLOR_OK, 
                        (bar_x, int(self.scan_line_y), bar_width, bar_height))
        
        # Update position
        speed = 2 if self.tiny_mode else 4
        self.scan_line_y += speed * self.scan_direction
        
        if self.scan_line_y >= scan_bottom - bar_height or self.scan_line_y <= scan_top:
            self.scan_direction *= -1

    def draw_alert_screen(self):
        """Draw the detection alert screen."""
        detection = self.current_detection
        if not detection:
            return
        
        elapsed = time.time() - self.alert_start_time
        
        header_height = 30 if self.tiny_mode else 60
        
        # Flashing background for new alerts
        if elapsed < ALERT_DURATION_S:
            flash = int(elapsed * 1000 / ALERT_FLASH_MS) % 2
            if flash:
                pygame.draw.rect(self.screen, COLOR_ALERT_BG, 
                               (0, header_height, self.width, self.height - header_height))
        
        # ALERT banner
        alert_y = header_height + 10 if self.tiny_mode else 110
        alert_text = self.font_large.render("⚠ DETECTED!", True, COLOR_ALERT)
        alert_rect = alert_text.get_rect(center=(self.width // 2, alert_y))
        self.screen.blit(alert_text, alert_rect)
        
        # Device info panel
        if self.tiny_mode:
            panel_y = header_height + 40
            panel_height = self.height - panel_y - 10
            info_x = 10
            info_y = panel_y
            line_height = 25
        else:
            panel_y = 160
            panel_height = 200
            info_x = 40
            info_y = panel_y + 15
            line_height = 35
            
            pygame.draw.rect(self.screen, (30, 30, 40), 
                            (20, panel_y, self.width - 40, panel_height), 
                            border_radius=10)
            pygame.draw.rect(self.screen, COLOR_ACCENT, 
                            (20, panel_y, self.width - 40, panel_height), 
                            2, border_radius=10)
        
        # Device details
        info_lines = [
            ("Type:", detection.protocol.upper()),
            ("ID:", detection.identifier[:20] if self.tiny_mode else detection.identifier[:30]),
            ("Sig:", f"{detection.rssi} dBm"),
        ]
        
        if not self.tiny_mode:
             info_lines.insert(1, ("MAC:", detection.mac_address))
             info_lines.append(("Method:", detection.detection_method))
        
        for label, value in info_lines:
            label_surf = self.font_small.render(label, True, COLOR_DIM)
            value_surf = self.font_small.render(value, True, COLOR_TEXT)
            self.screen.blit(label_surf, (info_x, info_y))
            self.screen.blit(value_surf, (info_x + (60 if self.tiny_mode else 120), info_y))
            info_y += line_height
        
        # Signal strength bar
        if self.tiny_mode:
            bar_y = self.height - 40
            bar_width = self.width - 20
            bar_height = 10
            bar_x = 10
        else:
            bar_y = panel_y + panel_height + 20
            bar_width = self.width - 80
            bar_height = 30
            bar_x = 40
        
        pygame.draw.rect(self.screen, COLOR_DIM, 
                        (bar_x, bar_y, bar_width, bar_height), 2, border_radius=5)
        
        # Map RSSI to bar (typically -100 to -30)
        fill_pct = max(0, min(100, (detection.rssi + 100) / 70 * 100))
        fill_width = int(bar_width * fill_pct / 100)
        
        bar_color = COLOR_OK if detection.rssi > -50 else (COLOR_WARN if detection.rssi > -70 else COLOR_ALERT)
        if fill_width > 0:
            pygame.draw.rect(self.screen, bar_color, 
                           (bar_x, bar_y, fill_width, bar_height), border_radius=5)
        
        # Threat score
        if not self.tiny_mode:
            score_y = bar_y + 50
            threat_color = COLOR_ALERT if detection.threat_score >= 85 else COLOR_WARN
            score_text = self.font_medium.render(f"THREAT: {detection.threat_score}%", True, threat_color)
            score_rect = score_text.get_rect(center=(self.width // 2, score_y))
            self.screen.blit(score_text, score_rect)
            
            # Detection count
            count_text = self.font_tiny.render(f"Total detections: {self.total_detections}", True, COLOR_DIM)
            self.screen.blit(count_text, (20, self.height - 40))
    
    def _format_uptime(self) -> str:
        """Format uptime as HH:MM:SS."""
        secs = int(pygame.time.get_ticks() / 1000)
        hours = secs // 3600
        mins = (secs // 60) % 60
        secs = secs % 60
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    
    def update(self, detection: Optional[Detection], connected: bool):
        """Update display state with new detection."""
        self.connected = connected
        
        if detection and detection != self.current_detection:
            if detection.is_active:
                self.current_detection = detection
                self.alert_start_time = time.time()
                self.total_detections += 1
                self.detection_history.append(detection)
        
        # Clear old detection
        if self.current_detection and not self.current_detection.is_active:
            self.current_detection = None
    
    def draw(self):
        """Draw the complete display."""
        self.screen.fill(COLOR_BG)
        self.draw_header()
        
        if self.current_detection and self.current_detection.is_active:
            self.draw_alert_screen()
        else:
            self.draw_idle_screen()
        
        pygame.display.flip()

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Flock Squawk Display Client")
    parser.add_argument("--ports", "-p", nargs='+', default=["auto"],
                       help="Serial ports (default: auto-detect all)")
    parser.add_argument("--baud", "-b", type=int, default=115200,
                       help="Baud rate (default: 115200)")
    parser.add_argument("--fullscreen", "-f", action="store_true",
                       help="Run in fullscreen mode")
    parser.add_argument("--tiny", "-t", action="store_true",
                       help="Optimize layout for tiny screens (e.g. 128x64, 320x240)")
    parser.add_argument("--radar", "-r", action="store_true",
                       help="Enable radar animation (best for multi-device setups)")
    args = parser.parse_args()
    
    print("Flock Squawk Display Client")
    print("=" * 40)
    
    # Initialize serial connection
    detector = DetectorSerial(args.ports, args.baud)
    if not detector.connect():
        print("\nFailed to connect to detector.")
        print("Make sure the detector is connected via USB.")
        sys.exit(1)
    
    detector.start()
    
    # Initialize display
    display = FlockDisplay(fullscreen=args.fullscreen, radar_mode=args.radar)
    
    # Auto-detect tiny screens or use flag
    if args.tiny or display.width < 400:
        display.tiny_mode = True
        print(f"Tiny mode enabled (Resolution: {display.width}x{display.height})")
    
    clock = pygame.time.Clock()
    
    print("\nDisplay running. Press ESC or Q to quit.\n")
    
    running = True
    while running:
        # Handle events
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key in (pygame.K_ESCAPE, pygame.K_q):
                    running = False
        
        # Update and draw
        detection = detector.get_latest_detection()
        display.update(detection, detector.connected)
        display.draw()
        
        clock.tick(FPS)
    
    # Cleanup
    detector.stop()
    pygame.quit()
    print("\nDisplay closed.")

if __name__ == "__main__":
    main()
