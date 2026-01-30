# PRD.md - DEFLOCK ESP32S3-Heltec-V4 Scanner

```toon
product:
  name: DEFLOCK Standalone Scanner
  ver: 3.2.0-secure
  description: WiFi+BLE surveillance detection device for Heltec ESP32-S3 V4 with OLED

# Hardware
hardware{platform,display,button,antenna}:
  Heltec ESP32-S3 WiFi LoRa 32 V4,128x64 SSD1306 OLED,GPIO0 PRG button,2.4GHz shared WiFi/BLE

# Detection Targets
targets[4]{id,name,protocol,patterns}:
  1,Flock Safety ALPR,WiFi+BLE,SSID:FLOCK*/Flock*/flock* MAC:B0:B2:1C|34:94:54|E8:6B:EA
  2,FS Ext Battery,BLE,Name:"FS Ext Battery"
  3,Raven Gunshot,BLE,ServiceUUID:bd4ac610-*
  4,Penguin Devices,WiFi,SSID:Penguin*

# Scan Profiles
profiles[3]{id,name,shortName,wifiHopMs,bleScanDur,bleScanInt,bleWindow,load}:
  1,HIGHWAY,HWY+,50ms,1s,300ms,50ms,HIGH
  2,URBAN,URB~,100ms,1s,500ms,50ms,MED
  3,SWEEP,SWP-,300ms,3s,1000ms,30ms,LOW

# Features
features[12]{id,name,pri,status,description}:
  1,WiFi Promiscuous Scan,P0,Done,Probe requests + beacons SSID/MAC matching
  2,BLE Active Scan,P0,Done,Device names + MAC prefixes + Raven service UUIDs
  3,OLED Display,P0,Done,128x64 status/alert with radar animation
  4,Scan Profile Cycling,P1,Done,1-click cycles HIGHWAY→URBAN→SWEEP with timing display
  5,Stealth Mode,P1,Done,2-10s hold toggles display/LED off (scanning continues)
  6,Stats Reset,P1,Done,10s+ hold resets all detection counters
  7,Profile Info Display,P1,Done,Persistent profile settings screen until dismissed
  8,5-Second Click Queue,P1,Done,Waits 5s after clicks before executing (scan-friendly)
  9,Hardware Watchdog,P0,Done,30s WDT auto-reboot on hang (JPL Rule compliance)
  10,Persistent Stats,P2,Done,NVS storage for detection counts across reboots
  11,Assurity Meter,P2,Done,FLOCK-ER confidence % based on signal strength
  12,Alert Screen,P0,Done,Flashing display with detection details and method

# Button Controls
controls[4]{action,trigger,display,result}:
  1-Click,<2s release + 5s wait,CLK:X(Y),Cycle scan profile
  2-Click,<2s each + 5s wait,CLK:2(Y),Reserved
  3-Click,<2s each + 5s wait,CLK:3(Y),Reserved
  Hold 2-10s,Release after HOLD:2-9,HOLD:X,Toggle stealth mode
  Hold 10s+,Wait for HOLD:10,HOLD:10,Reset all stats

# Security (AGENTS_SECURE.md Compliance)
security[6]{id,rule,implementation}:
  1,JPL Bounded Loops,MAX_PATTERN_ITERATIONS=64 MAX_SERVICE_UUID_ITERATIONS=16
  2,JPL No Dynamic Alloc,All buffers static after init
  3,JPL No Recursion,All functions iterative
  4,Input Validation,RSSI bounds [-127 to 0] channel bounds [1-14]
  5,Hardware Watchdog,esp_task_wdt 30s timeout
  6,Minimal Scope,Variables scoped to smallest block

# Display Layout (Idle Screen)
display{line,content}:
  L1,DEFLOCK v3.2.0-secure
  L2,SCANNING... [HOLD:X|CLK:X(Y)]
  L3,FLOCK-ER:[NONE|LOW|MED|HIGH|CRITICAL] [bar] %
  L4,SIG:XXdBm
  L5,F:X R:X W:X B:X
  L6,UP:HH:MM [HWY+|URB~|SWP-]

# Dependencies
libs[4]{name,version,purpose}:
  NimBLE-Arduino,1.4.3,BLE scanning
  Adafruit SSD1306,latest,OLED driver
  Adafruit GFX,latest,Graphics primitives
  ArduinoJson,6.21,JSON output formatting

# Build
build{env,board,framework}:
  heltec-esp32s3-v4,heltec_wifi_lora_32_V3,Arduino
```
