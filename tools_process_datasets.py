import csv
import glob
import os
import json
import re

# Use paths relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(SCRIPT_DIR, "datasets")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "src", "detection_patterns.h")

wifi_ssid_patterns = set()
mac_prefixes = set()
device_name_patterns = set()

# Process Flock WiFi CSV
for filepath in glob.glob(os.path.join(DATASET_DIR, "Flock-*.csv")):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ssid' in row and row['ssid']:
                # Add generic pattern "Flock-" if not already there
                if row['ssid'].startswith("Flock-"):
                    wifi_ssid_patterns.add("Flock-")
                else:
                    wifi_ssid_patterns.add(row['ssid'])
            
            if 'netid' in row and row['netid']:
                mac = row['netid'].replace(":", "").lower()
                if len(mac) >= 6:
                    mac_prefixes.add(mac[:6]) # OUI (first 3 bytes)

# Process Penguin CSV
for filepath in glob.glob(os.path.join(dataset_dir, "Penguin-*.csv")):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ssid' in row and row['ssid']:
                # SSID column in this CSV seems to be device name for BLE
                name = row['ssid']
                # Extract pattern like "Penguin-"
                if name.startswith("Penguin-"):
                    device_name_patterns.add("Penguin")
                else:
                    device_name_patterns.add(name)
            
            if 'netid' in row and row['netid']:
                mac = row['netid'].replace(":", "").lower()
                if len(mac) >= 6:
                    mac_prefixes.add(mac[:6])

# Process FS Ext Battery CSV
for filepath in glob.glob(os.path.join(DATASET_DIR, "FS+Ext+Battery_*.csv")):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ssid' in row and row['ssid']:
                device_name_patterns.add(row['ssid'])
            
            if 'netid' in row and row['netid']:
                mac = row['netid'].replace(":", "").lower()
                if len(mac) >= 6:
                    mac_prefixes.add(mac[:6])

# Hardcoded additions from existing main.cpp to ensure we don't lose them
wifi_ssid_patterns.add("Flock")
wifi_ssid_patterns.add("FLOCK")
wifi_ssid_patterns.add("FS Ext Battery")
wifi_ssid_patterns.add("Penguin")
wifi_ssid_patterns.add("Pigvision")

device_name_patterns.add("FS Ext Battery")
device_name_patterns.add("Penguin")
device_name_patterns.add("Flock")
device_name_patterns.add("Pigvision")

# Filter MAC prefixes to ensure they are valid hex
valid_mac_prefixes = []
for p in mac_prefixes:
    if re.match(r'^[0-9a-f]{6}$', p):
        formatted = f"{p[0:2]}:{p[2:4]}:{p[4:6]}"
        valid_mac_prefixes.append(formatted)

# Sort for consistency
sorted_ssids = sorted(list(wifi_ssid_patterns))
sorted_macs = sorted(list(set(valid_mac_prefixes)))
sorted_names = sorted(list(device_name_patterns))

output_file = "/Volumes/1tb-sandisk/code-external/flock-you/src/detection_patterns.h"

with open(output_file, 'w') as f:
    f.write("#ifndef DETECTION_PATTERNS_H\n")
    f.write("#define DETECTION_PATTERNS_H\n\n")
    
    f.write("// GENERATED PATTERNS FROM DATASETS\n")
    f.write("// WiFi SSID patterns to detect (case-insensitive)\n")
    f.write("static const char* wifi_ssid_patterns[] = {\n")
    for s in sorted_ssids:
        f.write(f'    "{s}",\n')
    f.write("};\n\n")

    f.write("// Known Flock Safety MAC address prefixes (from real device databases)\n")
    f.write("static const char* mac_prefixes[] = {\n")
    for i, m in enumerate(sorted_macs):
        end = "," if i < len(sorted_macs) - 1 else ""
        f.write(f'    "{m}"{end}\n')
    f.write("};\n\n")

    f.write("// Device name patterns for BLE advertisement detection\n")
    f.write("static const char* device_name_patterns[] = {\n")
    for n in sorted_names:
        f.write(f'    "{n}",\n')
    f.write("};\n\n")
    
    f.write("#endif // DETECTION_PATTERNS_H\n")

print(f"Successfully generated {OUTPUT_FILE}")
