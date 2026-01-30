# Flock Squawk System Manual

This manual covers the installation, configuration, and usage of the Flock Squawk surveillance detection system. The system can be deployed in four different configurations depending on your hardware and requirements.

## 📋 Prerequisites

1.  **Hardware**:
    *   Seeed Xiao ESP32-C3 or ESP32-S3 (for all configs)
    *   Raspberry Pi (Config 3 & 4)
    *   SSD1306 I2C OLED Display (Config 2)
    *   USB Cables

2.  **Software**:
    *   Python 3.x
    *   PlatformIO (for flashing firmware)
    *   `make` (optional, for easier command execution)

3.  **Installation**:
    Run the following to install Python dependencies on the Raspberry Pi:
    ```bash
    make install-pi-deps
    ```

---

## 🛠 Configurations

### 1. Xiao w/ LED Alerting (Standalone)
*Minimalist setup. The device scans silently and blinks the LED when a threat is detected.*

*   **Hardware**: Xiao ESP32 (Standalone)
*   **Behavior**: 
    *   **Idle**: LED off (stealth)
    *   **Detection**: Rapid LED blinking
*   **Setup**:
    1.  Connect Xiao ESP32 to computer via USB.
    2.  Run:
        ```bash
        make upload-esp32
        ```

### 2. ESP32 w/ Tiny Screen (Standalone)
*Portable visual detector. Shows scanning status and specific detection details on a small attached screen.*

*   **Hardware**: ESP32/Xiao + SSD1306 OLED Display (I2C)
*   **Wiring**:
    *   SDA -> ESP32 SDA
    *   SCL -> ESP32 SCL
    *   VCC -> 3.3V
    *   GND -> GND
*   **Behavior**:
    *   **Idle**: Displays "SCANNING..."
    *   **Detection**: Shows Device Type, ID, and Signal Strength Bar.
*   **Setup**:
    1.  Connect device to computer via USB.
    2.  Run:
        ```bash
        make upload-standalone-display
        ```

### 3. Xiao + Raspberry Pi (GUI Mode)
*Rich visual interface. The Xiao acts as a sensor for the Raspberry Pi, which displays a graphical interface.*

*   **Hardware**: Xiao ESP32 connected to Raspberry Pi via USB.
*   **Behavior**:
    *   **Idle**: Simple scanner bar animation ("Knight Rider" style).
    *   **Detection**: Full-screen alert with RSSI strength meter, threat level, and device details.
*   **Setup**:
    1.  Flash the Xiao with the default firmware (see Config 1).
    2.  Connect Xiao to Raspberry Pi USB port.
    3.  On Raspberry Pi, run:
        ```bash
        make run-display
        ```

### 4. Dual Xiao + Raspberry Pi (Radar Mode)
*Advanced detection. Uses multiple sensors to increase detection probability and coverage.*

*   **Hardware**: Two (or more) Xiao ESP32s connected to Raspberry Pi via USB.
*   **Behavior**:
    *   **Idle**: Rotating Radar sweep animation.
    *   **Detection**: Aggregated alerts from all connected sensors.
*   **Setup**:
    1.  Flash both Xiao units with the default firmware (see Config 1).
    2.  Connect all Xiao units to Raspberry Pi USB ports.
    3.  On Raspberry Pi, run:
        ```bash
        make run-display-radar
        ```

---

## 📂 Dataset Management

The system generates detection patterns dynamically from the `/datasets` directory. Supported files include:
*   `raven_configurations.json`
*   `Penguin-*.csv`
*   `Flock-*.csv`
*   `FS+Ext+Battery_*.csv`

To update the detection logic with new data:
1.  Place new CSV/JSON files in the `datasets/` folder.
2.  Re-flash the firmware:
    ```bash
    make upload-esp32
    ```
    *(The build process automatically runs `tools_process_datasets.py` to regenerate `detection_patterns.h` before compiling.)*

---

## ❓ Troubleshooting

*   **"Failed to connect to detector"**:
    *   Ensure the Xiao is plugged in.
    *   Check if the user has permission to access serial ports (`sudo usermod -a -G dialout $USER`).
*   **Display not showing on Config 2**:
    *   Verify I2C wiring (SDA/SCL).
    *   Ensure the correct I2C address (default `0x3C`) in `src/main.cpp`.
*   **No Detections**:
    *   Verify you are in range of a target device.
    *   Check `monitor-esp32` output to see raw logs:
        ```bash
        make monitor-esp32
        ```
