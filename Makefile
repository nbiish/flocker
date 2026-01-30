# Makefile for Flock Squawk System

PYTHON := python3
PIO := pio

.PHONY: all help install-pi-deps process-datasets build-esp32 upload-esp32 monitor-esp32 run-display clean

help:
	@echo "Flock Squawk System Management"
	@echo "=============================="
	@echo "Available commands:"
	@echo "  make install-pi-deps   - Install Python dependencies for Raspberry Pi"
	@echo "  make process-datasets  - Generate detection patterns from datasets"
	@echo "  make build-esp32       - Build ESP32 firmware"
	@echo "  make upload-esp32      - Upload firmware to ESP32"
	@echo "  make monitor-esp32     - Monitor ESP32 serial output"
	@echo "  make run-display       - Run the Raspberry Pi display client (Tiny mode)"
	@echo "  make run-display-radar - Run the Raspberry Pi display client (Radar mode)"
	@echo "  make clean             - Clean build artifacts"

install-pi-deps:
	@echo "Installing Raspberry Pi dependencies..."
	$(PYTHON) -m pip install -r display-clients/raspberry-pi/requirements.txt

process-datasets:
	@echo "Processing datasets..."
	$(PYTHON) tools_process_datasets.py

build-esp32: process-datasets
	@echo "Building ESP32 firmware (Default/LED Alert)..."
	$(PIO) run -e xiao_esp32c3

build-standalone-display: process-datasets
	@echo "Building ESP32 firmware (OLED Display)..."
	$(PIO) run -e esp32_oled

upload-esp32: process-datasets
	@echo "Uploading firmware to Xiao ESP32 (Default)..."
	$(PIO) run -e xiao_esp32c3 --target upload

upload-standalone-display: process-datasets
	@echo "Uploading firmware to ESP32 (OLED Display)..."
	$(PIO) run -e esp32_oled --target upload

monitor-esp32:
	@echo "Monitoring ESP32..."
	$(PIO) device monitor

run-display:
	@echo "Starting Display Client (Tiny Mode - Single/Multi Sensor)..."
	$(PYTHON) display-clients/raspberry-pi/flock_display.py --tiny

run-display-radar:
	@echo "Starting Display Client (Radar Mode - Multi Sensor)..."
	$(PYTHON) display-clients/raspberry-pi/flock_display.py --tiny --radar

clean:
	@echo "Cleaning build artifacts..."
	$(PIO) run --target clean
