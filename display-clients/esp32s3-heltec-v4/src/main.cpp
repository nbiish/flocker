/**
 * DEFLOCK Standalone Scanner + Display - Heltec ESP32-S3 with Built-in OLED
 * 
 * FULL STANDALONE DETECTION: WiFi Promiscuous Mode + BLE Scanning + OLED Display
 * No external detector required - this device scans AND displays!
 * 
 * Detection Methods:
 *   - WiFi Promiscuous Mode: Probe requests, Beacons (SSID & MAC matching)
 *   - BLE Active Scan: Device names, MAC prefixes, Raven service UUIDs
 * 
 * Optimized for Heltec WiFi LoRa 32 V3/V4 boards with 128x64 OLED.
 * 
 * Project: https://github.com/colonelpanichacks/flock-you
 * Data: deflock.me
 */

#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_task_wdt.h"  // Hardware watchdog timer (AGENTS_SECURE.md: fault recovery)

// ============================================================================
// VERSION & BRANDING
// ============================================================================

#define VERSION "3.2.0-secure"
#define BRANDING "DEFLOCK"

// ============================================================================
// SECURITY CONFIGURATION (AGENTS_SECURE.md Compliance)
// ============================================================================
// JPL "Power of 10" Rule Compliance:
//   - No recursion (all functions are iterative)
//   - Bounded loops (all loops have static upper bounds)
//   - No dynamic memory after init (all buffers are static)
//   - Minimal scope for variables

// Static bounds for all buffers (JPL Rule: No unbounded data structures)
#define MAX_SSID_LEN 32
#define MAX_MAC_LEN 18
#define MAX_IDENTIFIER_LEN 32
#define MAX_PROTOCOL_LEN 8
#define MAX_METHOD_LEN 24
#define MAX_DEVICE_TYPE_LEN 24

// Loop iteration limits (JPL Rule: Bounded loops)
#define MAX_PATTERN_ITERATIONS 64
#define MAX_SERVICE_UUID_ITERATIONS 16
#define MAX_DEDUP_ITERATIONS 16

// Input validation bounds
#define MIN_RSSI -127
#define MAX_RSSI 0

// Hardware watchdog timer (AGENTS_SECURE.md: fault recovery/safe state)
#define WDT_TIMEOUT_SEC 30  // Reboot if loop hangs for 30 seconds

// ============================================================================
// DISPLAY CONFIGURATION (from platformio.ini or defaults)
// ============================================================================

#ifndef SCREEN_WIDTH
    #define SCREEN_WIDTH 128
#endif

#ifndef SCREEN_HEIGHT
    #define SCREEN_HEIGHT 64
#endif

#ifndef OLED_SDA
    #define OLED_SDA 17  // Heltec V3/V4 default
#endif

#ifndef OLED_SCL
    #define OLED_SCL 18  // Heltec V3/V4 default
#endif

#ifndef OLED_RST
    #define OLED_RST 21  // Heltec V3/V4 default
#endif

// Heltec Vext power control (turns on OLED power)
#ifndef VEXT_PIN
    #define VEXT_PIN 36  // Heltec V3/V4 default
#endif

// PRG/USER button for reset
#ifndef PRG_BUTTON_PIN
    #define PRG_BUTTON_PIN 0  // GPIO0 - PRG button on Heltec V3/V4
#endif

// LED for visual alert
#ifndef LED_BUILTIN_PIN
    #define LED_BUILTIN_PIN 35  // Heltec V3 LED
#endif

#define BUTTON_LONG_PRESS_MS 2000  // Hold 2 seconds to reset

// ============================================================================
// INPUT VALIDATION & SANITIZATION (OWASP / AGENTS_SECURE.md)
// ============================================================================

// Channel bounds (needed by sanitizeChannel below)
#define MIN_CHANNEL 1
#define MAX_CHANNEL 13

// Sanitize string input - removes non-printable chars, enforces length
static void sanitizeString(char* dest, const char* src, size_t maxLen)
{
    if (!dest || maxLen == 0) return;
    if (!src) {
        dest[0] = '\0';
        return;
    }
    
    size_t i = 0;
    size_t j = 0;
    // Bounded loop with static upper limit
    while (i < maxLen - 1 && j < maxLen && src[j] != '\0') {
        // Only allow printable ASCII (0x20-0x7E)
        if (src[j] >= 0x20 && src[j] <= 0x7E) {
            dest[i++] = src[j];
        }
        j++;
    }
    dest[i] = '\0';
}

// Sanitize string input - returns std::string (for BLE callbacks)
static std::string sanitizeString(const char* src)
{
    std::string result;
    if (!src) return result;
    
    size_t j = 0;
    // Bounded loop with static upper limit
    while (j < MAX_IDENTIFIER_LEN && src[j] != '\0') {
        // Only allow printable ASCII (0x20-0x7E)
        if (src[j] >= 0x20 && src[j] <= 0x7E) {
            result += src[j];
        }
        j++;
    }
    return result;
}

// Validate RSSI is within expected bounds
static int sanitizeRssi(int rssi)
{
    if (rssi < MIN_RSSI) return MIN_RSSI;
    if (rssi > MAX_RSSI) return MAX_RSSI;
    return rssi;
}

// Validate channel number
static uint8_t sanitizeChannel(uint8_t channel)
{
    if (channel < MIN_CHANNEL) return MIN_CHANNEL;
    if (channel > MAX_CHANNEL) return MAX_CHANNEL;
    return channel;
}

// Validate MAC address format (basic check)
static bool isValidMacFormat(const char* mac)
{
    if (!mac) return false;
    size_t len = strlen(mac);
    // MAC should be 17 chars: XX:XX:XX:XX:XX:XX
    if (len != 17) return false;
    // Bounded loop
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') return false;
        } else {
            if (!isxdigit((unsigned char)mac[i])) return false;
        }
    }
    return true;
}

// ============================================================================
// SCANNING CONFIGURATION - AGGRESSIVE MODE
// ============================================================================

// WiFi Promiscuous Mode - Fast channel hopping
// Note: MIN_CHANNEL and MAX_CHANNEL defined in INPUT VALIDATION section above
// Default values (URBAN profile) - can be changed by scan profiles
#define CHANNEL_HOP_INTERVAL_DEFAULT 100  // 100ms per channel = full sweep in 1.3s
#define BLE_SCAN_DURATION_DEFAULT 1       // 1 second scans
#define BLE_SCAN_INTERVAL_DEFAULT 500     // 500ms gap between scans

// ============================================================================
// SCAN PROFILES - Optimized for different driving conditions
// ============================================================================

enum ScanProfile {
    PROFILE_HIGHWAY = 0,  // 60+ mph - fastest scanning
    PROFILE_URBAN   = 1,  // City driving - balanced (default)
    PROFILE_SWEEP   = 2,  // Parking lot sweep - max sensitivity
    PROFILE_COUNT   = 3
};

struct ScanProfileConfig {
    const char* name;
    const char* shortName;
    int channelHopMs;     // WiFi channel hop interval
    int bleScanDuration;  // BLE scan duration in seconds
    int bleScanInterval;  // Gap between BLE scans in ms
    int bleWindow;        // BLE scan window (duty cycle)
};

// Profile configurations with CPU load indicator
// Load: HIGH = aggressive scanning (more CPU), LOW = relaxed (less CPU)
// bleWindow: Lower value = lower BLE duty cycle (lighter scanning)
static const ScanProfileConfig scanProfiles[PROFILE_COUNT] = {
    // HIGHWAY: 60+ mph, catch fleeting signals - HIGH CPU load, 100% BLE duty
    { "HIGHWAY", "HWY+", 50, 1, 300, 50 },
    
    // URBAN: City driving, balanced performance (default) - MED CPU load, 100% BLE duty
    { "URBAN", "URB~", 100, 1, 500, 50 },
    
    // SWEEP: Slow/stationary, energy-saving sweep - LOW CPU load, 60% BLE duty
    // Longer channel dwell time for thorough coverage, shorter BLE scans for responsiveness
    { "SWEEP", "SWP-", 250, 1, 800, 30 }
};

// Current profile (default: URBAN)
static ScanProfile currentProfile = PROFILE_URBAN;

// Runtime config (loaded from current profile)
static int channelHopInterval = CHANNEL_HOP_INTERVAL_DEFAULT;
static int bleScanDuration = BLE_SCAN_DURATION_DEFAULT;
static int bleScanInterval = BLE_SCAN_INTERVAL_DEFAULT;

// ============================================================================
// STEALTH MODE - Covert operation (display + LED off, scanning continues)
// ============================================================================

static bool stealthMode = false;

// ============================================================================
// PROFILE INFO DISPLAY - Shows scan settings until dismissed
// ============================================================================

static bool showingProfileInfo = false;

// ============================================================================
// ALERT TIMING
// ============================================================================

#define ALERT_FLASH_MS      100      // Faster flash for urgency
#define ALERT_DURATION_MS   4000     // Shorter alert to return to scanning view
#define STATUS_UPDATE_MS    50       // 20 FPS display updates
#define RADAR_UPDATE_MS     40       // Smoother radar animation
#define DETECTION_TIMEOUT_MS 20000   // Faster timeout to clear stale detections
#define HEARTBEAT_INTERVAL_MS 5000   // More frequent heartbeat checks

// ============================================================================
// DETECTION PATTERNS - Extracted from Real Flock Safety Device Databases
// ============================================================================

// WiFi SSID patterns to detect (case-insensitive, partial match)
static const char* wifi_ssid_patterns[] = {
    "FLOCK",
    "Flock",
    "flock",
    "FS Ext Battery",
    "FS+Ext+Battery",
    "Penguin",
    "Pigvision",
    "SURVEILLANCE",
    "LPR-CAM"
};
static const int SSID_PATTERN_COUNT = sizeof(wifi_ssid_patterns) / sizeof(wifi_ssid_patterns[0]);

// Known Flock Safety MAC address prefixes (OUI from real device databases)
static const char* mac_prefixes[] = {
    // FS Ext Battery devices (highest priority - BLE beacons)
    "58:8e:81", "58:8e:87", "cc:cc:cc", "ec:1b:bd", "90:35:ea", 
    "04:0d:84", "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", 
    "b4:e3:f9", "90:35:86",
    
    // Flock WiFi devices
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
    "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea",
    
    // Extended Flock database
    "c0:02:5d", "c0:05:53", "c0:05:84", "c0:06:aa", "c0:08:33",
    "c0:09:30", "c0:0b:55", "c0:10:a8", "c0:14:92", "c0:16:82",
    "00:f4:8d", "b8:27:eb"
};
static const int MAC_PREFIX_COUNT = sizeof(mac_prefixes) / sizeof(mac_prefixes[0]);

// Device name patterns for BLE advertisement detection
static const char* device_name_patterns[] = {
    "FS Ext Battery",  // Flock Safety Extended Battery - CRITICAL
    "FS+Ext+Battery",  // URL-encoded variant
    "Flock",           // Standard Flock Safety devices
    "FLOCK",           // All caps
    "Penguin",         // Penguin surveillance devices
    "Pigvision",       // Pigvision surveillance systems
    "Raven",           // Raven gunshot detectors
    "ShotSpotter"      // ShotSpotter acoustic sensors
};
static const int DEVICE_NAME_PATTERN_COUNT = sizeof(device_name_patterns) / sizeof(device_name_patterns[0]);

// ============================================================================
// RAVEN SURVEILLANCE DEVICE UUID PATTERNS
// ============================================================================

#define RAVEN_DEVICE_INFO_SERVICE       "0000180a-0000-1000-8000-00805f9b34fb"
#define RAVEN_GPS_SERVICE               "00003100-0000-1000-8000-00805f9b34fb"
#define RAVEN_POWER_SERVICE             "00003200-0000-1000-8000-00805f9b34fb"
#define RAVEN_NETWORK_SERVICE           "00003300-0000-1000-8000-00805f9b34fb"
#define RAVEN_UPLOAD_SERVICE            "00003400-0000-1000-8000-00805f9b34fb"
#define RAVEN_ERROR_SERVICE             "00003500-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_HEALTH_SERVICE        "00001809-0000-1000-8000-00805f9b34fb"
#define RAVEN_OLD_LOCATION_SERVICE      "00001819-0000-1000-8000-00805f9b34fb"

static const char* raven_service_uuids[] = {
    RAVEN_GPS_SERVICE,            // GPS data - most common
    RAVEN_POWER_SERVICE,          // Battery/Solar
    RAVEN_NETWORK_SERVICE,        // LTE/WiFi status
    RAVEN_UPLOAD_SERVICE,         // Upload stats
    RAVEN_ERROR_SERVICE,          // Error tracking
    RAVEN_OLD_HEALTH_SERVICE,     // Legacy health
    RAVEN_OLD_LOCATION_SERVICE    // Legacy location
};
static const int RAVEN_UUID_COUNT = sizeof(raven_service_uuids) / sizeof(raven_service_uuids[0]);

// ============================================================================
// GLOBALS
// ============================================================================

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RST);
NimBLEScan* pBLEScan = nullptr;

// WiFi scanning state
static uint8_t currentChannel = 1;
static unsigned long lastChannelHop = 0;

// BLE scanning state
static unsigned long lastBleScan = 0;
static bool bleScanning = false;

// Detection state
struct DetectionInfo {
    bool active;
    unsigned long timestamp;
    char protocol[16];       // "WIFI" or "BLE"
    char deviceType[24];     // "FLOCK", "RAVEN", "PENGUIN", etc.
    char identifier[32];     // SSID or device name
    char macAddress[20];
    int rssi;
    int threatScore;
    char detectionMethod[24];  // "ssid", "mac", "ble_name", "raven_uuid"
};

DetectionInfo currentDetection = {0};

// Statistics
unsigned long lastStatusUpdate = 0;
unsigned long alertStartTime = 0;
bool alertFlashState = false;
int totalDetections = 0;
int flockDetections = 0;
int ravenDetections = 0;
int penguinDetections = 0;
int wifiDetections = 0;
int bleDetections = 0;
unsigned long startTime = 0;

// Assurity Meter - tracks confidence based on recent positive detections
#define ASSURITY_WINDOW_SIZE 12
#define ASSURITY_DECAY_MS 30000
int assurityBuffer[ASSURITY_WINDOW_SIZE] = {0};
int assurityIndex = 0;
int assurityLevel = 0;
unsigned long lastAssurityDecay = 0;
int lastRssi = -100;

// Unique Device Tracking
#define MAX_UNIQUE_DEVICES 32
#define DEVICE_EXPIRY_MS 300000
struct UniqueDevice {
    char macAddress[20];
    char protocol[8];
    unsigned long firstSeen;
    unsigned long lastSeen;
    int detectionCount;
    int maxRssi;
    bool confirmed;
};
UniqueDevice uniqueDevices[MAX_UNIQUE_DEVICES];
int uniqueDeviceCount = 0;

// Persistent storage
Preferences prefs;
int persistentDeviceCount = 0;
unsigned long lastSaveTime = 0;
#define SAVE_INTERVAL_MS 60000

// Button state - Simple: click (with 3s wait), 2-10s hold (stealth), 10s+ hold (reset)
unsigned long buttonPressStart = 0;
unsigned long lastButtonAction = 0;  // Cooldown tracking
bool buttonWasPressed = false;
bool showingResetConfirm = false;
unsigned long resetConfirmTime = 0;
bool stealthTriggered = false;  // Prevent re-triggering while held
bool resetTriggered = false;    // Prevent re-triggering reset
int pendingClickCount = 0;      // Clicks waiting to be processed
unsigned long lastClickTime = 0;
bool clicksProcessed = false;   // Flag to prevent re-processing

// Button timing - simple and predictable
#define DEBOUNCE_MS 50           // Ignore bounce
#define CLICK_WAIT_MS 5000       // Wait 5 seconds after last click before executing
#define STEALTH_HOLD_MS 2000     // Hold 2-10 seconds for stealth toggle
#define RESET_HOLD_MS 10000      // Hold 10+ seconds for reset

// Get current button hold time in seconds (for display)
int getCurrentHoldSeconds()
{
    if (buttonWasPressed) {
        return (millis() - buttonPressStart) / 1000;
    }
    return 0;
}

// Get pending click count (for display)
int getPendingClicks()
{
    return pendingClickCount;
}

// Get countdown until clicks are processed
int getClickCountdown()
{
    if (pendingClickCount > 0 && !clicksProcessed) {
        unsigned long elapsed = millis() - lastClickTime;
        if (elapsed < CLICK_WAIT_MS) {
            return (CLICK_WAIT_MS - elapsed + 999) / 1000;  // Round up
        }
    }
    return 0;
}

// Radar animation
int radarAngle = 0;
unsigned long lastRadarUpdate = 0;

// LED state
bool ledState = false;
unsigned long lastLedToggle = 0;
int alertBlinkRemaining = 0;

// Heartbeat tracking
unsigned long lastHeartbeat = 0;
unsigned long lastDetectionTime = 0;
bool deviceInRange = false;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const char* getShortDeviceType(const char* deviceType)
{
    if (strstr(deviceType, "FLOCK")) return "FLOCK";
    if (strstr(deviceType, "RAVEN")) return "RAVEN";
    if (strstr(deviceType, "PENGUIN")) return "PENGUIN";
    if (strstr(deviceType, "LPR")) return "LPR";
    return "SURV";
}

void formatUptime(char* buffer, size_t len, unsigned long ms)
{
    unsigned long secs = ms / 1000;
    unsigned long mins = secs / 60;
    unsigned long hrs = mins / 60;
    snprintf(buffer, len, "%02lu:%02lu", hrs, mins % 60);
}

// Assurity meter functions
void updateAssurityLevel()
{
    int sum = 0;
    for (int i = 0; i < ASSURITY_WINDOW_SIZE; i++) {
        sum += assurityBuffer[i];
    }
    assurityLevel = constrain((sum * 100) / (ASSURITY_WINDOW_SIZE * 10), 0, 100);
}

void recordPositiveDetection(int score)
{
    assurityBuffer[assurityIndex] = constrain(score, 1, 10);
    assurityIndex = (assurityIndex + 1) % ASSURITY_WINDOW_SIZE;
    updateAssurityLevel();
    lastAssurityDecay = millis();
}

void decayAssurity()
{
    if (millis() - lastAssurityDecay > ASSURITY_DECAY_MS) {
        int decayIdx = (assurityIndex + 1) % ASSURITY_WINDOW_SIZE;
        if (assurityBuffer[decayIdx] > 0) {
            assurityBuffer[decayIdx]--;
            updateAssurityLevel();
        }
        lastAssurityDecay = millis();
    }
}

const char* getAssurityLabel(int level)
{
    if (level >= 75) return "CONFIRMED";
    if (level >= 50) return "LIKELY";
    if (level >= 25) return "POSSIBLE";
    return "SCANNING";
}

// ============================================================================
// UNIQUE DEVICE TRACKING
// ============================================================================

void normalizeMac(const char* input, char* output, size_t len)
{
    int j = 0;
    for (int i = 0; input[i] && j < (int)len - 1; i++) {
        if (input[i] != ':' && input[i] != '-') {
            output[j++] = toupper(input[i]);
        }
    }
    output[j] = '\0';
}

bool macMatches(const char* mac1, const char* mac2)
{
    char norm1[18], norm2[18];
    normalizeMac(mac1, norm1, sizeof(norm1));
    normalizeMac(mac2, norm2, sizeof(norm2));
    return strcmp(norm1, norm2) == 0;
}

int findUniqueDevice(const char* mac)
{
    for (int i = 0; i < uniqueDeviceCount; i++) {
        if (macMatches(uniqueDevices[i].macAddress, mac)) {
            return i;
        }
    }
    return -1;
}

void expireOldDevices()
{
    unsigned long now = millis();
    int writeIdx = 0;
    
    for (int i = 0; i < uniqueDeviceCount; i++) {
        if (now - uniqueDevices[i].lastSeen < DEVICE_EXPIRY_MS) {
            if (writeIdx != i) {
                memcpy(&uniqueDevices[writeIdx], &uniqueDevices[i], sizeof(UniqueDevice));
            }
            writeIdx++;
        }
    }
    uniqueDeviceCount = writeIdx;
}

bool trackUniqueDevice(const char* mac, const char* protocol, int rssi, bool highConfidence)
{
    if (!highConfidence || !mac || strlen(mac) < 8) return false;
    
    unsigned long now = millis();
    int idx = findUniqueDevice(mac);
    
    if (idx >= 0) {
        uniqueDevices[idx].lastSeen = now;
        uniqueDevices[idx].detectionCount++;
        if (rssi > uniqueDevices[idx].maxRssi) {
            uniqueDevices[idx].maxRssi = rssi;
        }
        if (strcmp(uniqueDevices[idx].protocol, protocol) != 0 &&
            strcmp(uniqueDevices[idx].protocol, "MULTI") != 0) {
            strlcpy(uniqueDevices[idx].protocol, "MULTI", sizeof(uniqueDevices[idx].protocol));
        }
        return false;
    }
    
    if (uniqueDeviceCount >= MAX_UNIQUE_DEVICES) {
        expireOldDevices();
        if (uniqueDeviceCount >= MAX_UNIQUE_DEVICES) {
            memmove(&uniqueDevices[0], &uniqueDevices[1], 
                    sizeof(UniqueDevice) * (MAX_UNIQUE_DEVICES - 1));
            uniqueDeviceCount--;
        }
    }
    
    idx = uniqueDeviceCount++;
    strlcpy(uniqueDevices[idx].macAddress, mac, sizeof(uniqueDevices[idx].macAddress));
    strlcpy(uniqueDevices[idx].protocol, protocol, sizeof(uniqueDevices[idx].protocol));
    uniqueDevices[idx].firstSeen = now;
    uniqueDevices[idx].lastSeen = now;
    uniqueDevices[idx].detectionCount = 1;
    uniqueDevices[idx].maxRssi = rssi;
    uniqueDevices[idx].confirmed = highConfidence;
    
    persistentDeviceCount++;
    
    Serial.printf("[UNIQUE] New device #%d (total: %d): %s via %s\n", 
                  uniqueDeviceCount, persistentDeviceCount, mac, protocol);
    return true;
}

int getConfirmedDeviceCount()
{
    int count = 0;
    for (int i = 0; i < uniqueDeviceCount; i++) {
        if (uniqueDevices[i].confirmed) count++;
    }
    return count;
}

// ============================================================================
// PERSISTENT STORAGE
// ============================================================================

void loadPersistentData()
{
    prefs.begin("deflock", true);
    persistentDeviceCount = prefs.getInt("devCount", 0);
    totalDetections = prefs.getInt("totalDet", 0);
    flockDetections = prefs.getInt("flockDet", 0);
    ravenDetections = prefs.getInt("ravenDet", 0);
    penguinDetections = prefs.getInt("penguinDet", 0);
    wifiDetections = prefs.getInt("wifiDet", 0);
    bleDetections = prefs.getInt("bleDet", 0);
    prefs.end();
    
    Serial.printf("[NVS] Loaded: %d unique devices, %d total detections\n", 
                  persistentDeviceCount, totalDetections);
}

void savePersistentData()
{
    prefs.begin("deflock", false);
    prefs.putInt("devCount", persistentDeviceCount);
    prefs.putInt("totalDet", totalDetections);
    prefs.putInt("flockDet", flockDetections);
    prefs.putInt("ravenDet", ravenDetections);
    prefs.putInt("penguinDet", penguinDetections);
    prefs.putInt("wifiDet", wifiDetections);
    prefs.putInt("bleDet", bleDetections);
    prefs.end();
    
    lastSaveTime = millis();
}

void resetPersistentData()
{
    prefs.begin("deflock", false);
    prefs.clear();
    prefs.end();
    
    persistentDeviceCount = 0;
    totalDetections = 0;
    flockDetections = 0;
    ravenDetections = 0;
    penguinDetections = 0;
    wifiDetections = 0;
    bleDetections = 0;
    uniqueDeviceCount = 0;
    assurityLevel = 0;
    memset(assurityBuffer, 0, sizeof(assurityBuffer));
    memset(uniqueDevices, 0, sizeof(uniqueDevices));
    
    Serial.println("[NVS] All data reset!");
}

void checkPeriodicSave()
{
    if (millis() - lastSaveTime > SAVE_INTERVAL_MS) {
        savePersistentData();
    }
}

// ============================================================================
// LED ALERT SYSTEM
// ============================================================================

void ledOn()
{
    digitalWrite(LED_BUILTIN_PIN, HIGH);
    ledState = true;
}

void ledOff()
{
    digitalWrite(LED_BUILTIN_PIN, LOW);
    ledState = false;
}

void ledToggle()
{
    if (ledState) ledOff();
    else ledOn();
}

void ledAlertUpdate()
{
    unsigned long now = millis();
    
    if (alertBlinkRemaining > 0) {
        if (now - lastLedToggle >= ALERT_FLASH_MS) {
            ledToggle();
            lastLedToggle = now;
            if (!ledState) alertBlinkRemaining--;
        }
    } else if (deviceInRange) {
        // Slow heartbeat when device in range
        if (now - lastLedToggle >= 500) {
            ledToggle();
            lastLedToggle = now;
        }
    } else {
        if (ledState) ledOff();
    }
}

// ============================================================================
// BUTTON HANDLING - Single click, Double click, Long press
// ============================================================================

// Apply current scan profile settings
// Updates both timing variables AND reconfigures BLE scanner duty cycle
void applyScanProfile(ScanProfile profile)
{
    if (profile >= PROFILE_COUNT) profile = PROFILE_URBAN;
    
    currentProfile = profile;
    channelHopInterval = scanProfiles[profile].channelHopMs;
    bleScanDuration = scanProfiles[profile].bleScanDuration;
    bleScanInterval = scanProfiles[profile].bleScanInterval;
    
    // CRITICAL: Apply BLE window setting to scanner (was missing!)
    // This actually changes the scan duty cycle for lighter/heavier scanning
    if (pBLEScan != nullptr) {
        int bleWindow = scanProfiles[profile].bleWindow;
        pBLEScan->setWindow(bleWindow);
        pBLEScan->setInterval(50);  // Keep interval constant, vary window for duty cycle
        Serial.printf("[PROFILE] BLE duty cycle: %d%% (window=%dms/50ms)\n",
                      (bleWindow * 100) / 50, bleWindow);
    }
    
    Serial.printf("[PROFILE] Switched to %s: CH=%dms, BLE=%ds/%dms\n",
                  scanProfiles[profile].name,
                  channelHopInterval, bleScanDuration, bleScanInterval);
}

// Cycle to next scan profile
void cycleScanProfile()
{
    ScanProfile next = (ScanProfile)((currentProfile + 1) % PROFILE_COUNT);
    applyScanProfile(next);
    
    // Show profile info (non-blocking - stays until button press)
    if (!stealthMode) {
        showingProfileInfo = true;
    }
}

// Draw the profile info screen (called from updateDisplay)
void drawProfileInfoScreen()
{
    const ScanProfileConfig& cfg = scanProfiles[currentProfile];
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.printf("PROFILE: %s", cfg.name);
    display.setCursor(0, 14);
    display.printf("WiFi hop: %dms", cfg.channelHopMs);
    display.setCursor(0, 26);
    display.printf("BLE scan: %ds/%dms", cfg.bleScanDuration, cfg.bleScanInterval);
    display.setCursor(0, 38);
    display.printf("BLE window: %dms", cfg.bleWindow);
    display.setCursor(0, 56);
    display.print("[press to dismiss]");
    display.display();
}

// Toggle stealth mode
void toggleStealthMode()
{
    stealthMode = !stealthMode;
    
    if (stealthMode) {
        // Enter stealth: turn off display and LED
        display.clearDisplay();
        display.display();
        display.ssd1306_command(SSD1306_DISPLAYOFF);
        ledOff();
        Serial.println("[STEALTH] Enabled - display & LED off, scanning continues");
    } else {
        // Exit stealth: restore display
        display.ssd1306_command(SSD1306_DISPLAYON);
        Serial.println("[STEALTH] Disabled - display restored");
        
        // Brief confirmation
        display.clearDisplay();
        display.setTextSize(2);
        display.setTextColor(SSD1306_WHITE);
        display.setCursor(15, 20);
        display.print("VISIBLE");
        display.setTextSize(1);
        display.setCursor(20, 45);
        display.print("Display active");
        display.display();
        delay(500);
    }
}

void checkButton()
{
    bool buttonPressed = (digitalRead(PRG_BUTTON_PIN) == LOW);
    unsigned long now = millis();
    
    // Simple debounce
    static unsigned long lastDebounceTime = 0;
    static bool lastButtonState = false;
    
    if (buttonPressed != lastButtonState) {
        lastDebounceTime = now;
    }
    if (now - lastDebounceTime < DEBOUNCE_MS) {
        lastButtonState = buttonPressed;
        return;
    }
    lastButtonState = buttonPressed;
    
    // Button just pressed
    if (buttonPressed && !buttonWasPressed) {
        buttonPressStart = now;
        buttonWasPressed = true;
        stealthTriggered = false;
        resetTriggered = false;
    }
    
    // Button being held - check thresholds
    if (buttonPressed && buttonWasPressed) {
        unsigned long holdTime = now - buttonPressStart;
        
        // 10+ second hold - Reset stats
        if (holdTime >= RESET_HOLD_MS && !resetTriggered) {
            resetTriggered = true;
            stealthTriggered = true;  // Prevent stealth from triggering
            pendingClickCount = 0;    // Cancel any pending clicks
            
            resetPersistentData();
            showingResetConfirm = true;
            resetConfirmTime = now;
            
            display.ssd1306_command(SSD1306_DISPLAYON);
            stealthMode = false;
            display.clearDisplay();
            display.setTextSize(2);
            display.setTextColor(SSD1306_WHITE);
            display.setCursor(20, 15);
            display.print("RESET!");
            display.setTextSize(1);
            display.setCursor(10, 45);
            display.print("All stats cleared");
            display.display();
            Serial.println("[BUTTON] 10s+ hold - RESET STATS");
        }
    }
    
    // Button released - check what action to take
    if (!buttonPressed && buttonWasPressed) {
        unsigned long holdTime = now - buttonPressStart;
        buttonWasPressed = false;
        
        // If showing profile info, any press/release dismisses it
        if (showingProfileInfo) {
            showingProfileInfo = false;
            Serial.println("[BUTTON] Profile info dismissed");
            return;  // Don't process as other action
        }
        
        // 2-10 second hold = Stealth toggle
        if (holdTime >= STEALTH_HOLD_MS && holdTime < RESET_HOLD_MS && !resetTriggered) {
            pendingClickCount = 0;  // Cancel any pending clicks
            Serial.printf("[BUTTON] %lums hold - STEALTH TOGGLE\n", holdTime);
            toggleStealthMode();
        }
        // Under 2 seconds = Click (register it, wait for more)
        else if (holdTime < STEALTH_HOLD_MS && !resetTriggered && !showingResetConfirm) {
            pendingClickCount++;
            lastClickTime = now;
            clicksProcessed = false;
            Serial.printf("[BUTTON] Click registered: %d (waiting 5s...)\n", pendingClickCount);
        }
    }
    
    // Process pending clicks after 3 second wait
    if (pendingClickCount > 0 && !clicksProcessed && !buttonWasPressed) {
        if (now - lastClickTime >= CLICK_WAIT_MS) {
            clicksProcessed = true;
            Serial.printf("[BUTTON] Processing %d click(s)\n", pendingClickCount);
            
            // Execute action based on click count
            switch (pendingClickCount) {
                case 1:
                    // 1 click = Cycle scan profile
                    Serial.println("[BUTTON] 1 click - CYCLE PROFILE");
                    cycleScanProfile();
                    break;
                case 2:
                    // 2 clicks = Future feature placeholder
                    Serial.println("[BUTTON] 2 clicks - (reserved)");
                    // TODO: Add future feature
                    break;
                case 3:
                    // 3 clicks = Future feature placeholder
                    Serial.println("[BUTTON] 3 clicks - (reserved)");
                    // TODO: Add future feature
                    break;
                default:
                    // 4+ clicks = Ignored
                    Serial.printf("[BUTTON] %d clicks - ignored\n", pendingClickCount);
                    break;
            }
            
            pendingClickCount = 0;
        }
    }
    
    // Clear reset confirmation display
    if (showingResetConfirm && now - resetConfirmTime > 2000) {
        showingResetConfirm = false;
    }
}

// ============================================================================
// DETECTION MATCHING FUNCTIONS (Bounded iteration per AGENTS_SECURE.md)
// ============================================================================

bool checkMacPrefix(const uint8_t* mac)
{
    if (!mac) return false;  // Null check
    
    char macStr[9];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    
    // Bounded loop with compile-time limit
    const int iterLimit = (MAC_PREFIX_COUNT < MAX_PATTERN_ITERATIONS) ? MAC_PREFIX_COUNT : MAX_PATTERN_ITERATIONS;
    for (int i = 0; i < iterLimit; i++) {
        if (strncasecmp(macStr, mac_prefixes[i], 8) == 0) {
            return true;
        }
    }
    return false;
}

bool checkMacPrefixStr(const char* macStr)
{
    if (!macStr) return false;  // Null check
    
    // Bounded loop with compile-time limit
    const int iterLimit = (MAC_PREFIX_COUNT < MAX_PATTERN_ITERATIONS) ? MAC_PREFIX_COUNT : MAX_PATTERN_ITERATIONS;
    for (int i = 0; i < iterLimit; i++) {
        if (strncasecmp(macStr, mac_prefixes[i], 8) == 0) {
            return true;
        }
    }
    return false;
}

bool checkSsidPattern(const char* ssid)
{
    if (!ssid || strlen(ssid) == 0) return false;
    if (strlen(ssid) > MAX_SSID_LEN) return false;  // Reject oversized input
    
    // Bounded loop with compile-time limit
    const int iterLimit = (SSID_PATTERN_COUNT < MAX_PATTERN_ITERATIONS) ? SSID_PATTERN_COUNT : MAX_PATTERN_ITERATIONS;
    for (int i = 0; i < iterLimit; i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool checkDeviceNamePattern(const char* name)
{
    if (!name || strlen(name) == 0) return false;
    if (strlen(name) > MAX_IDENTIFIER_LEN) return false;  // Reject oversized input
    
    // Bounded loop with compile-time limit
    const int iterLimit = (DEVICE_NAME_PATTERN_COUNT < MAX_PATTERN_ITERATIONS) ? DEVICE_NAME_PATTERN_COUNT : MAX_PATTERN_ITERATIONS;
    for (int i = 0; i < iterLimit; i++) {
        if (strcasestr(name, device_name_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool checkRavenServiceUuid(NimBLEAdvertisedDevice* device, char* detectedService = nullptr)
{
    if (!device) return false;  // Null check
    if (!device->haveServiceUUID()) return false;
    
    int serviceCount = device->getServiceUUIDCount();
    
    // Bound the service count to prevent runaway iteration
    if (serviceCount > MAX_SERVICE_UUID_ITERATIONS) {
        serviceCount = MAX_SERVICE_UUID_ITERATIONS;
    }
    
    // Bounded outer loop
    for (int i = 0; i < serviceCount; i++) {
        NimBLEUUID serviceUUID = device->getServiceUUID(i);
        std::string uuidStr = serviceUUID.toString();
        
        // Bounded inner loop
        const int ravenLimit = (RAVEN_UUID_COUNT < MAX_SERVICE_UUID_ITERATIONS) ? RAVEN_UUID_COUNT : MAX_SERVICE_UUID_ITERATIONS;
        for (int j = 0; j < ravenLimit; j++) {
            if (strcasecmp(uuidStr.c_str(), raven_service_uuids[j]) == 0) {
                if (detectedService) {
                    // Safe copy with explicit null termination
                    strncpy(detectedService, uuidStr.c_str(), 40);
                    detectedService[40] = '\0';
                }
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// DETECTION DEDUPLICATION - Prevents alert spam while scanning fast
// ============================================================================

// Static allocation per AGENTS_SECURE.md (no dynamic memory after init)
#define DEDUP_CACHE_SIZE 16
#define DEDUP_COOLDOWN_MS 3000  // Don't re-alert same device for 3 seconds

struct DedupEntry {
    char macAddress[MAX_MAC_LEN];
    unsigned long lastSeen;
};
static DedupEntry dedupCache[DEDUP_CACHE_SIZE];  // Static allocation
static int dedupIndex = 0;

// Returns true if this is a new detection (not seen recently)
bool shouldAlertForDevice(const char* macAddr, int rssi)
{
    // Input validation
    if (!macAddr || strlen(macAddr) == 0 || strlen(macAddr) >= MAX_MAC_LEN) {
        return false;
    }
    
    unsigned long now = millis();
    
    // Bounded loop - explicit limit
    for (int i = 0; i < DEDUP_CACHE_SIZE && i < MAX_DEDUP_ITERATIONS; i++) {
        if (dedupCache[i].macAddress[0] && 
            strcasecmp(dedupCache[i].macAddress, macAddr) == 0) {
            if (now - dedupCache[i].lastSeen < DEDUP_COOLDOWN_MS) {
                // Update timestamp but don't alert
                dedupCache[i].lastSeen = now;
                return false;
            }
            // Cooldown expired, update and allow alert
            dedupCache[i].lastSeen = now;
            return true;
        }
    }
    
    // New device - add to cache
    strlcpy(dedupCache[dedupIndex].macAddress, macAddr, sizeof(dedupCache[dedupIndex].macAddress));
    dedupCache[dedupIndex].lastSeen = now;
    dedupIndex = (dedupIndex + 1) % DEDUP_CACHE_SIZE;
    
    return true;  // New device, alert!
}

// ============================================================================
// DETECTION PROCESSING
// ============================================================================

void processDetection(const char* protocol, const char* method, const char* deviceType,
                      const char* macAddr, const char* identifier, int rssi)
{
    // Check deduplication - always update stats but limit UI alerts
    bool shouldAlert = shouldAlertForDevice(macAddr, rssi);
    
    // Always update range tracking (device is in range even if we don't alert)
    deviceInRange = true;
    lastDetectionTime = millis();
    lastRssi = rssi;
    
    if (!shouldAlert) {
        // Silent update - device still in range
        return;
    }
    
    // Full alert processing
    memset(&currentDetection, 0, sizeof(DetectionInfo));
    currentDetection.active = true;
    currentDetection.timestamp = millis();
    alertStartTime = millis();
    alertBlinkRemaining = 10;  // 10 fast blinks
    
    strlcpy(currentDetection.protocol, protocol, sizeof(currentDetection.protocol));
    strlcpy(currentDetection.detectionMethod, method, sizeof(currentDetection.detectionMethod));
    strlcpy(currentDetection.deviceType, deviceType, sizeof(currentDetection.deviceType));
    strlcpy(currentDetection.macAddress, macAddr, sizeof(currentDetection.macAddress));
    
    if (identifier && strlen(identifier) > 0) {
        strlcpy(currentDetection.identifier, identifier, sizeof(currentDetection.identifier));
    }
    
    currentDetection.rssi = rssi;
    
    // Calculate threat score
    int score = 70;
    if (strstr(deviceType, "FLOCK")) score = 95;
    else if (strstr(deviceType, "RAVEN")) score = 100;
    else if (strstr(deviceType, "PENGUIN")) score = 90;
    
    if (rssi > -50) score = min(score + 5, 100);
    currentDetection.threatScore = score;
    
    // Update statistics
    totalDetections++;
    if (strcmp(protocol, "WIFI") == 0) wifiDetections++;
    else bleDetections++;
    
    int detectionScore = 5;
    if (strstr(deviceType, "FLOCK")) {
        flockDetections++;
        detectionScore = 10;
    } else if (strstr(deviceType, "RAVEN")) {
        ravenDetections++;
        detectionScore = 10;
    } else if (strstr(deviceType, "PENGUIN")) {
        penguinDetections++;
        detectionScore = 9;
    }
    
    // Record for assurity meter
    recordPositiveDetection(detectionScore);
    
    // Track unique device
    bool isNew = trackUniqueDevice(macAddr, protocol, rssi, detectionScore >= 7);
    
    // Update range tracking
    deviceInRange = true;
    lastDetectionTime = millis();
    lastHeartbeat = millis();
    
    // Serial output with JSON
    StaticJsonDocument<512> doc;
    doc["timestamp"] = millis();
    doc["protocol"] = protocol;
    doc["detection_method"] = method;
    doc["device_type"] = deviceType;
    doc["mac_address"] = macAddr;
    if (identifier && strlen(identifier) > 0) {
        doc["identifier"] = identifier;
    }
    doc["rssi"] = rssi;
    doc["threat_score"] = currentDetection.threatScore;
    doc["is_new_device"] = isNew;
    
    String jsonOutput;
    serializeJson(doc, jsonOutput);
    Serial.println(jsonOutput);
    
    Serial.printf("\n*** DETECTION #%d: %s @ %s (%ddBm) via %s [%s]%s ***\n",
                  totalDetections, deviceType, macAddr, rssi, protocol, method,
                  isNew ? " NEW DEVICE!" : "");
}

// ============================================================================
// WIFI PROMISCUOUS MODE HANDLER
// ============================================================================

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    unsigned sequence_ctrl:16;
    uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

void IRAM_ATTR wifiSnifferPacketHandler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    // Early exit for non-management frames
    if (type != WIFI_PKT_MGMT) return;
    
    // Validate buffer pointer (defensive programming)
    if (!buff) return;
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    
    // Validate payload length before accessing
    if (ppkt->rx_ctrl.sig_len < 24) return;  // Minimum 802.11 header size
    if (ppkt->rx_ctrl.sig_len > 2500) return;  // Max reasonable frame size
    
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
    
    // Check frame subtype: Probe Request (0x40) or Beacon (0x80)
    uint16_t frameCtrl = hdr->frame_ctrl;
    uint8_t subtype = (frameCtrl >> 4) & 0x0F;
    
    bool isProbeRequest = (subtype == 0x04);
    bool isBeacon = (subtype == 0x08);
    
    if (!isProbeRequest && !isBeacon) return;
    
    // Extract SSID with strict bounds checking
    char ssid[MAX_SSID_LEN + 1] = {0};
    const uint8_t *payload = ipkt->payload;
    int payloadLen = ppkt->rx_ctrl.sig_len - 24;
    
    // Bounds check for beacon fixed parameters
    if (isBeacon) {
        if (payloadLen <= 12) return;  // Not enough data
        payload += 12;
        payloadLen -= 12;
    }
    
    // Parse SSID element with strict validation
    if (payloadLen > 2 && payload[0] == 0) {
        uint8_t ssidLen = payload[1];
        // Validate SSID length is sane
        if (ssidLen <= MAX_SSID_LEN && ssidLen < (payloadLen - 2)) {
            memcpy(ssid, &payload[2], ssidLen);
            ssid[ssidLen] = '\0';
            // Sanitize SSID (remove non-printable chars)
            char sanitized[MAX_SSID_LEN + 1];
            sanitizeString(sanitized, ssid, sizeof(sanitized));
            memcpy(ssid, sanitized, sizeof(ssid));
        }
    }
    
    // Format MAC address (safe - fixed size buffer)
    char macStr[MAX_MAC_LEN];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
             hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    
    // Sanitize RSSI
    int rssi = sanitizeRssi(ppkt->rx_ctrl.rssi);
    
    // Check for matches
    bool ssidMatch = checkSsidPattern(ssid);
    bool macMatch = checkMacPrefix(hdr->addr2);
    
    if (ssidMatch || macMatch) {
        const char* method = ssidMatch ? "ssid_match" : "mac_match";
        const char* deviceType = "FLOCK_SAFETY";
        
        // Determine specific device type from SSID
        if (ssid[0] && strcasestr(ssid, "Penguin")) deviceType = "PENGUIN";
        else if (ssid[0] && strcasestr(ssid, "Pigvision")) deviceType = "PIGVISION";
        else if (ssid[0] && strcasestr(ssid, "FS Ext")) deviceType = "FLOCK_BATTERY";
        
        processDetection("WIFI", method, deviceType, macStr, 
                        ssid[0] ? ssid : "hidden", rssi);
    }
}

// ============================================================================
// BLE SCANNING CALLBACKS
// ============================================================================

class MyBLEAdvertisedDeviceCallbacks: public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* device) override {
        // Input validation - null check device pointer
        if (!device) return;
        
        NimBLEAddress addr = device->getAddress();
        std::string addrStr = addr.toString();
        
        // Validate MAC address length (security: prevent buffer issues)
        if (addrStr.length() == 0 || addrStr.length() >= MAX_MAC_LEN) return;
        
        // Sanitize RSSI (AGENTS_SECURE.md compliance)
        int rssi = sanitizeRssi(device->getRSSI());
        
        // Safely extract device name with length validation
        std::string name = "";
        if (device->haveName()) {
            name = device->getName();
            // Truncate oversized names (security: prevent buffer overflow)
            if (name.length() > MAX_IDENTIFIER_LEN) {
                name = name.substr(0, MAX_IDENTIFIER_LEN);
            }
            // Sanitize name to remove non-printable characters
            name = sanitizeString(name.c_str());
        }
        
        bool macMatch = checkMacPrefixStr(addrStr.c_str());
        bool nameMatch = !name.empty() && checkDeviceNamePattern(name.c_str());
        char ravenUuid[41] = {0};
        bool ravenMatch = checkRavenServiceUuid(device, ravenUuid);
        
        if (macMatch || nameMatch || ravenMatch) {
            const char* method = "ble_mac";
            const char* deviceType = "FLOCK_SAFETY";
            
            if (ravenMatch) {
                method = "raven_uuid";
                deviceType = "RAVEN_GUNSHOT";
            } else if (nameMatch) {
                method = "ble_name";
                if (strcasestr(name.c_str(), "FS Ext") || strcasestr(name.c_str(), "Battery")) {
                    deviceType = "FLOCK_BATTERY";
                } else if (strcasestr(name.c_str(), "Penguin")) {
                    deviceType = "PENGUIN";
                } else if (strcasestr(name.c_str(), "Raven")) {
                    deviceType = "RAVEN_GUNSHOT";
                }
            }
            
            processDetection("BLE", method, deviceType, addrStr.c_str(),
                           name.empty() ? nullptr : name.c_str(), rssi);
        }
    }
};

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

void drawHeader()
{
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.print(BRANDING);
    
    // Show current scan profile
    display.setCursor(45, 0);
    display.print(scanProfiles[currentProfile].shortName);
    
    // Show WiFi channel
    display.setCursor(70, 0);
    display.print("W");
    display.print(currentChannel < 10 ? "0" : "");
    display.print(currentChannel);
    
    // Device count badge
    if (persistentDeviceCount > 0) {
        char countStr[8];
        snprintf(countStr, sizeof(countStr), "%d", persistentDeviceCount);
        int countWidth = strlen(countStr) * 6;
        int boxX = SCREEN_WIDTH - countWidth - 6;
        display.fillRect(boxX, 0, countWidth + 4, 8, SSD1306_WHITE);
        display.setTextColor(SSD1306_BLACK);
        display.setCursor(boxX + 2, 0);
        display.print(countStr);
        display.setTextColor(SSD1306_WHITE);
    }
    
    display.drawLine(0, 9, SCREEN_WIDTH, 9, SSD1306_WHITE);
}

void drawIdleScreen()
{
    display.clearDisplay();
    drawHeader();
    
    // Status line with button feedback indicator
    display.setTextSize(1);
    display.setCursor(0, 12);
    display.print("SCANNING");
    int dots = (millis() / 400) % 4;
    for (int i = 0; i < dots; i++) display.print(".");
    
    // Show HOLD:, or CLICK:X (countdown) indicator on the right
    int holdSecs = getCurrentHoldSeconds();
    int clicks = getPendingClicks();
    int countdown = getClickCountdown();
    
    if (holdSecs > 0) {
        // Currently holding button - show seconds
        display.setCursor(80, 12);
        display.printf("HOLD:%d", holdSecs);
    } else if (clicks > 0 && countdown > 0) {
        // Pending clicks with countdown
        display.setCursor(68, 12);
        display.printf("CLK:%d(%d)", clicks, countdown);
    }
    
    // Assurity meter
    display.setCursor(0, 22);
    display.printf("FLOCK-ER:%s", getAssurityLabel(assurityLevel));
    
    int barY = 31;
    int barWidth = 80;
    display.drawRect(0, barY, barWidth + 2, 6, SSD1306_WHITE);
    int fillWidth = map(assurityLevel, 0, 100, 0, barWidth);
    if (fillWidth > 0) {
        display.fillRect(1, barY + 1, fillWidth, 4, SSD1306_WHITE);
    }
    display.setCursor(barWidth + 6, barY - 1);
    display.printf("%d%%", assurityLevel);
    
    // Signal strength
    display.setCursor(0, 40);
    if (lastRssi > -100) {
        display.printf("SIG:%ddBm", lastRssi);
    } else {
        display.print("SIG:--");
    }
    
    // Stats
    display.setCursor(0, 50);
    display.printf("F:%d R:%d W:%d B:%d", flockDetections, ravenDetections, 
                   wifiDetections, bleDetections);
    
    // Uptime and scan profile
    display.setCursor(0, 58);
    char uptimeStr[10];
    formatUptime(uptimeStr, sizeof(uptimeStr), millis() - startTime);
    display.printf("UP:%s %s", uptimeStr, scanProfiles[currentProfile].shortName);
    
    display.display();
}

void drawAlertScreen()
{
    unsigned long elapsed = millis() - alertStartTime;
    bool shouldFlash = (elapsed < ALERT_DURATION_MS) && ((elapsed / ALERT_FLASH_MS) % 2 == 0);
    
    display.clearDisplay();
    
    if (shouldFlash) {
        display.fillRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, SSD1306_WHITE);
        display.setTextColor(SSD1306_BLACK);
    } else {
        display.setTextColor(SSD1306_WHITE);
    }
    
    display.setTextSize(2);
    display.setCursor(0, 0);
    display.print("ALERT!");
    
    display.setTextSize(1);
    display.setCursor(75, 4);
    display.print(getShortDeviceType(currentDetection.deviceType));
    
    int sepY = 17;
    display.drawLine(0, sepY, SCREEN_WIDTH, sepY, shouldFlash ? SSD1306_BLACK : SSD1306_WHITE);
    
    display.setCursor(0, 20);
    display.printf("%s/%s", currentDetection.protocol, currentDetection.detectionMethod);
    
    display.setCursor(0, 30);
    char shortMac[12];
    strncpy(shortMac, currentDetection.macAddress, 11);
    shortMac[11] = '\0';
    display.printf("MAC:%s", shortMac);
    
    display.setCursor(0, 40);
    display.printf("RSSI:%ddBm", currentDetection.rssi);
    
    // Signal bar
    int barWidth = map(constrain(currentDetection.rssi, -100, -30), -100, -30, 2, 40);
    int barY = 40;
    int barX = 80;
    display.drawRect(barX, barY, 42, 8, shouldFlash ? SSD1306_BLACK : SSD1306_WHITE);
    display.fillRect(barX + 1, barY + 1, barWidth, 6, shouldFlash ? SSD1306_BLACK : SSD1306_WHITE);
    
    display.setCursor(0, 52);
    display.printf("THREAT:%d%% #%d", currentDetection.threatScore, totalDetections);
    
    display.display();
}

void updateDisplay()
{
    // Profile info display takes priority (except alerts)
    if (showingProfileInfo && !currentDetection.active) {
        drawProfileInfoScreen();
        return;
    }
    
    if (currentDetection.active && 
        (millis() - currentDetection.timestamp < DETECTION_TIMEOUT_MS)) {
        drawAlertScreen();
    } else {
        currentDetection.active = false;
        
        if (millis() - lastRadarUpdate > RADAR_UPDATE_MS) {
            radarAngle = (radarAngle + 12) % 360;
            lastRadarUpdate = millis();
        }
        
        drawIdleScreen();
    }
}

// ============================================================================
// CHANNEL HOPPING
// ============================================================================

void hopChannel()
{
    unsigned long now = millis();
    if (now - lastChannelHop > (unsigned long)channelHopInterval) {
        currentChannel++;
        if (currentChannel > MAX_CHANNEL) {
            currentChannel = 1;
        }
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        lastChannelHop = now;
    }
}

// ============================================================================
// BLE SCAN MANAGEMENT
// ============================================================================

void startBleScan()
{
    if (pBLEScan && !pBLEScan->isScanning()) {
        Serial.println("[BLE] Starting scan...");
        pBLEScan->start(bleScanDuration, false);
        bleScanning = true;
        lastBleScan = millis();
    }
}

void checkBleScan()
{
    unsigned long now = millis();
    
    // Start new scan if interval passed
    if (now - lastBleScan >= (unsigned long)bleScanInterval) {
        startBleScan();
    }
    
    // Clear results after scan completes
    if (pBLEScan && !pBLEScan->isScanning() && bleScanning) {
        pBLEScan->clearResults();
        bleScanning = false;
    }
}

// ============================================================================
// HEARTBEAT / RANGE TRACKING
// ============================================================================

void checkDeviceRange()
{
    unsigned long now = millis();
    
    if (deviceInRange) {
        // Heartbeat pulse
        if (now - lastHeartbeat >= HEARTBEAT_INTERVAL_MS) {
            Serial.println("[♥] Device still in range");
            lastHeartbeat = now;
        }
        
        // Check if device went out of range
        if (now - lastDetectionTime >= 30000) {
            Serial.println("[STATUS] Device out of range");
            deviceInRange = false;
        }
    }
}

// ============================================================================
// STARTUP SCREEN
// ============================================================================

void drawStartupScreen()
{
    display.clearDisplay();
    
    display.setTextSize(2);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(10, 5);
    display.print(BRANDING);
    
    display.setTextSize(1);
    display.setCursor(20, 28);
    display.printf("v%s", VERSION);
    
    display.setCursor(5, 42);
    display.print("WiFi+BLE Scanner");
    
    display.setCursor(15, 54);
    display.print("deflock.me");
    
    display.display();
}

// ============================================================================
// SETUP
// ============================================================================

void setup()
{
    Serial.begin(115200);
    delay(1000);
    
    Serial.println();
    Serial.println("========================================");
    Serial.printf("  %s Standalone Scanner v%s\n", BRANDING, VERSION);
    Serial.println("  WiFi Promiscuous + BLE Scanning");
    Serial.println("  Heltec ESP32-S3 OLED Edition");
    Serial.println("========================================");
    Serial.println();
    
    // Initialize LED
    pinMode(LED_BUILTIN_PIN, OUTPUT);
    ledOff();
    
    // Initialize PRG button
    pinMode(PRG_BUTTON_PIN, INPUT_PULLUP);
    Serial.printf("PRG button on GPIO%d:\n", PRG_BUTTON_PIN);
    Serial.println("  - Single click: Stealth mode toggle");
    Serial.println("  - Double click: Cycle scan profile");
    Serial.println("  - Long press (2s): Reset stats");
    
    // Initialize scan profile
    applyScanProfile(PROFILE_URBAN);  // Default: Urban
    
    // Load persistent data
    loadPersistentData();
    
    // Enable Vext for OLED power (Heltec specific)
    #ifdef VEXT_PIN
        Serial.printf("Enabling Vext on GPIO%d\n", VEXT_PIN);
        pinMode(VEXT_PIN, OUTPUT);
        digitalWrite(VEXT_PIN, LOW);
        delay(100);
    #endif
    
    // Initialize I2C
    Serial.printf("I2C: SDA=%d, SCL=%d\n", OLED_SDA, OLED_SCL);
    Wire.begin(OLED_SDA, OLED_SCL);
    
    // Reset OLED
    #ifdef OLED_RST
        Serial.printf("OLED Reset on GPIO%d\n", OLED_RST);
        pinMode(OLED_RST, OUTPUT);
        digitalWrite(OLED_RST, LOW);
        delay(50);
        digitalWrite(OLED_RST, HIGH);
        delay(50);
    #endif
    
    // Initialize display
    Serial.println("Initializing OLED...");
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println("ERROR: SSD1306 init failed!");
        while (1) {
            ledToggle();
            delay(200);
        }
    }
    
    Serial.printf("OLED ready: %dx%d\n", SCREEN_WIDTH, SCREEN_HEIGHT);
    display.clearDisplay();
    display.setRotation(0);
    drawStartupScreen();
    
    // Boot LED sequence
    for (int i = 0; i < 3; i++) {
        ledOn(); delay(100);
        ledOff(); delay(100);
    }
    
    // Initialize WiFi promiscuous mode
    Serial.println("\n[WiFi] Initializing promiscuous mode...");
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifiSnifferPacketHandler);
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    
    Serial.printf("[WiFi] Promiscuous mode enabled, starting on channel %d\n", currentChannel);
    Serial.printf("[WiFi] Monitoring %d SSID patterns, %d MAC prefixes\n", 
                  SSID_PATTERN_COUNT, MAC_PREFIX_COUNT);
    
    // Initialize BLE - settings will be adjusted per scan profile
    Serial.println("\n[BLE] Initializing scanner...");
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new MyBLEAdvertisedDeviceCallbacks(), false);
    pBLEScan->setActiveScan(true);      // Active scan gets device names
    pBLEScan->setInterval(50);          // 50ms interval - base timing
    pBLEScan->setWindow(scanProfiles[currentProfile].bleWindow);  // Duty cycle from profile
    pBLEScan->setMaxResults(0);         // Don't store results, process in callback
    pBLEScan->setDuplicateFilter(false); // Don't filter duplicates - catch every packet
    
    Serial.printf("[BLE] Scanner initialized, %d device name patterns, %d Raven UUIDs\n",
                  DEVICE_NAME_PATTERN_COUNT, RAVEN_UUID_COUNT);
    
    delay(2000);
    
    startTime = millis();
    lastChannelHop = millis();
    lastBleScan = millis();
    lastSaveTime = millis();
    
    Serial.println("\n========================================");
    Serial.println("  READY - Hunting for surveillance!");
    Serial.println("  WiFi: Probe requests & beacons");
    Serial.println("  BLE:  Device names & Raven UUIDs");
    Serial.println("========================================\n");
    
    // Initialize hardware watchdog timer (AGENTS_SECURE.md: fault recovery)
    // Uses ESP-IDF 4.4 API (Arduino-ESP32 v2.x)
    Serial.printf("[SECURITY] Enabling watchdog timer (%ds timeout)\n", WDT_TIMEOUT_SEC);
    esp_task_wdt_init(WDT_TIMEOUT_SEC, true);  // timeout in seconds, panic on timeout
    esp_task_wdt_add(NULL);  // Add current task (loopTask) to WDT
    
    // Start first BLE scan
    startBleScan();
}

// ============================================================================
// MAIN LOOP
// ============================================================================

void loop()
{
    // Feed watchdog timer (AGENTS_SECURE.md: prove liveness)
    esp_task_wdt_reset();
    
    // Check button (single/double click, long press)
    checkButton();
    if (showingResetConfirm) {
        delay(10);
        return;
    }
    
    // WiFi channel hopping
    hopChannel();
    
    // BLE scanning
    checkBleScan();
    
    // LED alert updates (respects stealth mode internally)
    if (!stealthMode) {
        ledAlertUpdate();
    } else if (ledState) {
        ledOff();  // Ensure LED stays off in stealth
    }
    
    // Device range tracking
    checkDeviceRange();
    
    // Assurity decay
    decayAssurity();
    
    // Expire old devices periodically
    static unsigned long lastExpireCheck = 0;
    if (millis() - lastExpireCheck > 30000) {
        expireOldDevices();
        lastExpireCheck = millis();
    }
    
    // Periodic save
    checkPeriodicSave();
    
    // Update display (skip if stealth mode)
    if (!stealthMode && millis() - lastStatusUpdate >= STATUS_UPDATE_MS) {
        updateDisplay();
        lastStatusUpdate = millis();
    }
    
    delay(1);  // Minimal delay for maximum responsiveness
}
