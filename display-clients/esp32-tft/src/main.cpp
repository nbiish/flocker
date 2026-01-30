/**
 * DEFLOCK Display Client - ESP32 + TFT LCD
 * 
 * Real-time surveillance detection display for the Flock-You project.
 * Connects to the Flock detector via serial and displays detections
 * on a TFT screen with visual alerts.
 * 
 * Supports multiple display types:
 *   - ST7789 240x240 (most common)
 *   - ILI9341 320x240 (TFT shields)
 *   - GC9A01 240x240 (round displays)
 *   - ST7735 128x160 (mini displays)
 *   - LILYGO T-Display variants
 * 
 * Connection Methods:
 *   1. USB-Serial adapter: Detector USB-C -> Adapter -> ESP32 RX pin
 *   2. Direct serial: Detector TX -> ESP32 RX, GND -> GND
 *   3. USB Host (S3 boards): Direct USB-C connection
 * 
 * Project: https://github.com/colonelpanichacks/flock-you
 * Data: deflock.me
 */

#include <Arduino.h>
#include <TFT_eSPI.h>
#include <ArduinoJson.h>

// ============================================================================
// VERSION & BRANDING
// ============================================================================

#define VERSION "2.0.0"
#define BRANDING "DEFLOCK"

// ============================================================================
// SERIAL CONFIGURATION (from platformio.ini or defaults)
// ============================================================================

#ifdef USE_USB_SERIAL
    #define DETECTOR_SERIAL Serial
    #define DETECTOR_BAUD 115200
#else
    #define DETECTOR_SERIAL Serial2
    #ifndef DETECTOR_RX_PIN
        #define DETECTOR_RX_PIN 27
    #endif
    #ifndef DETECTOR_TX_PIN
        #define DETECTOR_TX_PIN 26
    #endif
    #define DETECTOR_BAUD 115200
#endif

// ============================================================================
// DISPLAY COLORS - High contrast for outdoor visibility
// ============================================================================

#define COLOR_BG          TFT_BLACK
#define COLOR_HEADER      0x001F   // Dark blue
#define COLOR_ALERT       TFT_RED
#define COLOR_OK          0x07E0   // Bright green
#define COLOR_WARN        TFT_YELLOW
#define COLOR_TEXT        TFT_WHITE
#define COLOR_DIM         0x7BEF   // Light gray
#define COLOR_DARKDIM     0x39E7   // Dark gray
#define COLOR_FLOCK       0xF800   // Red for Flock
#define COLOR_RAVEN       0xFBE0   // Orange for Raven
#define COLOR_PENGUIN     0x07FF   // Cyan for Penguin
#define COLOR_UNKNOWN     0xFFE0   // Yellow for unknown

// ============================================================================
// ALERT TIMING
// ============================================================================

#define ALERT_FLASH_MS      150
#define ALERT_DURATION_MS   5000
#define STATUS_UPDATE_MS    100
#define IDLE_RADAR_SPEED_MS 50
#define DETECTION_TIMEOUT_MS 30000

// ============================================================================
// GLOBALS
// ============================================================================

TFT_eSPI tft = TFT_eSPI();

// Display dimensions (set dynamically after init)
int screenW = 240;
int screenH = 240;
bool isSmallDisplay = false;
bool isRoundDisplay = false;

// Detection state
struct DetectionInfo {
    bool active;
    unsigned long timestamp;
    char protocol[16];
    char deviceType[32];
    char identifier[48];
    char macAddress[20];
    int rssi;
    char signalStrength[12];
    int threatScore;
    char detectionMethod[32];
    char manufacturer[32];
    char alertLevel[16];
    char serviceUuids[256];
};

DetectionInfo currentDetection = {0};
DetectionInfo lastDetection = {0};

// Statistics
unsigned long lastStatusUpdate = 0;
unsigned long alertStartTime = 0;
bool alertFlashState = false;
int totalDetections = 0;
int flockDetections = 0;
int ravenDetections = 0;
int otherDetections = 0;
unsigned long startTime = 0;

// Flock-er Assurity Meter - tracks confidence based on recent positive detections
// Uses a sliding window approach with decay for "low to high" confidence
#define ASSURITY_WINDOW_SIZE 16
#define ASSURITY_DECAY_MS 30000    // Decay one level every 30 seconds without detection
int assurityBuffer[ASSURITY_WINDOW_SIZE] = {0};  // Circular buffer of detection scores
int assurityIndex = 0;
int assurityLevel = 0;              // 0-100 current assurity level
unsigned long lastAssurityDecay = 0;
int lastRssi = -100;                // Last RSSI for strength indicator

// Radar animation
int radarAngle = 0;
unsigned long lastRadarUpdate = 0;

// Serial buffer
char serialBuffer[4096];
int bufferIndex = 0;

// Connection state
bool detectorConnected = false;
unsigned long lastDataReceived = 0;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

uint16_t getDeviceColor(const char* deviceType)
{
    if (strstr(deviceType, "FLOCK") || strstr(deviceType, "Flock")) {
        return COLOR_FLOCK;
    } else if (strstr(deviceType, "RAVEN") || strstr(deviceType, "Raven")) {
        return COLOR_RAVEN;
    } else if (strstr(deviceType, "PENGUIN") || strstr(deviceType, "Penguin")) {
        return COLOR_PENGUIN;
    }
    return COLOR_UNKNOWN;
}

const char* getThreatLabel(int score)
{
    if (score >= 90) return "CRITICAL";
    if (score >= 75) return "HIGH";
    if (score >= 50) return "MEDIUM";
    if (score >= 25) return "LOW";
    return "MINIMAL";
}

uint16_t getThreatColor(int score)
{
    if (score >= 75) return COLOR_ALERT;
    if (score >= 50) return COLOR_WARN;
    return COLOR_OK;
}

void formatUptime(char* buffer, size_t len, unsigned long ms)
{
    unsigned long secs = ms / 1000;
    unsigned long hrs = secs / 3600;
    unsigned long mins = (secs / 60) % 60;
    unsigned long s = secs % 60;
    snprintf(buffer, len, "%02lu:%02lu:%02lu", hrs, mins, s);
}

// Calculate assurity level from detection buffer
void updateAssurityLevel()
{
    int sum = 0;
    for (int i = 0; i < ASSURITY_WINDOW_SIZE; i++) {
        sum += assurityBuffer[i];
    }
    // Scale to 0-100 (max score per detection is ~10, window is 16)
    assurityLevel = constrain((sum * 100) / (ASSURITY_WINDOW_SIZE * 10), 0, 100);
}

// Add a positive detection to the assurity meter
void recordPositiveDetection(int score)
{
    // Score 1-10 based on detection type match and signal strength
    int recordScore = constrain(score, 1, 10);
    assurityBuffer[assurityIndex] = recordScore;
    assurityIndex = (assurityIndex + 1) % ASSURITY_WINDOW_SIZE;
    updateAssurityLevel();
    lastAssurityDecay = millis();
}

// Decay assurity over time when no detections
void decayAssurity()
{
    if (millis() - lastAssurityDecay > ASSURITY_DECAY_MS) {
        // Decay oldest entry
        int decayIdx = (assurityIndex + 1) % ASSURITY_WINDOW_SIZE;
        if (assurityBuffer[decayIdx] > 0) {
            assurityBuffer[decayIdx]--;
            updateAssurityLevel();
        }
        lastAssurityDecay = millis();
    }
}

// Get color for assurity level
uint16_t getAssurityColor(int level)
{
    if (level >= 75) return COLOR_ALERT;     // High - red (confirmed flock activity)
    if (level >= 50) return COLOR_WARN;      // Medium - yellow (likely)
    if (level >= 25) return 0x07E0;          // Low-medium - green (possible)
    return COLOR_DIM;                        // Low - gray (minimal activity)
}

// Get assurity label
const char* getAssurityLabel(int level)
{
    if (level >= 75) return "CONFIRMED";
    if (level >= 50) return "LIKELY";
    if (level >= 25) return "POSSIBLE";
    return "SCANNING";
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

void drawHeader()
{
    int headerH = isSmallDisplay ? 24 : 36;
    
    tft.fillRect(0, 0, screenW, headerH, COLOR_HEADER);
    tft.setTextColor(COLOR_TEXT, COLOR_HEADER);
    
    if (isSmallDisplay) {
        tft.setTextSize(1);
        tft.setCursor(4, 8);
    } else {
        tft.setTextSize(2);
        tft.setCursor(8, 10);
    }
    tft.print(BRANDING);
    
    // Connection indicator
    int indicatorR = isSmallDisplay ? 4 : 8;
    int indicatorX = screenW - indicatorR - 8;
    int indicatorY = headerH / 2;
    
    uint16_t statusColor = detectorConnected ? COLOR_OK : COLOR_DIM;
    if (currentDetection.active) {
        statusColor = (millis() / 200) % 2 ? COLOR_ALERT : COLOR_OK;
    }
    tft.fillCircle(indicatorX, indicatorY, indicatorR, statusColor);
    
    // Detection count badge
    if (totalDetections > 0) {
        int badgeX = isSmallDisplay ? 70 : 110;
        tft.setTextSize(1);
        tft.setCursor(badgeX, isSmallDisplay ? 8 : 13);
        tft.setTextColor(COLOR_WARN, COLOR_HEADER);
        tft.printf("[%d]", totalDetections);
    }
}

void drawRadar(int centerX, int centerY, int radius)
{
    // Clear radar area efficiently
    #ifdef ROUND_DISPLAY
        // Don't clear for round displays - use whole screen
    #else
        tft.fillCircle(centerX, centerY, radius + 2, COLOR_BG);
    #endif
    
    // Draw concentric circles
    for (int i = 1; i <= 3; i++) {
        int r = radius * i / 3;
        tft.drawCircle(centerX, centerY, r, COLOR_DARKDIM);
    }
    
    // Draw crosshairs
    tft.drawLine(centerX - radius, centerY, centerX + radius, centerY, COLOR_DARKDIM);
    tft.drawLine(centerX, centerY - radius, centerX, centerY + radius, COLOR_DARKDIM);
    
    // Draw sweep line with fading trail
    float rad = radarAngle * PI / 180.0;
    int lineX = centerX + cos(rad) * radius;
    int lineY = centerY + sin(rad) * radius;
    
    // Main sweep line
    tft.drawLine(centerX, centerY, lineX, lineY, COLOR_OK);
    
    // Trail effect (3 lines fading)
    for (int i = 1; i <= 3; i++) {
        float trailRad = (radarAngle - i * 15) * PI / 180.0;
        int trailX = centerX + cos(trailRad) * radius;
        int trailY = centerY + sin(trailRad) * radius;
        uint16_t trailColor = (i == 1) ? 0x03E0 : (i == 2) ? 0x0200 : COLOR_DARKDIM;
        tft.drawLine(centerX, centerY, trailX, trailY, trailColor);
    }
    
    // Draw random "blips" for visual interest
    if (random(100) < 5) {
        int blipAngle = random(360);
        int blipDist = random(radius / 3, radius);
        float blipRad = blipAngle * PI / 180.0;
        int blipX = centerX + cos(blipRad) * blipDist;
        int blipY = centerY + sin(blipRad) * blipDist;
        tft.fillCircle(blipX, blipY, 2, COLOR_DIM);
    }
}

void drawStrengthBar(int x, int y, int width, int height, int rssi)
{
    // RSSI typically ranges from -100 (weak) to -30 (strong)
    int barWidth = map(constrain(rssi, -100, -30), -100, -30, 2, width - 4);
    uint16_t barColor = rssi > -50 ? COLOR_OK : (rssi > -70 ? COLOR_WARN : COLOR_ALERT);
    
    // Background
    tft.fillRect(x, y, width, height, COLOR_DARKDIM);
    // Fill bar
    tft.fillRect(x + 2, y + 2, barWidth, height - 4, barColor);
    // Border
    tft.drawRect(x, y, width, height, COLOR_DIM);
}

void drawAssurityMeter(int x, int y, int width, int height)
{
    int barWidth = map(assurityLevel, 0, 100, 2, width - 4);
    uint16_t barColor = getAssurityColor(assurityLevel);
    
    // Background with gradient effect
    tft.fillRect(x, y, width, height, COLOR_DARKDIM);
    
    // Segmented bar for visual appeal (5 segments)
    int segWidth = (width - 4) / 5;
    for (int i = 0; i < 5; i++) {
        int segX = x + 2 + (i * segWidth);
        int threshold = (i + 1) * 20;
        if (assurityLevel >= threshold - 10) {
            uint16_t segColor = (i < 2) ? COLOR_OK : (i < 4) ? COLOR_WARN : COLOR_ALERT;
            if (assurityLevel < threshold) {
                // Partial segment
                int partialWidth = map(assurityLevel, threshold - 20, threshold, 0, segWidth - 2);
                tft.fillRect(segX, y + 2, partialWidth, height - 4, segColor);
            } else {
                tft.fillRect(segX, y + 2, segWidth - 2, height - 4, segColor);
            }
        }
    }
    // Border
    tft.drawRect(x, y, width, height, COLOR_DIM);
}

void drawIdleScreen()
{
    int headerH = isSmallDisplay ? 24 : 36;
    tft.fillRect(0, headerH, screenW, screenH - headerH, COLOR_BG);
    
    int yPos = headerH + 8;
    int xMargin = isSmallDisplay ? 4 : 10;
    int barWidth = screenW - (xMargin * 2);
    
    // Status text
    tft.setTextColor(COLOR_OK, COLOR_BG);
    tft.setTextSize(isSmallDisplay ? 1 : 2);
    tft.setCursor(xMargin, yPos);
    tft.print("SCANNING");
    
    // Animated dots
    int dots = (millis() / 500) % 4;
    for (int i = 0; i < dots; i++) {
        tft.print(".");
    }
    
    yPos += isSmallDisplay ? 16 : 28;
    
    // ========== FLOCK-ER ASSURITY METER ==========
    tft.setTextColor(getAssurityColor(assurityLevel), COLOR_BG);
    tft.setTextSize(1);
    tft.setCursor(xMargin, yPos);
    tft.printf("FLOCK-ER: %s (%d%%)", getAssurityLabel(assurityLevel), assurityLevel);
    yPos += 12;
    
    // Draw the assurity bar
    drawAssurityMeter(xMargin, yPos, barWidth, isSmallDisplay ? 8 : 12);
    yPos += isSmallDisplay ? 14 : 20;
    
    // ========== SIGNAL STRENGTH BAR ==========
    tft.setTextColor(COLOR_DIM, COLOR_BG);
    tft.setTextSize(1);
    tft.setCursor(xMargin, yPos);
    if (currentDetection.active || lastRssi > -100) {
        int displayRssi = currentDetection.active ? currentDetection.rssi : lastRssi;
        tft.printf("SIGNAL: %d dBm", displayRssi);
        yPos += 12;
        drawStrengthBar(xMargin, yPos, barWidth, isSmallDisplay ? 6 : 10, displayRssi);
    } else {
        tft.print("SIGNAL: --");
    }
    yPos += isSmallDisplay ? 12 : 18;
    
    // ========== DETECTION STATISTICS ==========
    tft.setTextColor(COLOR_DIM, COLOR_BG);
    tft.setTextSize(1);
    
    tft.setCursor(xMargin, yPos);
    tft.printf("Total: %d", totalDetections);
    
    if (!isSmallDisplay) {
        yPos += 14;
        tft.setCursor(xMargin, yPos);
        tft.setTextColor(COLOR_FLOCK, COLOR_BG);
        tft.printf("Flock:%d ", flockDetections);
        tft.setTextColor(COLOR_RAVEN, COLOR_BG);
        tft.printf("Raven:%d", ravenDetections);
    }
    
    yPos += 14;
    char uptimeStr[16];
    formatUptime(uptimeStr, sizeof(uptimeStr), millis() - startTime);
    tft.setTextColor(COLOR_DIM, COLOR_BG);
    tft.setCursor(isSmallDisplay ? 4 : 10, yPos);
    tft.printf("Up: %s", uptimeStr);
    
    // Radar display
    int radarRadius = isSmallDisplay ? 35 : 60;
    int radarY = isSmallDisplay ? (screenH - radarRadius - 10) : (screenH - radarRadius - 20);
    
    #ifdef ROUND_DISPLAY
        radarRadius = screenW / 2 - 30;
        radarY = screenH / 2 + 10;
    #endif
    
    drawRadar(screenW / 2, radarY, radarRadius);
    
    // Connection status at bottom
    tft.setTextSize(1);
    tft.setCursor(isSmallDisplay ? 4 : 10, screenH - 12);
    if (detectorConnected) {
        tft.setTextColor(COLOR_OK, COLOR_BG);
        tft.print("DETECTOR OK");
    } else {
        tft.setTextColor(COLOR_DIM, COLOR_BG);
        tft.print("WAITING...");
    }
}

void drawAlertScreen()
{
    int headerH = isSmallDisplay ? 24 : 36;
    
    // Flash effect
    unsigned long elapsed = millis() - alertStartTime;
    bool shouldFlash = (elapsed < ALERT_DURATION_MS) && ((elapsed / ALERT_FLASH_MS) % 2 == 0);
    
    if (shouldFlash != alertFlashState) {
        alertFlashState = shouldFlash;
        tft.fillRect(0, headerH, screenW, screenH - headerH, 
                    alertFlashState ? COLOR_ALERT : COLOR_BG);
    }
    
    uint16_t bgColor = alertFlashState ? COLOR_ALERT : COLOR_BG;
    uint16_t textColor = alertFlashState ? COLOR_BG : COLOR_TEXT;
    uint16_t deviceColor = getDeviceColor(currentDetection.deviceType);
    
    int yPos = headerH + 8;
    int xMargin = isSmallDisplay ? 4 : 10;
    
    // ALERT banner
    tft.setTextColor(alertFlashState ? COLOR_BG : COLOR_ALERT, bgColor);
    tft.setTextSize(isSmallDisplay ? 1 : 2);
    tft.setCursor(xMargin, yPos);
    tft.print("!! DETECTED !!");
    
    yPos += isSmallDisplay ? 18 : 28;
    
    // Device type with color coding
    tft.setTextColor(alertFlashState ? COLOR_BG : deviceColor, bgColor);
    tft.setTextSize(isSmallDisplay ? 1 : 2);
    tft.setCursor(xMargin, yPos);
    
    // Truncate device type for small displays
    char deviceLabel[24];
    strncpy(deviceLabel, currentDetection.deviceType, sizeof(deviceLabel) - 1);
    deviceLabel[isSmallDisplay ? 16 : 23] = '\0';
    tft.print(deviceLabel);
    
    yPos += isSmallDisplay ? 18 : 26;
    
    // Protocol & Method
    tft.setTextColor(textColor, bgColor);
    tft.setTextSize(1);
    tft.setCursor(xMargin, yPos);
    tft.printf("%s / %s", currentDetection.protocol, currentDetection.detectionMethod);
    
    yPos += 14;
    
    // MAC Address
    tft.setCursor(xMargin, yPos);
    tft.printf("MAC: %s", currentDetection.macAddress);
    
    yPos += 14;
    
    // Identifier (SSID/Name) if different from MAC
    if (strlen(currentDetection.identifier) > 0 && 
        strcmp(currentDetection.identifier, currentDetection.macAddress) != 0) {
        tft.setCursor(xMargin, yPos);
        char idLabel[32];
        strncpy(idLabel, currentDetection.identifier, 24);
        idLabel[24] = '\0';
        tft.printf("ID: %s", idLabel);
        yPos += 14;
    }
    
    // Signal strength bar
    tft.setCursor(xMargin, yPos);
    tft.printf("RSSI: %d dBm", currentDetection.rssi);
    
    yPos += 12;
    
    // Draw signal bar
    int barMaxWidth = isSmallDisplay ? (screenW - 20) : 120;
    int barWidth = map(constrain(currentDetection.rssi, -100, -30), -100, -30, 5, barMaxWidth);
    uint16_t barColor = currentDetection.rssi > -50 ? COLOR_OK : 
                       (currentDetection.rssi > -70 ? COLOR_WARN : COLOR_ALERT);
    
    tft.fillRect(xMargin, yPos, barWidth, 8, alertFlashState ? COLOR_BG : barColor);
    tft.drawRect(xMargin, yPos, barMaxWidth, 8, alertFlashState ? COLOR_BG : COLOR_DIM);
    
    yPos += 16;
    
    // Threat score
    tft.setTextSize(isSmallDisplay ? 1 : 2);
    uint16_t threatColor = getThreatColor(currentDetection.threatScore);
    tft.setTextColor(alertFlashState ? COLOR_BG : threatColor, bgColor);
    tft.setCursor(xMargin, yPos);
    tft.printf("THREAT: %d%% %s", currentDetection.threatScore, 
               isSmallDisplay ? "" : getThreatLabel(currentDetection.threatScore));
    
    yPos += isSmallDisplay ? 18 : 28;
    
    // Manufacturer if known (for Raven)
    if (strlen(currentDetection.manufacturer) > 0 && !isSmallDisplay) {
        tft.setTextSize(1);
        tft.setTextColor(COLOR_DIM, bgColor);
        tft.setCursor(xMargin, yPos);
        tft.printf("Mfr: %s", currentDetection.manufacturer);
        yPos += 14;
    }
    
    // Time since detection
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM, bgColor);
    tft.setCursor(xMargin, screenH - 14);
    unsigned long secsSince = (millis() - currentDetection.timestamp) / 1000;
    tft.printf("Detected %lus ago | #%d", secsSince, totalDetections);
}

void updateDisplay()
{
    drawHeader();
    
    if (currentDetection.active && 
        (millis() - currentDetection.timestamp < DETECTION_TIMEOUT_MS)) {
        drawAlertScreen();
    } else {
        currentDetection.active = false;
        
        // Update radar animation
        if (millis() - lastRadarUpdate > IDLE_RADAR_SPEED_MS) {
            radarAngle = (radarAngle + 6) % 360;
            lastRadarUpdate = millis();
        }
        
        drawIdleScreen();
    }
}

// ============================================================================
// JSON PARSING
// ============================================================================

void parseDetectionJson(const char* json)
{
    StaticJsonDocument<2048> doc;
    DeserializationError error = deserializeJson(doc, json);
    
    if (error) {
        Serial.printf("JSON parse error: %s\n", error.c_str());
        return;
    }
    
    // Check if this is a detection (has protocol or detection_type field)
    if (!doc.containsKey("protocol") && !doc.containsKey("detection_type")) {
        return;
    }
    
    // Mark data received
    lastDataReceived = millis();
    detectorConnected = true;
    
    // Store previous detection
    memcpy(&lastDetection, &currentDetection, sizeof(DetectionInfo));
    
    // Reset and populate new detection
    memset(&currentDetection, 0, sizeof(DetectionInfo));
    currentDetection.active = true;
    currentDetection.timestamp = millis();
    alertStartTime = millis();
    alertFlashState = false;
    totalDetections++;
    
    // Copy fields safely
    strlcpy(currentDetection.protocol, 
            doc["protocol"] | "unknown", sizeof(currentDetection.protocol));
    
    strlcpy(currentDetection.macAddress, 
            doc["mac_address"] | "unknown", sizeof(currentDetection.macAddress));
    
    strlcpy(currentDetection.detectionMethod, 
            doc["detection_method"] | "unknown", sizeof(currentDetection.detectionMethod));
    
    strlcpy(currentDetection.signalStrength, 
            doc["signal_strength"] | "unknown", sizeof(currentDetection.signalStrength));
    
    strlcpy(currentDetection.alertLevel, 
            doc["alert_level"] | "MEDIUM", sizeof(currentDetection.alertLevel));
    
    currentDetection.rssi = doc["rssi"] | -100;
    currentDetection.threatScore = doc["threat_score"] | 50;
    
    // Device type determination
    if (doc.containsKey("device_type")) {
        strlcpy(currentDetection.deviceType, 
                doc["device_type"], sizeof(currentDetection.deviceType));
    } else if (doc.containsKey("detection_type")) {
        strlcpy(currentDetection.deviceType, 
                doc["detection_type"], sizeof(currentDetection.deviceType));
    } else {
        strlcpy(currentDetection.deviceType, "FLOCK_SAFETY", sizeof(currentDetection.deviceType));
    }
    
    // Manufacturer (especially for Raven)
    if (doc.containsKey("manufacturer")) {
        strlcpy(currentDetection.manufacturer, 
                doc["manufacturer"], sizeof(currentDetection.manufacturer));
    }
    
    // Service UUIDs (for Raven BLE detection)
    if (doc.containsKey("service_uuids")) {
        JsonArray uuids = doc["service_uuids"].as<JsonArray>();
        currentDetection.serviceUuids[0] = '\0';
        for (JsonVariant uuid : uuids) {
            if (strlen(currentDetection.serviceUuids) < sizeof(currentDetection.serviceUuids) - 40) {
                strcat(currentDetection.serviceUuids, uuid.as<const char*>());
                strcat(currentDetection.serviceUuids, ",");
            }
        }
    }
    
    // Identifier (SSID, device name, or MAC)
    if (doc.containsKey("ssid") && strlen(doc["ssid"] | "") > 0) {
        strlcpy(currentDetection.identifier, doc["ssid"], sizeof(currentDetection.identifier));
    } else if (doc.containsKey("device_name") && strlen(doc["device_name"] | "") > 0) {
        strlcpy(currentDetection.identifier, doc["device_name"], sizeof(currentDetection.identifier));
    } else {
        strlcpy(currentDetection.identifier, currentDetection.macAddress, sizeof(currentDetection.identifier));
    }
    
    // Update statistics and assurity meter
    int detectionScore = 5;  // Base score
    bool isKnownDevice = false;
    
    if (strstr(currentDetection.deviceType, "FLOCK") || strstr(currentDetection.deviceType, "Flock")) {
        flockDetections++;
        detectionScore = 10;  // High score for Flock
        isKnownDevice = true;
    } else if (strstr(currentDetection.deviceType, "RAVEN") || strstr(currentDetection.deviceType, "Raven")) {
        ravenDetections++;
        detectionScore = 9;   // High score for Raven
        isKnownDevice = true;
    } else if (strstr(currentDetection.deviceType, "PENGUIN") || strstr(currentDetection.deviceType, "Penguin")) {
        detectionScore = 8;   // Score for Penguin
        isKnownDevice = true;
        otherDetections++;
    } else if (strstr(currentDetection.deviceType, "SURVEILLANCE") || 
               strstr(currentDetection.deviceType, "CAMERA") ||
               strstr(currentDetection.deviceType, "LPR")) {
        detectionScore = 7;   // Score for generic surveillance
        isKnownDevice = true;
        otherDetections++;
    } else {
        otherDetections++;
        detectionScore = 3;   // Lower score for unknown
    }
    
    // Boost score for strong signals (close proximity)
    if (currentDetection.rssi > -50) {
        detectionScore = min(detectionScore + 2, 10);
    } else if (currentDetection.rssi > -70) {
        detectionScore = min(detectionScore + 1, 10);
    }
    
    // Record for assurity meter (only known surveillance devices)
    if (isKnownDevice) {
        recordPositiveDetection(detectionScore);
    }
    
    // Track RSSI for strength indicator
    lastRssi = currentDetection.rssi;
    
    Serial.printf("Detection #%d: %s @ %s (%d dBm) - %s [score:%d, assurity:%d%%]\n", 
                  totalDetections,
                  currentDetection.deviceType,
                  currentDetection.macAddress,
                  currentDetection.rssi,
                  currentDetection.detectionMethod,
                  detectionScore,
                  assurityLevel);
}

void processSerialData()
{
    while (DETECTOR_SERIAL.available()) {
        char c = DETECTOR_SERIAL.read();
        lastDataReceived = millis();
        detectorConnected = true;
        
        if (c == '\n' || c == '\r') {
            if (bufferIndex > 0) {
                serialBuffer[bufferIndex] = '\0';
                
                // Check if it looks like JSON
                if (serialBuffer[0] == '{') {
                    parseDetectionJson(serialBuffer);
                }
                
                bufferIndex = 0;
            }
        } else if (bufferIndex < sizeof(serialBuffer) - 1) {
            serialBuffer[bufferIndex++] = c;
        }
    }
    
    // Check for connection timeout
    if (millis() - lastDataReceived > 10000) {
        detectorConnected = false;
    }
}

// ============================================================================
// STARTUP SCREEN
// ============================================================================

void drawStartupScreen()
{
    tft.fillScreen(COLOR_BG);
    
    int centerX = screenW / 2;
    int centerY = screenH / 2;
    
    // Logo/title
    tft.setTextColor(COLOR_OK, COLOR_BG);
    tft.setTextSize(isSmallDisplay ? 2 : 3);
    tft.setCursor(centerX - (isSmallDisplay ? 40 : 70), centerY - 30);
    tft.print(BRANDING);
    
    // Version
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM, COLOR_BG);
    tft.setCursor(centerX - 30, centerY);
    tft.printf("Display v%s", VERSION);
    
    // Status
    tft.setTextColor(COLOR_WARN, COLOR_BG);
    tft.setCursor(centerX - 50, centerY + 20);
    tft.print("Initializing...");
    
    // Credits
    tft.setTextColor(COLOR_DARKDIM, COLOR_BG);
    tft.setCursor(centerX - 35, screenH - 20);
    tft.print("deflock.me");
}

void drawConnectingScreen()
{
    tft.fillScreen(COLOR_BG);
    
    int centerX = screenW / 2;
    int centerY = screenH / 2;
    
    tft.setTextColor(COLOR_OK, COLOR_BG);
    tft.setTextSize(2);
    tft.setCursor(centerX - 50, centerY - 20);
    tft.print("WAITING");
    
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM, COLOR_BG);
    tft.setCursor(centerX - 60, centerY + 10);
    tft.print("Connect detector via");
    tft.setCursor(centerX - 50, centerY + 24);
    #ifdef USE_USB_SERIAL
        tft.print("USB-C cable");
    #else
        tft.print("serial adapter");
    #endif
    
    // Show expected baud rate
    tft.setCursor(centerX - 45, centerY + 44);
    tft.printf("%d baud", DETECTOR_BAUD);
}

// ============================================================================
// MAIN
// ============================================================================

void setup()
{
    // Debug serial (USB on most boards)
    Serial.begin(115200);
    delay(1000);  // Give USB CDC time to enumerate
    
    Serial.println();
    Serial.println("========================================");
    Serial.printf("  %s Display Client v%s\n", BRANDING, VERSION);
    Serial.println("  Surveillance Detection System");
    Serial.println("========================================");
    Serial.println();
    
    // Initialize backlight pin BEFORE display init
    #ifdef TFT_BL
        Serial.printf("Backlight pin: GPIO%d\n", TFT_BL);
        pinMode(TFT_BL, OUTPUT);
        digitalWrite(TFT_BL, HIGH);  // Turn on backlight
    #endif
    
    Serial.println("Initializing TFT display...");
    Serial.printf("  MOSI: GPIO%d\n", TFT_MOSI);
    Serial.printf("  SCLK: GPIO%d\n", TFT_SCLK);
    Serial.printf("  CS:   GPIO%d\n", TFT_CS);
    Serial.printf("  DC:   GPIO%d\n", TFT_DC);
    Serial.printf("  RST:  GPIO%d\n", TFT_RST);
    
    // Initialize detector serial (if not using USB)
    #ifndef USE_USB_SERIAL
        DETECTOR_SERIAL.begin(DETECTOR_BAUD, SERIAL_8N1, DETECTOR_RX_PIN, DETECTOR_TX_PIN);
        Serial.printf("Detector serial: RX=%d TX=%d @ %d baud\n", 
                      DETECTOR_RX_PIN, DETECTOR_TX_PIN, DETECTOR_BAUD);
    #else
        Serial.println("Using USB serial for detector connection");
    #endif
    
    // Initialize display
    tft.init();
    Serial.println("TFT init complete");
    
    // Get actual display dimensions
    screenW = tft.width();
    screenH = tft.height();
    
    // Detect display characteristics
    #ifdef SMALL_DISPLAY
        isSmallDisplay = true;
    #else
        isSmallDisplay = (screenW < 200 || screenH < 200);
    #endif
    
    #ifdef ROUND_DISPLAY
        isRoundDisplay = true;
    #endif
    
    // Set rotation (adjust as needed: 0, 1, 2, or 3)
    tft.setRotation(0);
    
    Serial.printf("Display: %dx%d (small=%d, round=%d)\n", 
                  screenW, screenH, isSmallDisplay, isRoundDisplay);
    
    // Show startup screen
    drawStartupScreen();
    delay(2000);
    
    // Show connecting screen
    drawConnectingScreen();
    delay(1000);
    
    // Clear and start main loop
    tft.fillScreen(COLOR_BG);
    startTime = millis();
    lastDataReceived = millis();
    
    Serial.println();
    Serial.println("Ready - waiting for detections...");
    Serial.println();
}

void loop()
{
    // Process incoming serial data from detector
    processSerialData();
    
    // Decay assurity over time without detections
    decayAssurity();
    
    // Update display at regular intervals
    unsigned long now = millis();
    if (now - lastStatusUpdate >= STATUS_UPDATE_MS) {
        updateDisplay();
        lastStatusUpdate = now;
    }
    
    // Small delay to prevent tight loop
    delay(5);
}
