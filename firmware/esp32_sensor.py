# Legacy file — not used in Polarix production
# Polarix uses Teltonika FMB920 + EYE Sensor hardware. See hardware/HARDWARE.md.
"""
Polarix — ESP32 MicroPython sensor firmware (legacy)
Hardware: ESP32 + DS18B20 temperature sensor
"""
import machine, network, urequests, time, onewire, ds18x20, json

# ── Configure these ───────────────────────────────────────────────────────────
WIFI_SSID      = "YOUR_WIFI_SSID"
WIFI_PASS      = "YOUR_WIFI_PASSWORD"
SERVER_URL     = "https://your-polarix-server.com/reading"
CLIENT_ID      = "your_client_id"
SENSOR_ID      = "sensor_01"
DS18B20_PIN    = 4       # GPIO pin connected to DS18B20 data line
LED_PIN        = 2       # onboard LED (active LOW on most ESP32 boards)
SEND_INTERVAL  = 60      # seconds between readings
DEEP_SLEEP     = False   # set True to use deep sleep between readings

# ── Setup ─────────────────────────────────────────────────────────────────────
led = machine.Pin(LED_PIN, machine.Pin.OUT)

def blink(n=1, ms=100):
    for _ in range(n):
        led.value(0); time.sleep_ms(ms)
        led.value(1); time.sleep_ms(ms)

def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if wlan.isconnected():
        return wlan
    print("Connecting to WiFi...")
    wlan.connect(WIFI_SSID, WIFI_PASS)
    for _ in range(20):
        if wlan.isconnected():
            print("WiFi connected:", wlan.ifconfig()[0])
            blink(3, 80)
            return wlan
        time.sleep(1)
    raise OSError("WiFi connect timeout")

def read_temperature():
    ow  = onewire.OneWire(machine.Pin(DS18B20_PIN))
    ds  = ds18x20.DS18X20(ow)
    roms = ds.scan()
    if not roms:
        raise RuntimeError("No DS18B20 found")
    ds.convert_temp()
    time.sleep_ms(750)          # conversion time
    return ds.read_temp(roms[0])

def send_reading(temp, wlan):
    # Read battery level if ADC available (optional — remove if not wired)
    battery_pct = None
    try:
        adc = machine.ADC(machine.Pin(34))
        adc.atten(machine.ADC.ATTN_11DB)
        raw = adc.read()
        # 3.3 V ref, divider: 100k+100k → full = 4096 → 4.2 V = 100%
        voltage = (raw / 4096) * 3.3 * 2
        battery_pct = max(0, min(100, int((voltage - 3.0) / (4.2 - 3.0) * 100)))
    except Exception:
        pass

    payload = {
        "sensor_id":     SENSOR_ID,
        "client_id":     CLIENT_ID,
        "temperature":   round(temp, 2),
        "battery_level": battery_pct,
    }
    headers = {"Content-Type": "application/json"}
    resp = urequests.post(SERVER_URL, data=json.dumps(payload), headers=headers, timeout=10)
    status = resp.json().get("status", "?")
    resp.close()
    return status

# ── Main loop ─────────────────────────────────────────────────────────────────

def run():
    wlan = connect_wifi()
    while True:
        try:
            temp   = read_temperature()
            status = send_reading(temp, wlan)
            print(f"Sent {temp:.2f}°C → {status}")
            blink(1 if status == "ok" else 3)
        except OSError as e:
            print("Network error:", e)
            try:
                wlan = connect_wifi()
            except Exception:
                pass
            blink(5, 200)
        except Exception as e:
            print("Error:", e)
            blink(2, 300)

        if DEEP_SLEEP:
            machine.deepsleep(SEND_INTERVAL * 1000)
        else:
            time.sleep(SEND_INTERVAL)

run()
