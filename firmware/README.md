# Polarix — ESP32 Sensor Firmware

## Hardware required

| Part | Notes |
|------|-------|
| ESP32 dev board | Any variant (WROOM, WROVER, etc.) |
| DS18B20 temperature sensor | Waterproof probe recommended for cold chain use |
| 4.7 kΩ resistor | Pull-up between DS18B20 DATA and 3.3 V |

## Wiring

```
DS18B20         ESP32
─────────────────────
VCC  ──────── 3.3 V
GND  ──────── GND
DATA ──────── GPIO 4  (change DS18B20_PIN if needed)
               │
             4.7 kΩ
               │
            3.3 V (pull-up)
```

## Flash MicroPython

1. Download the latest MicroPython firmware for ESP32:
   https://micropython.org/download/ESP32_GENERIC/

2. Install esptool:
   ```
   pip install esptool
   ```

3. Erase and flash:
   ```
   esptool.py --chip esp32 --port COM3 erase_flash
   esptool.py --chip esp32 --port COM3 write_flash -z 0x1000 ESP32_GENERIC-v1.xx.bin
   ```
   Replace `COM3` with your port (`/dev/ttyUSB0` on Linux/Mac).

## Upload the firmware script

Use [Thonny IDE](https://thonny.org) or `mpremote`:

```
pip install mpremote
mpremote connect COM3 cp esp32_sensor.py :main.py
```

The script runs automatically on boot when saved as `main.py`.

## Configure

Edit the top of `esp32_sensor.py`:

```python
WIFI_SSID   = "your_network_name"
WIFI_PASS   = "your_password"
SERVER_URL  = "https://your-polarix-server.com/reading"
CLIENT_ID   = "your_client_id"      # must match your Polarix account
SENSOR_ID   = "sensor_01"           # unique name for this sensor
DS18B20_PIN = 4                     # GPIO pin for DS18B20 data line
SEND_INTERVAL = 60                  # seconds between readings
DEEP_SLEEP  = False                 # True = deep sleep (lower battery use)
```

## LED status

| Pattern | Meaning |
|---------|---------|
| 1 short blink | Reading sent OK |
| 3 quick blinks | Alert state (breach/alarm) |
| 3 slow blinks on startup | WiFi connected |
| 5 blinks | Network error — retrying |

## Tips

- **Deep sleep**: set `DEEP_SLEEP = True` for battery-powered deployments.
  The ESP32 will wake every `SEND_INTERVAL` seconds, send a reading, then sleep.
- **GPS**: add a GPS module (e.g. NEO-6M via UART) and extend the payload with `lat`/`lng` fields.
- **Multiple sensors**: run multiple DS18B20 on the same OneWire bus; scan `roms` list and send one reading per device using a unique `sensor_id` for each.
