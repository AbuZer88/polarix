# Polarix — Hardware Reference

## Hardware Stack

Polarix is built around two Teltonika devices per vehicle:

| Device | Model | Role | Price |
|---|---|---|---|
| GPS Tracker / BLE Gateway | Teltonika FMB920 or FMM920 | Sends GPS position + relays EYE Sensor temperature over GSM | ~€45 |
| Temperature Sensor | Teltonika EYE Sensor (Blue) | EN12830-certified BLE temperature/humidity logger | ~€35 |

**Total per vehicle: ~€80**

---

## How Data Flows

```
EYE Sensor (BLE) ──→ FMB920 (BLE gateway) ──GSM──→ Polarix API
                                                    POST /teltonika/http  (Railway / cloud)
                                              OR    TCP port 8005         (VPS / local)
```

1. EYE Sensor broadcasts temperature over BLE every ~10 seconds.
2. FMB920 reads the EYE Sensor BLE advertisement and stores it as IO ID 72.
3. FMB920 sends a data record to the Polarix server (HTTP or TCP Codec 8).
4. Backend stores the reading, evaluates alarm rules, dispatches alerts.

---

## FMB920 Configuration — HTTP Mode (Railway / Cloud Deployments)

Use this mode when your Polarix server is on Railway or any platform that only 
exposes HTTP/HTTPS ports (not raw TCP).

**In Teltonika Configurator:**

1. Open **GPRS** → **Data Sending**
2. Set **Protocol**: `HTTP/HTTPS`
3. Set **Server URL**: `https://<your-app>.railway.app/teltonika/http`
4. Set **HTTP Method**: `POST`
5. Under **HTTP Headers**, add:
   - Header name: `X-Teltonika-Token`
   - Header value: `<your TELTONIKA_HTTP_TOKEN from .env>`
6. Set **Send period**: `60` seconds (or your preferred interval)
7. Under **Records settings**, enable **Send Records on Connect**

**IO Elements to enable (Data Acquisition → IO):**

| IO ID | Name | Enable in | Notes |
|---|---|---|---|
| 72 | BLE Temperature 1 | All records | Signed int16, value ÷ 10 = °C |
| 113 | Battery Level | All records | uint8, 0–100 % |
| 21 | GSM Signal | On Change | Optional, for connectivity monitoring |
| 68 | Dallas Temperature 1 | All records | Only if using wired probe instead of BLE |

**EYE Sensor BLE pairing in FMB920:**

Under **Bluetooth** → **BLE Devices**:
- Enable BLE scanning
- Add EYE Sensor MAC address (found on the label or via Teltonika app)
- Set **BLE Input ID**: 1 (maps to IO ID 72 for temperature)
- Save and send configuration to device (requires RMS or USB)

---

## FMB920 Configuration — TCP Codec 8 Mode (VPS / Local Deployments)

Use this mode when running Polarix on a VPS or local machine with a public IP 
and port 8005 open.

**In Teltonika Configurator:**

1. Open **GPRS** → **Data Sending**
2. Set **Protocol**: `TCP`
3. Set **Server IP/Domain**: `<your-server-ip-or-domain>`
4. Set **Server Port**: `8005`
5. Set **Data Protocol**: `Codec 8` (or `Codec 8 Extended` for more IO slots)
6. Set **Send period**: `60` seconds
7. Enable **Records on Connect**

The backend TCP server in `backend/teltonika.py` handles the IMEI handshake and 
Codec 8 / 8E parsing automatically. No additional setup required.

---

## Registering a Device in Polarix Admin

Before a device can send data, it must be registered:

1. Log into the admin panel (`/dashboard/admin.html`)
2. Go to **GPS Devices**
3. Enter the device IMEI (printed on the label, 15 digits)
4. Enter the **Client ID** that owns this device
5. Optionally enter the **RMS Device ID** (numeric ID from the Teltonika RMS portal) 
   — required only if you want OTA EYE Sensor configuration pushes via the Reassign page
6. Click **Register**

The backend auto-derives a `sensor_id` from the IMEI tail (e.g. `gps-514701`) if you 
leave the field blank.

---

## Teltonika EYE Sensor Notes

- Model: **EYE Sensor Blue** (BTSMP1)
- Certification: EN12830 (pharmaceutical cold chain compliant)
- Temperature range: −40°C to +85°C, accuracy ±0.5°C
- BLE range: ~30 m line of sight from FMB920
- Battery: CR2032, ~2 years at 10-second intervals
- The EYE Sensor MAC address must be:
  1. Registered in the Polarix admin (EYE Sensors page)
  2. Configured in the FMB920 BLE whitelist (via Teltonika Configurator or RMS)
  3. Paired to a vehicle by the client (Settings → Vehicle Assignments)

---

## Teltonika RMS (Remote Management System)

RMS allows over-the-air configuration of FMB920 devices. Polarix uses the RMS API 
to push updated EYE Sensor BLE MAC whitelists when sensors are reassigned between vehicles.

To enable:
1. Register your FMB920 devices in the RMS portal (rms.teltonika-networks.com)
2. Get a RMS API token (Profile → API Tokens)
3. Add `TELTONIKA_RMS_TOKEN=<token>` to your `.env`
4. When registering a GPS device in the admin panel, enter the RMS Device ID 
   (the numeric ID shown in the RMS device list)

Without RMS token, EYE Sensor reassignment still works in Polarix (the DB is updated) 
but the FMB920 BLE whitelist must be updated manually via USB or RMS web UI.

---

## IO ID Reference

| ID | Parameter | Type | Scale | Notes |
|---|---|---|---|---|
| 72 | BLE Temperature (EYE Sensor) | int16 signed | ÷ 10 = °C | Primary temp source |
| 68 | Dallas/1-Wire Temperature | int16 signed | ÷ 10 = °C | Wired probe alternative |
| 113 | Battery Level | uint8 | Direct % | Device internal battery |
| 21 | GSM Signal Strength | uint8 | Direct | 0–5 bars |
| 1 | Digital Input 1 | uint8 | 0/1 | Door sensor (if wired) |
| 200–203 | BLE Sensor 1–4 | varies | — | Extended BLE data slots |
