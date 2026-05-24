# Polarix — Full Project Context
*Last updated: 2026-05-24 | For use in Claude Code sessions to resume work without re-reading the whole codebase.*

---

## What This Project Is

**Polarix** is a cold-chain SaaS platform. It monitors refrigerated vehicles using Teltonika FMB920 GPS trackers paired with Teltonika EYE Sensor BLE temperature probes. A FastAPI backend stores readings, evaluates alarm rules, and dispatches alerts via WhatsApp, SMS, and Email. Two single-file HTML dashboards — one for clients, one for admins — talk to the API over JWT.

**Target market:** Refrigerated transport SMBs (1–20 trucks), food distributors, pharma couriers — Almería, Spain + MENA. Pain point: EU ATP compliance + food safety audits.

---

## Hardware

| Device | Model | Price | Identifier | Notes |
|---|---|---|---|---|
| GPS Tracker | Teltonika FMB920 | ~€45 | **IMEI** (15 digits) | Wired to vehicle. Sends GPS + relays BLE over GSM |
| Temp Sensor | Teltonika EYE Sensor | ~€35 | **mac_address** (admin), **serial_number** (client-facing) | BLE, EN12830 certified, paired with FMB920 |
| SIM Card | Any M2M SIM | ~€5 | **ICCID** (20 digits) | Inserted into FMB920. Managed in admin SIM inventory |
| Legacy ESP32 | DIY WiFi sensor | — | hardware_id | Still in DB schema; removed from primary UI flows |

**Key rule:** `serial_number` is the physical label printed on the device. This is what clients see everywhere. `mac_address` and `IMEI` are internal identifiers only — they appear in the admin panel and in Vehicles tab, never in graphs, reports, or the overview.

---

## File Structure

```
polarix/
├── backend/
│   ├── main.py              FastAPI app — all REST endpoints, DB init, alarm engine (~3500 lines)
│   ├── teltonika.py         Async TCP server (port 8005), Codec 8/8E AVL decoder (legacy/VPS only)
│   └── requirements.txt     Python dependencies
├── alerts/
│   └── notifier.py          Alert dispatch: WhatsApp (Twilio), SMS, Email (SMTP), HTML templates
├── dashboard/
│   ├── index.html           Client dashboard — single-file SPA (~4000 lines)
│   └── admin.html           Admin CRM panel — single-file SPA
├── tests/
│   └── simulate_fmm920.py   CLI simulator: pushes realistic GPS+temp payloads to /teltonika/http
├── docs/
│   └── BUSINESS.md          Business model notes (pricing, target market, MVP steps)
├── firmware/
│   └── esp32_sensor.py      Legacy ESP32 firmware (reference only — not in active use)
├── hardware/
│   └── HARDWARE.md          FMB920 Teltonika Configurator setup guide
├── .env                     Local dev secrets (gitignored — never committed)
├── .env.development         Dev env template (no real secrets)
├── .env.staging             Staging env template (fill REPLACE_WITH_* values before use)
├── .env.production          Production template (set via Railway Variables panel)
├── .env.example             Full reference of all supported env vars with descriptions
├── railway.toml             Railway build/deploy config (Nixpacks, uvicorn start command)
├── Procfile                 Heroku-style fallback: web: uvicorn backend.main:app ...
├── Makefile                 dev / staging / deploy-staging / deploy-prod targets
├── start.bat                Windows one-click local dev launcher (loads from .env)
├── CONTEXT.md               This file
├── DEPLOY.md                Step-by-step Railway production deploy checklist
└── PENDING_BUILDS.md        Scoped but not-yet-built features with implementation notes
```

---

## Environments

| Environment | Command | URL | Database | Banner |
|---|---|---|---|---|
| Local dev | `make dev` or `start.bat` | http://localhost:8080 | `canary.db` | None |
| Local staging sim | `make staging` | http://localhost:8001 | `canary_staging.db` | ⚠ Orange banner |
| Railway staging | `make deploy-staging` | https://polarix-staging.up.railway.app | `canary_staging.db` (SQLite) | ⚠ Orange banner |
| Railway production | `make deploy-prod` | https://polarix-production.up.railway.app | SQLite (upgrade to Postgres later) | None |

**GitHub repo:** https://github.com/AbuZer88/polarix (private)
**Railway project:** https://railway.com/project/ddbc68d0-7ee8-42d3-8d0e-37ed6556be2f

**Production credentials (save these securely):**
- Admin key: `polarix-admin-2026-prod`
- Teltonika HTTP token: `23aa455fbc09749b68971b9d10dfbb57`

**Staging credentials:**
- Admin key: `polarix-admin-2026-staging`
- Teltonika HTTP token: `f47b254ae23843bb75bd98e7983c4473`

**Still needed on Railway (add via Variables tab):**
- `SMTP_USER`, `SMTP_PASS` — for email alerts
- `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM` — for WhatsApp/SMS alerts

### Staging usage policy (decided 2026-05-24)

Staging is **fully built and reserved for later** — activate it when you have real paying clients on production and need a safe place to test changes without disrupting them. While you're still in pre-launch / pilot mode:

- **Workflow now:** push to `main` → Railway auto-deploys production → test there directly
- **Workflow later (once you have clients):** push to `staging` branch → test on staging URL → merge to `main` → production deploys

The staging environment on Railway will sit idle (costs nothing on free tier) until you switch to the 2-branch workflow. All infrastructure is ready: separate DB, separate secrets, separate URL, orange warning banner. No additional setup needed.

**Staging banner:** Both dashboards call `GET /health` on load. When `ENVIRONMENT=staging` the response triggers a fixed orange bar: *"⚠ STAGING ENVIRONMENT — data here is for testing only"*.

**`.env.staging` placeholders to fill before deploying staging:**
- `ADMIN_KEY`, `JWT_SECRET` (generate: `python -c "import secrets; print(secrets.token_hex(32))"`)
- `SMTP_USER`, `SMTP_PASS` (Gmail App Password)
- `TWILIO_SID`, `TWILIO_TOKEN`
- `TELTONIKA_HTTP_TOKEN`

---

## Database Schema (key tables)

| Table | Purpose |
|---|---|
| `clients` | Client accounts (id, name, email, password_hash) |
| `client_users` | Multi-user per client (sub-accounts with their own login) |
| `device_registry` | GPS devices — IMEI, serial_number, sensor_id, client_id, notes |
| `ble_sensors` | EYE sensors — mac_address, serial_number, label, client_id, battery |
| `ble_sensor_assignments` | Links EYE sensor (mac) to GPS device (IMEI) at a point in time |
| `gps_vehicle_assignments` | Links GPS (IMEI) to a plate + driver_name + notes |
| `vehicle_assignments` | Client-facing: plate, sensor_id, eye_mac, driver_name, notes |
| `sim_cards` | SIM inventory — ICCID, phone_number, carrier, plan, cost |
| `sim_assignments` | Links SIM to GPS IMEI (history preserved on change) |
| `sensor_readings` | Temperature readings — sensor_id, temperature, lat, lng, speed, timestamp |
| `sensor_health` | Latest status per sensor — last_seen, battery, rssi |
| `gps_history` | GPS track points per device — lat, lng, speed, timestamp |
| `alarm_rules` | Per-sensor rules — min_temp, max_temp, delay_mins, rule_type ('temperature'\|'speed'), speed_kmh_limit |
| `alerts` | Fired alert log — sensor_id, client_id, temperature, direction, timestamp |
| `contacts` | Alert contacts — type ('whatsapp'\|'sms'\|'email'), value |
| `thresholds` | Per-client global settings — offline_after_mins, rearm_hours, accent_color |
| `sensor_colors` | Per-client, per-sensor hex color for chart rendering |
| `sensor_inventory` | Almacén (warehouse) inventory — items, serial, status, notes |
| `assignment_history` | Full audit trail of sensor→vehicle assignments |

---

## Backend: Key Endpoints

**Auth**
- `POST /auth/login` — client login → JWT
- `POST /auth/admin_login` — admin login → JWT

**Client data**
- `GET /sensors/{client_id}` — current readings + status for all sensors
- `GET /gps_devices/{client_id}` — GPS devices with serial_number, plate, last_seen
- `GET /ble_sensors/{client_id}` — EYE sensors with serial_number, label, battery
- `GET /chart/{client_id}?sensor_id=&days=7&from_dt=&to_dt=` — chart data; x-axis `dd/mm HH:MM`
- `GET /map/{client_id}` — current positions for all GPS devices
- `GET /gps_history/{client_id}?imei=&hours=24` — GPS track for map replay
- `GET /alerts/{client_id}` — alert history
- `GET /contacts/{client_id}` — alert contacts
- `POST /contacts/{client_id}` — add contact (type: whatsapp|sms|email)
- `DELETE /contacts/{client_id}/{id}`
- `GET /alarm_rules/{client_id}` — alarm rules (includes rule_type, speed_kmh_limit)
- `POST /alarm_rules/{client_id}` — create rule
- `DELETE /alarm_rules/{client_id}/{id}`
- `GET /vehicle_assignments/{client_id}` — current plate/driver/sensor assignments
- `POST /vehicle_assignments/{client_id}` — create assignment
- `PUT /vehicle_assignments/{client_id}/{id}` — update assignment
- `DELETE /vehicle_assignments/{client_id}/{id}` — unassign
- `GET /export/{client_id}?sensor_id=&from_dt=&to_dt=` — CSV export

**Admin**
- `GET /admin/clients` — list all clients
- `POST /admin/clients` — create client
- `DELETE /admin/clients/{id}` — delete client + all data
- `POST /admin/clients/{id}/purge_orphans?dry_run=0|1` — delete readings for unregistered sensors
- `GET /admin/devices` — list GPS devices
- `POST /admin/register_device` — register GPS device
- `PATCH /admin/devices/{imei}` — update serial_number + notes  ← NEW
- `DELETE /admin/devices/{imei}`
- `GET /admin/ble_sensors` — list EYE sensors
- `POST /admin/ble_sensors` — register EYE sensor
- `PATCH /admin/ble_sensors/{id}` — update serial_number + label  ← NEW
- `DELETE /admin/ble_sensors/{id}`
- `GET /admin/sims` — SIM inventory
- `POST /admin/sims` — register SIM
- `POST /admin/sims/{id}/assign` — assign SIM to GPS device (dropdown modal, not prompt())
- `POST /admin/sims/{id}/unassign`
- `GET /admin/gps_vehicle_assignments` — admin view of all plate assignments
- `POST /admin/backup` — trigger SQLite backup (SQLite only)
- `GET /health` — returns app, status, version, environment

**Teltonika ingest**
- `POST /teltonika/http` — FMB920 HTTP mode payload receiver
  - Extracts GPS position, temperature (AVL IO-72), speed, battery
  - Calls `_check_temp_alarms()` → fires alerts if breach exceeds delay_mins
  - Calls `_check_speed_alarms()` → fires alert if speed_kmh > rule limit

---

## Alert System

**notifier.py** handles 4 alert types, each with a plain-text version and a dark-themed HTML email:

| Type | Function | Trigger |
|---|---|---|
| Temperature breach | `send_alert_all()` | Temp outside min/max for > delay_mins |
| Sensor offline | `send_alert_offline()` | No reading for > offline_after_mins |
| Battery low | `send_alert_battery()` | battery_level ≤ 20% |
| Speed exceeded | `send_alert_speed()` | GPS speed > speed_kmh_limit |

**Channels per contact:**
- `whatsapp` → Twilio WhatsApp API
- `sms` → Twilio SMS
- `email` → SMTP (Gmail App Password or any SMTP provider)

**Email is fully built** — only needs `SMTP_USER` + `SMTP_PASS` in `.env` to activate. See PENDING_BUILDS Item 17.

---

## Client Dashboard (index.html) — Key Functions

| Function | What it does |
|---|---|
| `_buildMergedDevices()` | Merges GPS + EYE + fleet data into one row per vehicle |
| `_prettyLabel(sid)` | Converts sensor_id → "Plate (Serial)" for chart labels, alerts, offline banner |
| `cleanGpsSerial(raw)` | Strips "gps-" prefix to avoid "GPS-gps-X" double prefix |
| `renderDeviceTiles()` | Overview sensor cards — shows GPS serial, EYE serial, temp, status |
| `renderFleetTable()` | Fleet tab table — plate, GPS serial, EYE serial, temp, speed |
| `loadSensorAssignTree()` | Vehicles tab — professional vehicle cards (plate, serial, driver, battery) + assign form |
| `loadAlarmRules()` | Settings alarm rules — shows temperature or speed rules with correct badge |
| `createAlarmRule()` | Creates temp or speed rule from form |
| `generatePdfForDays()` | PDF compliance report — plate + serial in readings table, no mac_address |
| `loadContacts()` | Alert contacts list with WhatsApp/SMS/Email icons |
| `addContact()` | Add contact — type selector updates placeholder and hint text |
| `renderSensorColorPickers()` | Settings — per-sensor color pickers (uses plate+serial as label) |
| `showTab(name)` | Tab switcher — triggers renderSensorColorPickers() on settings tab |

**mac_address is never shown to clients.** All display falls back to: `serial_number || label || "EYE Sensor"`. mac_address is only used internally for data lookups (`_eyeSensCache.find(e => e.mac_address === sid)`).

---

## Admin Panel (admin.html) — Key Features

- **GPS Devices table** — IMEI, serial, sensor_id, client, plate, registered date. Has ✏️ edit button (opens modal to set serial_number + notes) and ✕ delete.
- **EYE Sensors table** — mac, serial, label, client, paired GPS, battery, last seen. Has ✏️ edit (serial + label) and ✕ delete.
- **SIM Cards page** — full inventory with assign/unassign. "Assign…" opens a modal with dropdown of registered GPS devices (not a raw browser prompt).
- **Vehicles tab** — GPS vehicle assignments (plate + driver per IMEI).
- **Clients tab** — create/delete clients, purge orphan readings.
- **Simulator** — push fake GPS + temperature readings for any registered device. Route: Almería → Roquetas de Mar.
- **Almacén** — warehouse/stock inventory for hardware items.
- **Edit modal** (shared) — `#edit-modal-overlay` — used by both GPS and EYE edit buttons.
- **SIM assign modal** — `#sim-assign-overlay` — populated with registered GPS devices dropdown.
- **Staging banner** — `#staging-banner` — shown when `/health` returns `environment: staging`.

---

## Test / QA Workflow

**Simulator CLI** (`tests/simulate_fmm920.py`):
```bash
# Basic: 15 normal readings + breach that fires an alert
python tests/simulate_fmm920.py --imei YOUR_IMEI --host http://localhost:8080

# Staging:
python tests/simulate_fmm920.py --imei YOUR_IMEI --host https://polarix-staging.up.railway.app

# GPS track only, no breach
python tests/simulate_fmm920.py --imei YOUR_IMEI --no-breach
```

**Pre-requisites for simulator to fire an alert:**
1. IMEI registered in Admin → GPS Devices
2. Client has an alarm rule with min/max that 11.5°C breaches (e.g. min=2, max=8)
3. Client has at least one alert contact (whatsapp or email)
4. SMTP or Twilio credentials set in `.env`

**Fix deploy workflow:**
```
Bug found on prod → fix locally (make dev) → test locally → make staging →
test on staging URL → confirm staging banner visible → make deploy-staging →
verify on Railway staging URL → make deploy-prod (requires manual confirm)
```

---

## Pending Items (see PENDING_BUILDS.md for full detail)

| # | Item | Size |
|---|---|---|
| 4 | PDF Report with Embedded Map | Large |
| 9 | Reconsider "Recent Readings" section | Small |
| 10 | Smarter PDF/CSV Export (multi-sensor, column chooser) | Medium |
| 11 | Historical Chart Tooltip with City Name | Medium |
| 14 | Vehicle Icons / Telematics Look | Large |
| 15 | Admin Panel CRM Redesign (client profile pages) | Large |
| 16 | Vehicle/Sensor Assignment Panel Redesign | Medium |
| 17 | **SMTP Email — add credentials to .env** (5 min) | Trivial |

---

## Critical Bugs Fixed (2026-05-24)

- **index.html API URL** was hardcoded to `http://localhost:8080` — fixed to dynamic (`window.location.origin` in production, localhost fallback in dev). This was a production blocker — the dashboard would never have connected to Railway.

---

## Known Good State (as of 2026-05-24)

- All client-facing views show `serial_number` — no mac_address, no raw sensor_id
- Count label shows correct "X online · Y offline" (GPS devices only, not EYE)
- Chart x-axis shows `dd/mm HH:MM` (date + time)
- PDF report includes Matrícula column; sensor column shows serial not sensor_id
- Speed alarms: DB columns, backend check, notifier, frontend UI all complete
- Alarm rules: support temperature + speed types, correct badge in list
- Settings: accent color + sensor colors in Ajustes tab (moved from Profile modal)
- BLE sensors: hidden from Settings tab (managed only via Vehicles tab)
- Vehicles tab: professional vehicle cards (GPS serial, EYE serial, plate, status)
- Admin: ✏️ edit buttons on GPS + EYE tables for post-registration serial edits
- Admin: SIM assign uses dropdown modal (not `prompt()`)
- Staging: orange banner in both dashboards when ENVIRONMENT=staging
- Offline/alert banner: shows plate+serial, not raw sensor_id
- Alert history: uses `_prettyLabel()` for all entries; speed alerts show km/h + 🚗 badge
