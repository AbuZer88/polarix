# 🌡️ Polarix

**Low-cost temperature monitoring & alert system for cold-chain logistics.**
Target: SMB refrigerated transport (Spain, MENA). No enterprise subscription needed.

---

## What This Does
- Reads temperature from cheap IoT sensors inside trailers/fridges
- Sends WhatsApp/SMS/email alert the moment a threshold is breached
- Logs all readings to a web dashboard with live fleet map
- Exports EN 12830 compliant PDF reports for cold-chain audits
- Works with or without GPS; supports multi-sensor fleets

---

## Project Structure

```
polarix/
├── backend/          # FastAPI server — receives data, stores it, triggers alerts
├── alerts/           # WhatsApp/SMS/email alert engine (Twilio + SMTP)
├── dashboard/        # Web dashboard (index.html = client, admin.html = admin)
├── firmware/         # ESP32 MicroPython sensor firmware
└── docs/             # Business model, pricing, client onboarding guide
```

---

## Stack
- **Hardware:**   ESP32 + DS18B20 probe (see `firmware/`)
- **Firmware:**   MicroPython
- **Backend:**    Python (FastAPI) + SQLite (dev) / PostgreSQL (prod)
- **Security:**   bcrypt passwords, JWT sessions (24h), slowapi rate limiting
- **Alerts:**     Twilio (WhatsApp/SMS) + SMTP email
- **Dashboard:**  Vanilla HTML/JS — Leaflet.js map, Chart.js charts
- **Hosting:**    Railway (see `railway.toml`)

---

## Quick Start

```bash
# 1. Copy env file and fill in required values
cp .env.example .env
# Set ADMIN_KEY and JWT_SECRET — server won't start without them

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Run
uvicorn backend.main:app --reload --port 8080

# 4. Open dashboard
open http://localhost:8080/dashboard
```

---

## MVP Goal
5 sensors deployed → real alerts firing → one paying client.
