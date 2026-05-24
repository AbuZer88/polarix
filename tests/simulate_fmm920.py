#!/usr/bin/env python3
"""
Polarix -- FMM920 / FMB920 HTTP payload simulator
==================================================

Sends realistic Teltonika HTTP payloads to POST /teltonika/http.

What it does
------------
1. Sends 15 normal GPS + temperature readings along a truck route in Almeria
   (Puerto de Almeria -> city centre -> N-340 -> Roquetas de Mar)
2. Sends a door-open "breach start" reading (temp spikes to 11.5 C)
3. Sends a "breach trigger" reading 6 min later (12.0 C, delay_mins=5 exceeded)
   -> this fires send_alert_all() -> real WhatsApp / email if contacts are configured

Pre-requisites
--------------
  - Backend is running (default: http://localhost:8080)
  - The IMEI is registered in the admin panel (GPS Devices page)
  - The client has:
      - at least one active alarm rule (any min/max that 11.5 C would breach)
      - at least one alert contact (WhatsApp / email)
  - Optional: TELTONIKA_HTTP_TOKEN set in .env (script reads it automatically)

Usage
-----
  python tests/simulate_fmm920.py [options]

  --imei        FMM920/FMB920 IMEI registered in admin  (default: 352656100001234)
  --host        Backend base URL                         (default: http://localhost:8080)
  --token       X-Teltonika-Token override               (default: read from .env)
  --delay       Seconds between normal readings          (default: 1.5)
  --breach-temp Breach temperature in degrees C          (default: 11.5)
  --eye-mac     EYE Sensor MAC to show in readings       (informational only)
  --no-breach   Send normal readings only -- skip breach

Examples
--------
  # Basic run (IMEI 352656100001234, local server)
  python tests/simulate_fmm920.py

  # Custom IMEI and host
  python tests/simulate_fmm920.py --imei 123456789012345 --host https://myapp.railway.app

  # Skip the breach (just populate GPS track)
  python tests/simulate_fmm920.py --no-breach
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv

# -- Terminal colours ----------------------------------------------------------
def _c(code, text):
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

def ok(msg):   print(_c("32", f"  [+] {msg}"))
def err(msg):  print(_c("31", f"  [!] {msg}"))
def info(msg): print(_c("36", f"   .  {msg}"))
def warn(msg): print(_c("33", f"  [!] {msg}"))
def hdr(msg):  print(_c("1;34", f"\n{'-'*55}\n  {msg}\n{'-'*55}"))
def sep():     print(_c("90", "  " + "-" * 53))


# -- GPS route: Almeria truck delivery circuit ---------------------------------
#
#  Puerto de Almeria -> city centre -> N-340 west -> Roquetas de Mar -> return
#  Coordinates verified on OSM; route is a plausible refrigerated van delivery.
#
ROUTE = [
    # (lat, lng, speed_kmh, note)
    (36.8304, -2.4597,  0, "Puerto de Almeria - loading bay"),
    (36.8382, -2.4640, 22, "Paseo de Almeria - city centre"),
    (36.8400, -2.4727, 18, "Mercado Central area"),
    (36.8357, -2.4840, 31, "Ronda Sur / A-7 ramp"),
    (36.8272, -2.5047, 68, "N-340 westbound - clear road"),
    (36.8251, -2.5252, 71, "Viator junction"),
    (36.8219, -2.5470, 73, "La Canada commercial area"),
    (36.8183, -2.5624, 69, "San Agustin de la Laguna"),
    (36.8102, -2.5773, 64, "Roquetas Norte interchange"),
    (36.7923, -2.6048, 42, "Approaching Roquetas de Mar"),
    (36.7654, -2.6155,  5, "Roquetas de Mar - delivery stop"),
    (36.7654, -2.6155,  0, "At delivery - engine idle"),
    (36.7847, -2.5991, 38, "Return - A-394 northbound"),
    (36.8023, -2.5823, 55, "Coast road back to Almeria"),
    (36.8304, -2.4597,  0, "Back at Puerto de Almeria"),
]

# -- Normal cold-chain temperatures (deg C) for each waypoint -----------------
#
#  Refrigerated van set-point: 4 C.  Slight rise when doors open at delivery.
#
NORMAL_TEMPS = [
    4.2, 4.5, 4.3, 4.7, 4.8,
    4.9, 5.0, 5.1, 5.2, 5.0,
    5.5, 5.8,                  # temp creeping up at delivery stop (door opened briefly)
    5.4, 5.1, 4.9,             # cooling back on return
]

assert len(NORMAL_TEMPS) == len(ROUTE), "ROUTE and NORMAL_TEMPS must be same length"


# -- Payload builder -----------------------------------------------------------

def _temp_to_avl(celsius: float) -> int:
    """Convert float deg C to Teltonika AVL IO-72 int16 encoding (value x 10)."""
    raw = round(celsius * 10)
    if raw < 0:
        raw = raw & 0xFFFF   # two's complement uint16
    return raw


def build_payload(imei: str, records: list[dict]) -> dict:
    """
    Build a Teltonika HTTP JSON payload.

    Each record dict must have:
      timestamp  -- datetime object (UTC)
      lat, lng   -- float
      speed      -- int (km/h)
      temp_c     -- float (deg C); omit or None to skip temperature element
      battery    -- int (0-100 %)
      satellites -- int
    """
    out_records = []
    for r in records:
        elements = [{"id": 113, "value": r.get("battery", 78)}]
        if r.get("temp_c") is not None:
            elements.insert(0, {"id": 72, "value": _temp_to_avl(r["temp_c"])})

        out_records.append({
            "timestamp": int(r["timestamp"].timestamp()),
            "gps": {
                "latitude":   r["lat"],
                "longitude":  r["lng"],
                "speed":      r.get("speed", 0),
                "satellites": r.get("satellites", 8),
            },
            "elements": elements,
        })
    return {"deviceId": imei, "records": out_records}


# -- HTTP sender ---------------------------------------------------------------

def send(host: str, imei: str, records: list[dict],
         token: str = "", timeout: int = 10) -> dict:
    url = host.rstrip("/") + "/teltonika/http"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Teltonika-Token"] = token
    payload = build_payload(imei, records)
    resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# -- Main ----------------------------------------------------------------------

def main():
    # Load .env from project root (two dirs up from tests/)
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)

    parser = argparse.ArgumentParser(
        description="Simulate FMM920 HTTP payloads for Polarix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--imei",        default="352656100001234",
                        help="FMM920 IMEI registered in admin (default: 352656100001234)")
    parser.add_argument("--host",        default="http://localhost:8080",
                        help="Backend base URL (default: http://localhost:8080)")
    parser.add_argument("--token",       default=os.getenv("TELTONIKA_HTTP_TOKEN", ""),
                        help="X-Teltonika-Token (default: read from .env)")
    parser.add_argument("--delay",       type=float, default=1.5,
                        help="Seconds between normal readings (default: 1.5)")
    parser.add_argument("--breach-temp", type=float, default=11.5,
                        help="Breach temperature in degrees C (default: 11.5)")
    parser.add_argument("--no-breach",   action="store_true",
                        help="Send normal readings only -- skip the breach sequence")
    parser.add_argument("--eye-mac",     default="",
                        help="EYE Sensor MAC (informational; must be assigned to IMEI in admin)")
    args = parser.parse_args()

    hdr("Polarix -- FMM920 HTTP Simulator")
    info(f"Target   : {args.host}")
    info(f"IMEI     : {args.imei}")
    info(f"Token    : {'(set)' if args.token else '(none)'}")
    if args.eye_mac:
        info(f"EYE MAC  : {args.eye_mac}")
    info(f"Delay    : {args.delay}s between readings")
    if not args.no_breach:
        info(f"Breach   : {args.breach_temp} C  (alarm fires after >= delay_mins in range)")

    # -- Health check ----------------------------------------------------------
    sep()
    print()
    info("Checking backend health...")
    try:
        r = requests.get(args.host.rstrip("/") + "/health", timeout=5)
        d = r.json()
        ok(f"Backend  : {d.get('app', '?')} v{d.get('version', '?')}  [{d.get('environment', '?')}]")
    except Exception as e:
        err(f"Cannot reach backend at {args.host}: {e}")
        err("Start the backend first:  uvicorn backend.main:app --reload --port 8080")
        sys.exit(1)

    # -- Normal readings -------------------------------------------------------
    hdr(f"Phase 1 -- Normal readings  ({len(ROUTE)} waypoints)")
    print()

    now = datetime.now(timezone.utc)

    total_sent = 0
    for i, ((lat, lng, speed, note), temp) in enumerate(zip(ROUTE, NORMAL_TEMPS)):
        ts = now - timedelta(minutes=(len(ROUTE) - i) * 3)
        record = {
            "timestamp":  ts,
            "lat":        lat,
            "lng":        lng,
            "speed":      speed,
            "temp_c":     temp,
            "battery":    78,
            "satellites": 9 if speed > 0 else 7,
        }
        try:
            result = send(args.host, args.imei, [record], token=args.token)
            accepted = result.get("accepted", 0)
            status_str = _c("32", "[+]") if accepted == 1 else _c("31", "[!]")
            temp_avl = _temp_to_avl(temp)
            print(f"  {status_str} [{i+1:02d}/{len(ROUTE)}] "
                  f"{lat:.4f},{lng:.4f}  "
                  f"{_c('36', f'{temp:+.1f} C')} (AVL={temp_avl})  "
                  f"{speed:3d} km/h  {_c('90', note)}")
            total_sent += accepted
        except requests.HTTPError as e:
            err(f"HTTP {e.response.status_code}: {e.response.text[:120]}")
            if e.response.status_code == 404:
                warn(f"IMEI {args.imei!r} is not registered -- add it via Admin -> GPS Devices")
            sys.exit(1)
        except Exception as e:
            err(f"Request failed: {e}")
            sys.exit(1)

        time.sleep(args.delay)

    sep()
    ok(f"Phase 1 complete -- {total_sent}/{len(ROUTE)} readings accepted")

    if args.no_breach:
        print()
        ok("--no-breach set -- skipping breach sequence. Done.")
        sys.exit(0)

    # -- Breach sequence -------------------------------------------------------
    hdr("Phase 2 -- Temperature breach  (triggers alert)")
    print()

    # Reading 1: breach starts (sets breach_since in DB)
    breach_ts_1 = datetime.now(timezone.utc)
    # Reading 2: breach confirmed -- timestamp must exceed alarm rule delay_mins (default 5)
    breach_ts_2 = breach_ts_1 + timedelta(minutes=6)

    breach_location = ROUTE[10]   # Roquetas de Mar delivery stop
    breach_lat, breach_lng, breach_speed, breach_note = breach_location

    print(_c("33", f"  Sending breach reading 1  (temp={args.breach_temp} C, sets breach_since)"))
    record_b1 = {
        "timestamp":  breach_ts_1,
        "lat":        breach_lat,
        "lng":        breach_lng,
        "speed":      breach_speed,
        "temp_c":     args.breach_temp,
        "battery":    77,
        "satellites": 7,
    }
    try:
        result = send(args.host, args.imei, [record_b1], token=args.token)
        accepted = result.get("accepted", 0)
        if accepted:
            ok(f"  Breach reading 1 accepted  "
               f"AVL={_temp_to_avl(args.breach_temp)}  "
               f"ts={breach_ts_1.strftime('%H:%M:%S')} UTC")
        else:
            warn("  Breach reading 1 was not accepted by backend")
    except Exception as e:
        err(f"Breach reading 1 failed: {e}")
        sys.exit(1)

    time.sleep(1.0)

    # Reading 2: more than delay_mins elapsed in payload timestamp -> alert fires
    breach_temp_2 = round(args.breach_temp + 0.5, 1)
    print()
    print(_c("31", f"  Sending breach reading 2  (temp={breach_temp_2} C, +6 min -> alert fires!)"))
    record_b2 = {
        "timestamp":  breach_ts_2,
        "lat":        breach_lat,
        "lng":        breach_lng,
        "speed":      breach_speed,
        "temp_c":     breach_temp_2,
        "battery":    77,
        "satellites": 7,
    }
    try:
        result = send(args.host, args.imei, [record_b2], token=args.token)
        accepted = result.get("accepted", 0)
        if accepted:
            ok(f"  Breach reading 2 accepted  "
               f"AVL={_temp_to_avl(breach_temp_2)}  "
               f"ts={breach_ts_2.strftime('%H:%M:%S')} UTC  (+6 min offset)")
        else:
            warn("  Breach reading 2 was not accepted by backend")
    except Exception as e:
        err(f"Breach reading 2 failed: {e}")
        sys.exit(1)

    # -- Summary ---------------------------------------------------------------
    hdr("Result")
    print()
    ok(f"Sent {total_sent} normal readings + 2 breach readings")
    print()
    info("If an alert fired, check:")
    info("  - Admin panel -> client profile -> Recent Alerts")
    info("  - WhatsApp / email of the configured alert contacts")
    info("  - Backend console for [alarm] log lines")
    print()
    info("If no alert fired, verify:")
    info("  - Client has an active alarm rule with min/max that 11.5 C breaches")
    warn(f"    e.g. rule: min=2 max=8 delay=5  ->  {args.breach_temp} C breaches (too_high)")
    info("  - Client has at least one alert contact (whatsapp / email)")
    info("  - TWILIO_SID / SMTP_HOST configured in .env")
    print()


if __name__ == "__main__":
    main()
