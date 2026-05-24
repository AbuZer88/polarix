"""
Polarix - Backend Server
"""
import asyncio
import csv
import hashlib
import secrets
import io
import math
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

import bcrypt as _bcrypt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from pydantic import BaseModel, Field, validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import create_engine, text

load_dotenv()

# ── Sentry error tracking (optional) ─────────────────────────────────────────
# When SENTRY_DSN is set, all unhandled exceptions are reported. When empty,
# this is a complete no-op — Sentry is not even initialized.
_SENTRY_DSN = os.getenv("SENTRY_DSN", "").strip()
if _SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        sentry_sdk.init(
            dsn=_SENTRY_DSN,
            environment=os.getenv("ENVIRONMENT", "development"),
            release=os.getenv("APP_VERSION", "polarix@2.0.0"),
            # Capture 10% of transactions in prod, all in dev
            traces_sample_rate=float(os.getenv("SENTRY_TRACES_RATE", "0.1")),
            # Don't send PII (user IPs, headers with secrets, etc.)
            send_default_pii=False,
            integrations=[FastApiIntegration()],
        )
        print(f"[SENTRY] initialized for environment={os.getenv('ENVIRONMENT','development')}")
    except Exception as e:
        print(f"[SENTRY] init failed: {e}")

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alerts.notifier import send_alert_all, send_alert_offline, send_alert_battery

# ── Config ──────────────────────────────────────────────────────────────────

DB_PATH     = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "canary.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}")
JWT_SECRET  = os.getenv("JWT_SECRET", "")
ADMIN_KEY   = os.getenv("ADMIN_KEY", "")
RMS_TOKEN            = os.getenv("TELTONIKA_RMS_TOKEN", "")
RMS_BASE             = "https://rms.teltonika-networks.com/api/v1"
TELTONIKA_HTTP_TOKEN = os.getenv("TELTONIKA_HTTP_TOKEN", "")
STRIPE_SECRET_KEY       = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_STARTER    = os.getenv("STRIPE_PRICE_ID_STARTER", "")
STRIPE_PRICE_GROWTH     = os.getenv("STRIPE_PRICE_ID_GROWTH", "")
STRIPE_PRICE_FLEET      = os.getenv("STRIPE_PRICE_ID_FLEET", "")
VERSION     = "2.0.0"

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)

limiter = Limiter(key_func=get_remote_address)


# ── Auth helpers ─────────────────────────────────────────────────────────────

def _hash_new(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()

def _verify(pw: str, stored: str) -> bool:
    if stored.startswith("$2"):
        return _bcrypt.checkpw(pw.encode(), stored.encode())
    return hashlib.sha256(pw.encode()).hexdigest() == stored

def _make_token(client_id: str, user_id: Optional[int] = None,
                request: Optional[Request] = None) -> str:
    """Issue a JWT and record an entry in user_sessions for revocation support.
    user_id is None for legacy single-user (client_id) logins."""
    jti = secrets.token_hex(8)
    issued = datetime.utcnow()
    expires = issued + timedelta(hours=24)
    payload = {"sub": client_id, "exp": expires, "jti": jti}
    if user_id is not None:
        payload["uid"] = user_id
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    ip = ""
    ua = ""
    if request is not None:
        try:
            ip = request.client.host if request.client else ""
            ua = (request.headers.get("user-agent") or "")[:200]
        except Exception:
            pass
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO user_sessions (user_id,client_id,jti,issued_at,expires_at,ip,user_agent)
                VALUES (:uid,:cid,:jti,:ts,:exp,:ip,:ua)"""),
                {"uid": user_id, "cid": client_id, "jti": jti,
                 "ts": issued.isoformat(), "exp": expires.isoformat(),
                 "ip": ip, "ua": ua})
    except Exception as e:
        # Don't block login if session table write fails; just log
        print(f"[SESSION] failed to record: {e}")
    return token

def _check_client(request: Request, client_id: str) -> str:
    # Admin key bypass: allows admin panel to view any client's data
    if ADMIN_KEY and request.headers.get("X-Admin-Key", "") == ADMIN_KEY:
        return client_id
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(401, "Session expired — please log in again")
    if payload.get("sub") != client_id:
        raise HTTPException(403, "Access denied")
    # Revocation check: if this token has a jti and the matching session was
    # revoked, reject. Tokens issued before sessions existed have no jti and
    # pass through (backward compat).
    jti = payload.get("jti")
    if jti:
        try:
            with engine.connect() as conn:
                row = conn.execute(text(
                    "SELECT revoked_at FROM user_sessions WHERE jti=:jti"),
                    {"jti": jti}).fetchone()
            if row and row[0]:
                raise HTTPException(401, "Session was revoked")
        except HTTPException:
            raise
        except Exception:
            pass  # never block on a session-table read failure
    return payload["sub"]


def _current_user_id(request: Request) -> Optional[int]:
    """Return the user_id claim from a Bearer JWT, or None for legacy/admin-key auth."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
        return payload.get("uid")
    except JWTError:
        return None

def _check_admin(request: Request):
    key = request.headers.get("X-Admin-Key", "")
    if key != ADMIN_KEY:
        raise HTTPException(403, "Forbidden")


# ── DB init ───────────────────────────────────────────────────────────────────

def init_db():
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id TEXT, client_id TEXT,
            temperature REAL, timestamp TEXT,
            lat REAL DEFAULT NULL, lng REAL DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS thresholds (
            client_id TEXT PRIMARY KEY,
            min_temp REAL DEFAULT 2.0, max_temp REAL DEFAULT 8.0,
            alert_active INTEGER DEFAULT 0, reactivate INTEGER DEFAULT 1,
            alert_delay_mins INTEGER DEFAULT 0, breach_since TEXT DEFAULT NULL,
            alarm_start_dt TEXT DEFAULT NULL, alarm_end_dt TEXT DEFAULT NULL,
            messages_sent INTEGER DEFAULT 0, offline_after_mins INTEGER DEFAULT 60)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
            UNIQUE(client_id, type, value))"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT, sensor_id TEXT,
            temperature REAL, direction TEXT, timestamp TEXT)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS sensor_health (
            sensor_id TEXT NOT NULL, client_id TEXT NOT NULL,
            plate TEXT DEFAULT '', last_seen TEXT DEFAULT NULL,
            battery_level INTEGER DEFAULT NULL,
            last_lat REAL DEFAULT NULL, last_lng REAL DEFAULT NULL,
            offline_alerted INTEGER DEFAULT 0, battery_alerted INTEGER DEFAULT 0,
            PRIMARY KEY (sensor_id, client_id))"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS sensor_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id TEXT NOT NULL, client_id TEXT NOT NULL,
            plate TEXT NOT NULL, assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL,
            driver_name TEXT DEFAULT '',
            shipment_notes TEXT DEFAULT '')"""))
        for col, defval in [("driver_name","''"), ("shipment_notes","''")]:
            try:
                conn.execute(text(f"ALTER TABLE sensor_assignments ADD COLUMN {col} TEXT DEFAULT {defval}"))
            except Exception: pass

        conn.execute(text("""CREATE TABLE IF NOT EXISTS client_passwords (
            client_id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS sensor_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hardware_id TEXT UNIQUE NOT NULL, sensor_id TEXT NOT NULL,
            client_id TEXT DEFAULT '', notes TEXT DEFAULT '',
            registered_at TEXT NOT NULL, assigned_at TEXT DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS device_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            imei TEXT UNIQUE NOT NULL,
            sensor_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            notes TEXT DEFAULT '',
            registered_at TEXT NOT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS gps_vehicle_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            imei TEXT NOT NULL,
            plate TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS alarm_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT 'Temperature Alarm',
            sensor_id TEXT DEFAULT '',
            min_temp REAL NOT NULL DEFAULT 2.0,
            max_temp REAL NOT NULL DEFAULT 8.0,
            alert_delay_mins INTEGER DEFAULT 5,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            breach_since TEXT DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate TEXT NOT NULL,
            client_id TEXT NOT NULL,
            label TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(plate, client_id))"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS ble_sensors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            label TEXT DEFAULT '',
            battery_level INTEGER DEFAULT NULL,
            last_seen TEXT DEFAULT NULL,
            registered_at TEXT NOT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS ble_sensor_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ble_sensor_id INTEGER NOT NULL,
            device_imei TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL)"""))

        # SIM cards inventory (admin-managed)
        conn.execute(text("""CREATE TABLE IF NOT EXISTS sim_cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            iccid TEXT NOT NULL UNIQUE,
            phone_number TEXT DEFAULT '',
            carrier TEXT DEFAULT '',
            plan TEXT DEFAULT '',
            status TEXT DEFAULT 'active',
            monthly_cost_eur REAL DEFAULT 0,
            activated_at TEXT DEFAULT NULL,
            expires_at TEXT DEFAULT NULL,
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL)"""))
        # SIM <-> device (FMB920) assignment history
        conn.execute(text("""CREATE TABLE IF NOT EXISTS sim_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sim_id INTEGER NOT NULL,
            imei TEXT NOT NULL,
            client_id TEXT DEFAULT '',
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL,
            notes TEXT DEFAULT '')"""))

        # ── Multi-user per client ─────────────────────────────────────────────
        # 'users' is an additional login layer on top of client_id. A client
        # always has at least 1 implicit "owner" — the one set via /auth/set_password.
        # Extra users (paid tier) are stored here with email + bcrypt password.
        # JWTs issued by /auth/user_login carry both client_id (sub) and user_id.
        conn.execute(text("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            email TEXT NOT NULL,
            name TEXT DEFAULT '',
            role TEXT DEFAULT 'viewer',
            password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            last_login TEXT DEFAULT NULL,
            UNIQUE(client_id, email))"""))
        # Active sessions — populated on every successful login, keyed by JTI
        conn.execute(text("""CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            client_id TEXT NOT NULL,
            jti TEXT NOT NULL UNIQUE,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            revoked_at TEXT DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS vehicle_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            imei TEXT NOT NULL,
            eye_mac TEXT DEFAULT '',
            plate TEXT NOT NULL,
            driver_name TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL)"""))

        conn.execute(text("""CREATE TABLE IF NOT EXISTS client_billing (
            client_id TEXT PRIMARY KEY,
            stripe_customer_id TEXT DEFAULT '',
            stripe_subscription_id TEXT DEFAULT '',
            plan TEXT DEFAULT '',
            subscription_status TEXT DEFAULT '',
            current_period_end TEXT DEFAULT '')"""))

        # Add rms_device_id to device_registry if missing
        try:
            conn.execute(text("ALTER TABLE device_registry ADD COLUMN rms_device_id TEXT DEFAULT ''"))
        except Exception: pass
        try:
            conn.execute(text("ALTER TABLE device_registry ADD COLUMN serial_number TEXT DEFAULT ''"))
        except Exception: pass
        try:
            conn.execute(text("ALTER TABLE ble_sensors ADD COLUMN serial_number TEXT DEFAULT ''"))
        except Exception: pass
        # Speed alarm support
        try:
            conn.execute(text("ALTER TABLE alarm_rules ADD COLUMN rule_type TEXT DEFAULT 'temperature'"))
        except Exception: pass
        try:
            conn.execute(text("ALTER TABLE alarm_rules ADD COLUMN speed_kmh_limit REAL DEFAULT NULL"))
        except Exception: pass
        try:
            conn.execute(text("ALTER TABLE alarm_rules ADD COLUMN in_breach INTEGER DEFAULT 0"))
        except Exception: pass

        # Migrate existing thresholds → alarm_rules (run once per client)
        try:
            thresh_rows = conn.execute(text(
                "SELECT client_id,min_temp,max_temp,alert_delay_mins FROM thresholds "
                "WHERE min_temp IS NOT NULL AND client_id NOT IN "
                "(SELECT DISTINCT client_id FROM alarm_rules)")).fetchall()
            _mts = datetime.utcnow().isoformat()
            for _cid, _mn, _mx, _dl in thresh_rows:
                conn.execute(text("""
                    INSERT INTO alarm_rules
                      (client_id,name,sensor_id,min_temp,max_temp,alert_delay_mins,status,created_at)
                    VALUES (:cid,'Default Alarm','',
                            :mn,:mx,:dl,'active',:ts)"""),
                    {"cid": _cid, "mn": _mn or 2.0, "mx": _mx or 8.0,
                     "dl": _dl or 5, "ts": _mts})
        except Exception:
            pass

        # Table-creation migrations — create missing tables on existing DBs
        conn.execute(text("""CREATE TABLE IF NOT EXISTS alarm_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT 'Temperature Alarm',
            sensor_id TEXT DEFAULT '',
            min_temp REAL NOT NULL DEFAULT 2.0,
            max_temp REAL NOT NULL DEFAULT 8.0,
            alert_delay_mins INTEGER DEFAULT 5,
            status TEXT DEFAULT 'active',
            created_at TEXT NOT NULL,
            breach_since TEXT DEFAULT NULL)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate TEXT NOT NULL,
            client_id TEXT NOT NULL,
            label TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(plate, client_id))"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS ble_sensors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            label TEXT DEFAULT '',
            battery_level INTEGER DEFAULT NULL,
            last_seen TEXT DEFAULT NULL,
            registered_at TEXT NOT NULL)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS ble_sensor_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            client_id TEXT NOT NULL,
            imei TEXT DEFAULT '',
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS vehicle_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            sensor_id TEXT NOT NULL,
            plate TEXT NOT NULL,
            driver_name TEXT DEFAULT '',
            shipment_notes TEXT DEFAULT '',
            assigned_at TEXT NOT NULL,
            unassigned_at TEXT DEFAULT NULL)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS threshold_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            min_temp REAL,
            max_temp REAL,
            alert_delay_mins INTEGER,
            offline_after_mins INTEGER,
            data_retention_years INTEGER)"""))

        # Column migrations — safe to re-run
        _migrations = {
            "readings":      [("lat","REAL","NULL"), ("lng","REAL","NULL"), ("reading_type","TEXT","'temperature'")],
            "thresholds":    [("alert_active","INTEGER","0"),("reactivate","INTEGER","1"),
                              ("alert_delay_mins","INTEGER","0"),("breach_since","TEXT","NULL"),
                              ("alarm_start_dt","TEXT","NULL"),("alarm_end_dt","TEXT","NULL"),
                              ("messages_sent","INTEGER","0"),("offline_after_mins","INTEGER","60"),
                              ("data_retention_years","INTEGER","5"),("can_import","INTEGER","0"),
                              ("max_users","INTEGER","1")],
            "sensor_health": [("plate","TEXT","''"),("last_lat","REAL","NULL"),
                              ("last_lng","REAL","NULL"),("battery_level","INTEGER","NULL"),
                              ("offline_alerted","INTEGER","0"),("battery_alerted","INTEGER","0")],
            "alarm_rules":       [("breach_since","TEXT","NULL"),("in_breach","INTEGER","0")],
            "device_registry":   [("serial_number","TEXT","''")],
            "ble_sensors":       [("serial_number","TEXT","''")],
            "ble_sensor_assignments": [("imei","TEXT","''")],
        }
        for table, cols in _migrations.items():
            for col, typ, default in cols:
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {typ} DEFAULT {default}"))
                except Exception:
                    pass

        # Migrate legacy single-contact column in thresholds
        try:
            old = conn.execute(text(
                "SELECT client_id, contact FROM thresholds WHERE contact IS NOT NULL AND contact != ''")).fetchall()
            for cid, contact in old:
                try:
                    conn.execute(text(
                        "INSERT OR IGNORE INTO contacts (client_id,type,value) VALUES (:cid,'whatsapp',:v)"),
                        {"cid": cid, "v": contact})
                except Exception:
                    pass
            conn.execute(text("ALTER TABLE thresholds DROP COLUMN contact"))
        except Exception:
            pass


# ── Background checker ────────────────────────────────────────────────────────

def _current_assignment(conn, sensor_id: str, client_id: str, fallback_plate: str) -> dict:
    row = conn.execute(text("""
        SELECT plate,driver_name,shipment_notes FROM sensor_assignments
        WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL
        ORDER BY assigned_at DESC LIMIT 1"""), {"sid": sensor_id, "cid": client_id}).fetchone()
    plate = (row[0] if row else None) or fallback_plate or ""
    driver = (row[1] if row else "") or ""
    notes  = (row[2] if row else "") or ""
    return {"plate": plate, "driver_name": driver, "shipment_notes": notes}

def _current_plate(conn, sensor_id: str, client_id: str, fallback: str) -> str:
    return _current_assignment(conn, sensor_id, client_id, fallback)["plate"]

def run_offline_check():
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT sh.sensor_id, sh.client_id, sh.last_seen, sh.battery_level,
                   sh.offline_alerted, sh.battery_alerted, sh.plate,
                   COALESCE(t.offline_after_mins, 60)
            FROM sensor_health sh
            LEFT JOIN thresholds t ON sh.client_id=t.client_id""")).fetchall()

    now = datetime.utcnow()
    for sensor_id, client_id, last_seen, battery, off_alerted, bat_alerted, sh_plate, offline_mins in rows:
        with engine.connect() as conn:
            contacts = [{"type": r[0], "value": r[1]} for r in conn.execute(text(
                "SELECT type,value FROM contacts WHERE client_id=:cid"), {"cid": client_id}).fetchall()]
            plate = _current_plate(conn, sensor_id, client_id, sh_plate)

        if last_seen:
            elapsed = (now - datetime.fromisoformat(last_seen)).total_seconds() / 60
            if elapsed >= offline_mins and not off_alerted and contacts:
                try:
                    send_alert_offline(contacts, sensor_id, plate, int(elapsed))
                    with engine.begin() as conn:
                        conn.execute(text(
                            "UPDATE sensor_health SET offline_alerted=1 WHERE sensor_id=:sid AND client_id=:cid"),
                            {"sid": sensor_id, "cid": client_id})
                    print(f"[OFFLINE] {sensor_id} ({int(elapsed)} min)")
                except Exception as e:
                    print(f"[OFFLINE ERROR] {e}")

        if battery is not None and battery <= 20 and not bat_alerted and contacts:
            try:
                send_alert_battery(contacts, sensor_id, plate, battery)
                with engine.begin() as conn:
                    conn.execute(text(
                        "UPDATE sensor_health SET battery_alerted=1 WHERE sensor_id=:sid AND client_id=:cid"),
                        {"sid": sensor_id, "cid": client_id})
                print(f"[BATTERY] {sensor_id} ({battery}%)")
            except Exception as e:
                print(f"[BATTERY ERROR] {e}")

async def offline_check_loop():
    while True:
        await asyncio.sleep(900)
        try:
            run_offline_check()
        except Exception as e:
            print(f"[CHECKER ERROR] {e}")


# ── Daily SQLite backup ──────────────────────────────────────────────────────
# Only runs when DATABASE_URL is sqlite. On Postgres (Railway etc.), the
# managed service handles backups, so we skip. Backup directory and retention
# are configurable via env vars.

BACKUP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backups")
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "14"))


def _is_sqlite() -> bool:
    return DATABASE_URL.startswith("sqlite")


def run_sqlite_backup() -> dict:
    """Copy canary.db to backups/canary_YYYY-MM-DD.db using SQLite's online
    backup API (safe even while the DB is in use). Returns metadata."""
    if not _is_sqlite():
        return {"status": "skipped", "reason": "not sqlite"}
    if BACKUP_RETENTION_DAYS <= 0:
        return {"status": "skipped", "reason": "BACKUP_RETENTION_DAYS=0 (disabled)"}
    import sqlite3
    os.makedirs(BACKUP_DIR, exist_ok=True)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    dest_path = os.path.join(BACKUP_DIR, f"canary_{today}.db")
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest_path)
    try:
        with dst:
            src.backup(dst)
    finally:
        src.close(); dst.close()
    size = os.path.getsize(dest_path)
    # Rotate: delete backups older than BACKUP_RETENTION_DAYS
    deleted = []
    cutoff = datetime.utcnow() - timedelta(days=BACKUP_RETENTION_DAYS)
    for fname in os.listdir(BACKUP_DIR):
        if not (fname.startswith("canary_") and fname.endswith(".db")):
            continue
        try:
            dpart = fname[len("canary_"):-3]   # "YYYY-MM-DD"
            d = datetime.strptime(dpart, "%Y-%m-%d")
            if d < cutoff:
                fp = os.path.join(BACKUP_DIR, fname)
                os.remove(fp); deleted.append(fname)
        except Exception:
            pass
    return {"status": "ok", "file": os.path.basename(dest_path),
            "size_bytes": size, "deleted_old": deleted,
            "retention_days": BACKUP_RETENTION_DAYS}


async def daily_backup_loop():
    """Run an SQLite backup once every 24h. Skips quietly on non-sqlite."""
    if not _is_sqlite() or BACKUP_RETENTION_DAYS <= 0:
        return
    # First backup ~60 seconds after startup so the server is fully up
    await asyncio.sleep(60)
    while True:
        try:
            result = run_sqlite_backup()
            print(f"[BACKUP] {result.get('status')} {result.get('file', '')} "
                  f"({result.get('size_bytes', 0):,} bytes)"
                  + (f" · deleted {len(result['deleted_old'])} old" if result.get('deleted_old') else ""))
        except Exception as e:
            print(f"[BACKUP ERROR] {e}")
        await asyncio.sleep(24 * 60 * 60)


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET env var is not set — generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
    if not ADMIN_KEY:
        raise RuntimeError("ADMIN_KEY env var is not set — set it before starting the server")
    init_db()
    from backend.teltonika import run_tcp_server
    offline_task = asyncio.create_task(offline_check_loop())
    tcp_task     = asyncio.create_task(run_tcp_server(engine))
    backup_task  = asyncio.create_task(daily_backup_loop())
    yield
    for t in (offline_task, tcp_task, backup_task):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Polarix API", version=VERSION, lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS lockdown ────────────────────────────────────────────────────────────
# In development (no CORS_ORIGINS set), allow localhost on any port for dev
# convenience. In production, set CORS_ORIGINS to a comma-separated list of
# exact origins, e.g. "https://app.polarix.es,https://polarix.es".
_cors_env = os.getenv("CORS_ORIGINS", "").strip()
if _cors_env:
    _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    _allow_origin_regex = None
else:
    # Dev default: any localhost / 127.0.0.1 port (http only — prod must opt in via CORS_ORIGINS)
    _allowed_origins = []
    _allow_origin_regex = r"^http://(localhost|127\.0\.0\.1)(:\d+)?$"
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-Key", "X-Teltonika-Token"],
)

DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

def is_in_schedule(alarm_start_dt, alarm_end_dt):
    now = datetime.utcnow()
    try:
        if alarm_start_dt and now < datetime.fromisoformat(alarm_start_dt): return False
        if alarm_end_dt   and now > datetime.fromisoformat(alarm_end_dt):   return False
    except Exception: pass
    return True


# ── Pydantic models ───────────────────────────────────────────────────────────

class Reading(BaseModel):
    sensor_id:    str            = Field(..., max_length=64)
    client_id:    str            = Field(..., max_length=64)
    temperature:  Optional[float] = None   # Optional: GPS-only readings have no temp
    lat:          Optional[float] = None
    lng:          Optional[float] = None
    battery_level: Optional[int] = None
    reading_type: Optional[str]   = None   # "gps", "temperature", or auto-detect

    @validator("sensor_id", "client_id")
    def strip_ids(cls, v): return v.strip()

class Threshold(BaseModel):
    client_id: str
    min_temp: float
    max_temp: float
    reactivate: int = 1
    alert_delay_mins: int = 0
    alarm_start_dt: str = ""
    alarm_end_dt: str = ""
    offline_after_mins: int = 60
    data_retention_years: int = 5

class Contact(BaseModel):
    type: str
    value: str

class AssignVehicle(BaseModel):
    sensor_id:       str = Field(..., max_length=64)
    plate:           str = Field(..., max_length=20)
    driver_name:     str = Field("", max_length=80)
    shipment_notes:  str = Field("", max_length=200)

    @validator("sensor_id", "plate", "driver_name", "shipment_notes")
    def strip_fields(cls, v): return v.strip()

class LoginRequest(BaseModel):
    client_id: str = Field(..., max_length=64)
    password:  str

    @validator("client_id")
    def strip_cid(cls, v): return v.strip()

class ChangePasswordRequest(BaseModel):
    client_id:    str = Field(..., max_length=64)
    password:     str
    new_password: str

    @validator("client_id")
    def strip_cid(cls, v): return v.strip()

class AdminClientCreate(BaseModel):
    client_id: str = Field(..., max_length=64)
    password:  str
    min_temp:  float = 2.0
    max_temp:  float = 8.0

    @validator("client_id")
    def strip_cid(cls, v): return v.strip()

class SensorRegister(BaseModel):
    hardware_id: str
    sensor_id:   str = Field(..., max_length=64)
    client_id:   str = Field("", max_length=64)
    notes:       str = ""

    @validator("sensor_id", "client_id", "hardware_id")
    def strip_fields(cls, v): return v.strip()

class SensorAssignToClient(BaseModel):
    client_id: str = Field(..., max_length=64)

    @validator("client_id")
    def strip_cid(cls, v): return v.strip()

class DeviceRegistryCreate(BaseModel):
    imei:          str = Field(..., max_length=20)
    sensor_id:     str = Field("", max_length=64)   # auto-derived from IMEI if blank
    client_id:     str = Field(..., max_length=64)
    serial_number: str = Field(..., min_length=1, max_length=64,
                               description="Physical device serial number — printed on the FMB920 housing")
    notes:         str = ""
    rms_device_id: str = ""

    @validator("imei", "sensor_id", "client_id", "serial_number")
    def strip_fields(cls, v): return v.strip()

class VehicleCreate(BaseModel):
    plate:     str = Field(..., max_length=20)
    client_id: str = Field(..., max_length=64)
    label:     str = ""

    @validator("plate", "client_id")
    def strip_fields(cls, v): return v.strip().upper() if v else v

class BleSensorCreate(BaseModel):
    mac_address:   str = Field(..., max_length=20)
    client_id:     str = Field(..., max_length=64)
    serial_number: str = Field(..., min_length=1, max_length=64,
                               description="Physical sensor serial number — printed on the EYE Sensor housing")
    label:         str = ""

    @validator("mac_address", "client_id", "serial_number")
    def strip_fields(cls, v): return v.strip()

class BleReassign(BaseModel):
    ble_sensor_id: int
    new_device_imei: str = Field(..., max_length=20)

    @validator("new_device_imei")
    def strip_imei(cls, v): return v.strip()

class ResetPassword(BaseModel):
    new_password: str = Field(..., min_length=4)

class SimCardCreate(BaseModel):
    iccid:            str = Field(..., min_length=10, max_length=22, description="SIM serial number (ICCID) — 19-20 digits printed on the SIM card")
    phone_number:     str = Field("", max_length=20, description="MSISDN, e.g. +34612345678")
    carrier:          str = Field("", max_length=40, description="Movistar / Orange / Vodafone / Truphone / etc.")
    plan:             str = Field("", max_length=80, description="e.g. 'M2M 100MB/month'")
    status:           str = Field("active", max_length=20, description="active / suspended / expired")
    monthly_cost_eur: float = 0.0
    activated_at:     str = ""
    expires_at:       str = ""
    notes:            str = ""

    @validator("iccid", "phone_number", "carrier", "plan", "status")
    def strip_fields(cls, v): return (v or "").strip()


class SimCardUpdate(BaseModel):
    phone_number:     Optional[str]   = None
    carrier:          Optional[str]   = None
    plan:             Optional[str]   = None
    status:           Optional[str]   = None
    monthly_cost_eur: Optional[float] = None
    activated_at:     Optional[str]   = None
    expires_at:       Optional[str]   = None
    notes:            Optional[str]   = None


class SimAssign(BaseModel):
    imei:      str = Field(..., max_length=20)
    client_id: str = Field("", max_length=64)
    notes:     str = ""

    @validator("imei", "client_id")
    def strip_fields(cls, v): return (v or "").strip()


class UserCreate(BaseModel):
    email:    str = Field(..., max_length=120)
    name:     str = Field("", max_length=80)
    role:     str = Field("viewer", max_length=20)   # 'owner' | 'admin' | 'viewer'
    password: str = Field(..., min_length=4, max_length=200)

    @validator("email")
    def strip_lower_email(cls, v): return v.strip().lower()
    @validator("role")
    def validate_role(cls, v):
        v = (v or "viewer").strip().lower()
        if v not in ("owner", "admin", "viewer"):
            raise ValueError("role must be one of: owner, admin, viewer")
        return v


class UserUpdate(BaseModel):
    name:     Optional[str] = None
    role:     Optional[str] = None
    status:   Optional[str] = None
    password: Optional[str] = None


class UserLogin(BaseModel):
    email:    str
    password: str
    client_id: Optional[str] = None   # optional if email is unique globally; helps disambiguate


class GpsVehicleAssign(BaseModel):
    imei:  str = Field(..., max_length=20)
    plate: str = Field(..., max_length=20)

    @validator("imei", "plate")
    def strip_fields(cls, v): return v.strip().upper()

class VehicleAssignmentCreate(BaseModel):
    imei:        str = Field(..., max_length=20)
    eye_mac:     str = Field("", max_length=20)
    plate:       str = Field(..., max_length=20)
    driver_name: str = Field("", max_length=80)
    notes:       str = Field("", max_length=200)

    @validator("imei","plate","eye_mac","driver_name","notes")
    def strip_fields(cls, v): return v.strip()

class AlarmRuleCreate(BaseModel):
    name:             str   = Field("Temperature Alarm", max_length=64)
    sensor_id:        str   = Field("", max_length=64)
    min_temp:         float = 2.0
    max_temp:         float = 8.0
    alert_delay_mins: int   = 5
    rule_type:        str   = Field("temperature", max_length=20)
    speed_kmh_limit:  Optional[float] = None

    @validator("name", "sensor_id", "rule_type")
    def strip_fields(cls, v): return v.strip()

class AlarmRulePatch(BaseModel):
    status: str  # "active" or "inactive"


# ── Teltonika RMS integration ─────────────────────────────────────────────────

def _push_ble_whitelist(device_imei: str) -> dict:
    """Push active BLE sensor MAC whitelist to the GPS device via Teltonika RMS API."""
    if not RMS_TOKEN:
        return {"skipped": True, "reason": "TELTONIKA_RMS_TOKEN not set"}
    import urllib.request, json as _json
    # Fetch the device's rms_device_id
    with engine.connect() as conn:
        dev_row = conn.execute(text(
            "SELECT rms_device_id FROM device_registry WHERE imei=:imei"),
            {"imei": device_imei}).fetchone()
        if not dev_row or not dev_row[0]:
            return {"skipped": True, "reason": "rms_device_id not set for this device"}
        rms_id = dev_row[0]
        # Fetch all active BLE sensors assigned to this GPS device
        macs = conn.execute(text("""
            SELECT bs.mac_address FROM ble_sensor_assignments bsa
            JOIN ble_sensors bs ON bs.id = bsa.ble_sensor_id
            WHERE bsa.device_imei=:imei AND bsa.unassigned_at IS NULL
            ORDER BY bsa.id"""), {"imei": device_imei}).fetchall()
    mac_list = [r[0] for r in macs]
    # Build RMS API params — BLE sensor whitelist slots (up to 4 sensors)
    params = {}
    for i, mac in enumerate(mac_list[:4]):
        params[f"ble.sensor.mac.{i}"] = mac
    # Clear unused slots
    for i in range(len(mac_list), 4):
        params[f"ble.sensor.mac.{i}"] = ""
    payload = _json.dumps({"params": params}).encode()
    url = f"{RMS_BASE}/devices/{rms_id}/params"
    req = urllib.request.Request(url, data=payload, method="PUT",
        headers={"Authorization": f"Bearer {RMS_TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": True, "rms_status": resp.status, "macs_pushed": mac_list}
    except Exception as e:
        return {"ok": False, "error": str(e), "macs_attempted": mac_list}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"app": "Polarix", "status": "ok", "version": VERSION, "environment": os.getenv("ENVIRONMENT", "development")}


# ── Core reading ingest + alarm check ────────────────────────────────────────

def _ingest_and_check(sensor_id: str, client_id: str, temperature: Optional[float],
                      timestamp: str, lat: Optional[float], lng: Optional[float],
                      battery: Optional[int], reading_type: str = "temperature") -> str:
    """Insert reading, update sensor_health, evaluate alarm rules. Returns status string.

    reading_type:
      'temperature' — EYE Sensor / standalone sensor row; alarm rules evaluated here.
      'gps'         — FMB920 GPS track row; alarm rules skipped (temperature row handles it).
    """
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO readings (sensor_id,client_id,temperature,timestamp,lat,lng,reading_type)
            VALUES (:sid,:cid,:temp,:ts,:lat,:lng,:rtype)"""),
            {"sid": sensor_id, "cid": client_id, "temp": temperature,
             "ts": timestamp, "lat": lat, "lng": lng, "rtype": reading_type})

        conn.execute(text("""
            INSERT INTO sensor_health (sensor_id,client_id,last_seen,battery_level,last_lat,last_lng,offline_alerted,battery_alerted)
            VALUES (:sid,:cid,:ts,:bat,:lat,:lng,0,
              COALESCE((SELECT battery_alerted FROM sensor_health WHERE sensor_id=:sid AND client_id=:cid),0))
            ON CONFLICT(sensor_id,client_id) DO UPDATE SET
              last_seen=excluded.last_seen,
              battery_level=COALESCE(excluded.battery_level,sensor_health.battery_level),
              last_lat=COALESCE(excluded.last_lat,sensor_health.last_lat),
              last_lng=COALESCE(excluded.last_lng,sensor_health.last_lng),
              offline_alerted=0"""),
            {"sid": sensor_id, "cid": client_id, "ts": timestamp,
             "bat": battery, "lat": lat, "lng": lng})

        if battery is not None and battery > 25:
            conn.execute(text(
                "UPDATE sensor_health SET battery_alerted=0 WHERE sensor_id=:sid AND client_id=:cid"),
                {"sid": sensor_id, "cid": client_id})

    if temperature is None or reading_type != "temperature":
        return "ok"

    with engine.connect() as conn:
        rules = conn.execute(text("""
            SELECT id,name,min_temp,max_temp,alert_delay_mins,breach_since,
                   COALESCE(in_breach,0)
            FROM alarm_rules
            WHERE client_id=:cid AND status='active'
              AND (sensor_id='' OR sensor_id=:sid)"""),
            {"cid": client_id, "sid": sensor_id}).fetchall()
        thresh_row = conn.execute(text(
            "SELECT alert_active,reactivate FROM thresholds WHERE client_id=:cid"),
            {"cid": client_id}).fetchone()

    result = "ok"; alert_fired = False
    for rule_id, rule_name, min_t, max_t, delay_mins, breach_since, in_breach in rules:
        in_range = min_t <= temperature <= max_t
        if not in_range:
            if in_breach:
                # Already alerted for this breach cycle; do not re-fire until temp recovers
                if result == "ok": result = "breach_active"
            elif not breach_since:
                # Temperature just left range — start the delay timer
                with engine.begin() as conn:
                    conn.execute(text(
                        "UPDATE alarm_rules SET breach_since=:ts WHERE id=:id"),
                        {"ts": timestamp, "id": rule_id})
                if result == "ok": result = "breach_started"
            else:
                elapsed = (datetime.fromisoformat(timestamp) - datetime.fromisoformat(breach_since)).total_seconds() / 60
                if elapsed >= (delay_mins or 0):
                    direction = "too_high" if temperature > max_t else "too_low"
                    with engine.begin() as conn:
                        conn.execute(text(
                            "INSERT INTO alerts VALUES (NULL,:cid,:sid,:temp,:dir,:ts)"),
                            {"cid": client_id, "sid": sensor_id,
                             "temp": temperature, "dir": direction, "ts": timestamp})
                        # Mark in_breach=1 so we don't re-fire while still OOR
                        conn.execute(text(
                            "UPDATE alarm_rules SET breach_since=NULL,in_breach=1 WHERE id=:id"),
                            {"id": rule_id})
                        conn.execute(text(
                            "UPDATE thresholds SET alert_active=1,messages_sent=messages_sent+1 WHERE client_id=:cid"),
                            {"cid": client_id})
                    if not alert_fired:
                        with engine.connect() as conn:
                            contacts = [{"type": c[0], "value": c[1]} for c in conn.execute(text(
                                "SELECT type,value FROM contacts WHERE client_id=:cid"),
                                {"cid": client_id}).fetchall()]
                        send_alert_all(contacts, sensor_id, temperature, min_t, max_t)
                        alert_fired = True
                    result = "alert_sent"
                else:
                    if result == "ok": result = "breach_waiting"
        else:
            if breach_since or in_breach:
                # Temperature recovered — reset rule so it can fire again next time
                with engine.begin() as conn:
                    conn.execute(text(
                        "UPDATE alarm_rules SET breach_since=NULL,in_breach=0 WHERE id=:id"),
                        {"id": rule_id})

    if not alert_fired and thresh_row and thresh_row[0] and thresh_row[1]:
        with engine.connect() as conn:
            still_breaching = conn.execute(text(
                "SELECT 1 FROM alarm_rules WHERE client_id=:cid "
                "AND (breach_since IS NOT NULL OR in_breach=1) LIMIT 1"),
                {"cid": client_id}).fetchone()
        if not still_breaching:
            with engine.begin() as conn:
                conn.execute(text(
                    "UPDATE thresholds SET alert_active=0,breach_since=NULL WHERE client_id=:cid"),
                    {"cid": client_id})
            if result == "ok": result = "alarm_reset"

    return result


# ── Readings ──────────────────────────────────────────────────────────────────

@app.post("/reading")
@limiter.limit("60/minute")
def receive_reading(r: Reading, request: Request):
    timestamp = datetime.utcnow().isoformat()
    # Auto-detect reading_type when not explicitly provided
    rtype = r.reading_type
    if not rtype:
        rtype = "gps" if (r.temperature is None and r.lat is not None) else "temperature"
    result = _ingest_and_check(r.sensor_id, r.client_id, r.temperature, timestamp,
                                r.lat, r.lng, r.battery_level, reading_type=rtype)
    return {"status": result, "temperature": r.temperature, "reading_type": rtype}


# ── Speed alarm check ────────────────────────────────────────────────────────

def _check_speed_alarms(sensor_id: str, client_id: str, speed_kmh: float, timestamp: str):
    """Fire speed alarm if vehicle exceeds limit defined in alarm_rules."""
    from alerts.notifier import send_alert_speed as _send_speed
    with engine.connect() as conn:
        rules = conn.execute(text("""
            SELECT id, name, speed_kmh_limit, COALESCE(in_breach,0)
            FROM alarm_rules
            WHERE client_id=:cid AND status='active' AND rule_type='speed'
              AND speed_kmh_limit IS NOT NULL
              AND (sensor_id='' OR sensor_id=:sid)"""),
            {"cid": client_id, "sid": sensor_id}).fetchall()

    for rule_id, rule_name, limit_kmh, in_breach in rules:
        if speed_kmh > limit_kmh:
            if not in_breach:
                # Fire alert
                with engine.begin() as conn:
                    conn.execute(text(
                        "INSERT INTO alerts VALUES (NULL,:cid,:sid,:spd,'speed_exceeded',:ts)"),
                        {"cid": client_id, "sid": sensor_id, "spd": speed_kmh, "ts": timestamp})
                    conn.execute(text(
                        "UPDATE alarm_rules SET in_breach=1 WHERE id=:id"), {"id": rule_id})
                with engine.connect() as conn:
                    contacts = [{"type": c[0], "value": c[1]} for c in conn.execute(text(
                        "SELECT type,value FROM contacts WHERE client_id=:cid"),
                        {"cid": client_id}).fetchall()]
                _send_speed(contacts, sensor_id, speed_kmh, limit_kmh)
        else:
            if in_breach:
                with engine.begin() as conn:
                    conn.execute(text(
                        "UPDATE alarm_rules SET in_breach=0 WHERE id=:id"), {"id": rule_id})


# ── Teltonika HTTP data ingestion ─────────────────────────────────────────────

@app.post("/teltonika/http")
async def teltonika_http_ingest(request: Request):
    """
    Accept data from Teltonika FMB/FMM devices configured in HTTP mode.
    Use this instead of TCP port 8005 when deployed on Railway or any
    platform that only exposes HTTP/HTTPS ports.

    Device configuration (Teltonika Configurator):
      - Data Protocol: HTTP / HTTPS
      - Server URL: https://your-app.railway.app/teltonika/http
      - HTTP Header: X-Teltonika-Token: <TELTONIKA_HTTP_TOKEN value>

    Expected JSON payload (standard Teltonika HTTP format):
      {"deviceId": "<IMEI>", "records": [{"timestamp": <unix_s>,
        "gps": {"latitude": ..., "longitude": ..., "speed": ..., "satellites": ...},
        "elements": [{"id": 72, "value": <temp*10>}, {"id": 113, "value": <battery%>}]}]}
    """
    if TELTONIKA_HTTP_TOKEN:
        token = request.headers.get("X-Teltonika-Token", "")
        if token != TELTONIKA_HTTP_TOKEN:
            raise HTTPException(403, "Invalid Teltonika token")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    imei = str(body.get("deviceId", "")).strip()
    if not imei:
        raise HTTPException(400, "Missing deviceId")

    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT sensor_id, client_id FROM device_registry WHERE imei=:imei"),
            {"imei": imei}).fetchone()

    if not row:
        raise HTTPException(404, f"IMEI {imei} not registered — register it in the admin panel first")

    sensor_id, client_id = row[0], row[1]
    records = body.get("records", [])
    accepted = 0

    for rec in records:
        try:
            # Timestamp — Teltonika sends Unix seconds; handle ms just in case
            ts_raw = rec.get("timestamp", 0)
            if ts_raw > 1e10:
                ts_raw = ts_raw / 1000.0
            timestamp = datetime.utcfromtimestamp(float(ts_raw)).isoformat()

            # GPS — support both "latitude"/"longitude" and "lat"/"lng" field names
            gps = rec.get("gps", {})
            lat = gps.get("latitude") or gps.get("lat")
            lng = gps.get("longitude") or gps.get("lng")
            satellites = int(gps.get("satellites", 0))
            if satellites < 1 or not lat or not lng or float(lat) == 0.0:
                lat = None; lng = None
            else:
                lat = float(lat); lng = float(lng)

            # IO elements — build id→value dict
            elements = {int(e["id"]): e["value"]
                        for e in rec.get("elements", [])
                        if "id" in e and "value" in e}

            # Temperature: IO ID 72, signed int16 × 10 (e.g. 235 = 23.5°C)
            temperature = None
            if 72 in elements:
                raw_t = int(elements[72])
                if raw_t >= 0x8000:
                    raw_t -= 0x10000
                temperature = round(raw_t / 10.0, 1)

            # Battery: IO ID 113, uint8 0–100 %
            battery = int(elements[113]) if 113 in elements else None

            # Speed: from GPS payload (km/h)
            speed_kmh = float(gps.get("speed", 0) or 0)

            # GPS row — FMB920 sensor_id, with GPS position; alarm rules skipped here
            _ingest_and_check(sensor_id, client_id, temperature, timestamp,
                              lat, lng, battery, reading_type="gps")

            # Speed alarm check
            if speed_kmh > 0:
                _check_speed_alarms(sensor_id, client_id, speed_kmh, timestamp)

            # Temperature row — look up active EYE Sensor MAC from vehicle_assignment
            if temperature is not None:
                with engine.connect() as conn:
                    eye_row = conn.execute(text("""
                        SELECT eye_mac FROM vehicle_assignments
                        WHERE client_id=:cid AND imei=:imei
                          AND eye_mac != '' AND unassigned_at IS NULL
                        ORDER BY assigned_at DESC LIMIT 1"""),
                        {"cid": client_id, "imei": imei}).fetchone()
                eye_mac = eye_row[0] if eye_row else None
                temp_sid = eye_mac if eye_mac else sensor_id
                # Store under EYE MAC (or FMB920 sid as fallback); triggers alarm check
                _ingest_and_check(temp_sid, client_id, temperature, timestamp,
                                  None, None, None, reading_type="temperature")

            accepted += 1

        except Exception as e:
            print(f"[HTTP] Record error for IMEI {imei}: {e}")

    return {"accepted": accepted}


@app.get("/readings/{client_id}")
def get_readings(client_id: str, request: Request, limit: int = 100,
                 from_dt: str = "", to_dt: str = "", sensor_id: str = "",
                 type: str = ""):
    _check_client(request, client_id)
    q = "SELECT sensor_id,temperature,timestamp,lat,lng FROM readings WHERE client_id=:cid"
    p: dict = {"cid": client_id}
    if sensor_id: q += " AND sensor_id=:sid";      p["sid"]     = sensor_id
    if from_dt:   q += " AND timestamp>=:from_dt"; p["from_dt"] = from_dt
    if to_dt:     q += " AND timestamp<=:to_dt";   p["to_dt"]   = to_dt
    if type in ("temperature", "gps"):
        q += " AND reading_type=:rtype"; p["rtype"] = type
    q += " ORDER BY timestamp DESC LIMIT :limit"; p["limit"] = limit
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    return [{"sensor_id":r[0],"temperature":r[1],"timestamp":r[2],"lat":r[3],"lng":r[4]} for r in rows]


# ── GPS history ───────────────────────────────────────────────────────────────

@app.get("/gps_history/{client_id}")
def get_gps_history(client_id: str, request: Request, sensor_id: str = "", from_dt: str = "", to_dt: str = "", limit: int = 2000):
    _check_client(request, client_id)
    q = """SELECT r.sensor_id,r.lat,r.lng,r.temperature,r.timestamp,
           COALESCE(
             (SELECT sa.plate FROM sensor_assignments sa
              WHERE sa.sensor_id=r.sensor_id AND sa.client_id=r.client_id
              AND sa.assigned_at<=r.timestamp
              AND (sa.unassigned_at IS NULL OR sa.unassigned_at>r.timestamp)
              ORDER BY sa.assigned_at DESC LIMIT 1),
             COALESCE(sh.plate,'')
           ) as plate
           FROM readings r
           LEFT JOIN sensor_health sh ON r.sensor_id=sh.sensor_id AND r.client_id=sh.client_id
           WHERE r.client_id=:cid AND r.lat IS NOT NULL AND r.lng IS NOT NULL"""
    p: dict = {"cid": client_id}
    if sensor_id: q += " AND r.sensor_id=:sid";    p["sid"]     = sensor_id
    if from_dt:   q += " AND r.timestamp>=:from_dt"; p["from_dt"] = from_dt
    if to_dt:     q += " AND r.timestamp<=:to_dt";   p["to_dt"]   = to_dt
    q += " ORDER BY r.timestamp ASC LIMIT :limit"; p["limit"] = limit
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    return [{"sensor_id":r[0],"lat":r[1],"lng":r[2],"temperature":r[3],"timestamp":r[4],"plate":r[5]} for r in rows]


@app.get("/export/gps/{client_id}")
def export_gps(client_id: str, request: Request, sensor_id: str = "", from_dt: str = "", to_dt: str = ""):
    _check_client(request, client_id)
    q = """SELECT r.sensor_id,r.lat,r.lng,r.temperature,r.timestamp,
           COALESCE(
             (SELECT sa.plate FROM sensor_assignments sa
              WHERE sa.sensor_id=r.sensor_id AND sa.client_id=r.client_id
              AND sa.assigned_at<=r.timestamp
              AND (sa.unassigned_at IS NULL OR sa.unassigned_at>r.timestamp)
              ORDER BY sa.assigned_at DESC LIMIT 1),
             COALESCE(sh.plate,'')
           ) as plate
           FROM readings r
           LEFT JOIN sensor_health sh ON r.sensor_id=sh.sensor_id AND r.client_id=sh.client_id
           WHERE r.client_id=:cid AND r.lat IS NOT NULL AND r.lng IS NOT NULL"""
    p: dict = {"cid": client_id}
    if sensor_id: q += " AND r.sensor_id=:sid";    p["sid"]     = sensor_id
    if from_dt:   q += " AND r.timestamp>=:from_dt"; p["from_dt"] = from_dt
    if to_dt:     q += " AND r.timestamp<=:to_dt";   p["to_dt"]   = to_dt
    q += " ORDER BY r.timestamp ASC"
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp_utc","sensor_id","plate","lat","lng","temperature_c"])
    for r in rows:
        w.writerow([r[4],r[0],r[5],r[1],r[2],r[3]])
    return StreamingResponse(io.BytesIO(buf.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=gps_{client_id}.csv"})


# ── Threshold ─────────────────────────────────────────────────────────────────

@app.post("/threshold")
def set_threshold(t: Threshold, request: Request):
    _check_client(request, t.client_id)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO thresholds
              (client_id,min_temp,max_temp,alert_active,reactivate,
               alert_delay_mins,alarm_start_dt,alarm_end_dt,messages_sent,offline_after_mins,
               data_retention_years)
            VALUES (:cid,:min,:max,0,:re,:delay,:start,:end,
              COALESCE((SELECT messages_sent FROM thresholds WHERE client_id=:cid),0),:offline,
              :retention)
            ON CONFLICT(client_id) DO UPDATE SET
              min_temp=excluded.min_temp, max_temp=excluded.max_temp,
              reactivate=excluded.reactivate, alert_delay_mins=excluded.alert_delay_mins,
              alarm_start_dt=excluded.alarm_start_dt, alarm_end_dt=excluded.alarm_end_dt,
              offline_after_mins=excluded.offline_after_mins,
              data_retention_years=excluded.data_retention_years"""),
            {"cid": t.client_id, "min": t.min_temp, "max": t.max_temp,
             "re": t.reactivate, "delay": t.alert_delay_mins,
             "start": t.alarm_start_dt or None, "end": t.alarm_end_dt or None,
             "offline": t.offline_after_mins, "retention": t.data_retention_years})
        conn.execute(text("""
            INSERT INTO threshold_history
              (client_id,changed_at,min_temp,max_temp,alert_delay_mins,
               offline_after_mins,data_retention_years)
            VALUES (:cid,:ts,:min,:max,:delay,:offline,:retention)"""),
            {"cid": t.client_id, "ts": ts, "min": t.min_temp, "max": t.max_temp,
             "delay": t.alert_delay_mins, "offline": t.offline_after_mins,
             "retention": t.data_retention_years})
    return {"status": "set"}


@app.get("/threshold/{client_id}")
def get_threshold(client_id: str):
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT min_temp,max_temp,alert_active,reactivate,alert_delay_mins,
                   breach_since,alarm_start_dt,alarm_end_dt,messages_sent,offline_after_mins,
                   COALESCE(data_retention_years,5), COALESCE(can_import,0)
            FROM thresholds WHERE client_id=:cid"""), {"cid": client_id}).fetchone()
    if not row:
        return {"min_temp":None,"max_temp":None,"alert_active":0,"reactivate":1,
                "alert_delay_mins":0,"breach_since":None,"alarm_start_dt":None,
                "alarm_end_dt":None,"messages_sent":0,"offline_after_mins":60,
                "data_retention_years":5,"can_import":0}
    return {"min_temp":row[0],"max_temp":row[1],"alert_active":row[2],"reactivate":row[3],
            "alert_delay_mins":row[4],"breach_since":row[5],"alarm_start_dt":row[6],
            "alarm_end_dt":row[7],"messages_sent":row[8],"offline_after_mins":row[9],
            "data_retention_years":row[10],"can_import":row[11]}


@app.get("/clients")
def list_clients(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT client_id,min_temp,max_temp FROM thresholds")).fetchall()
    return [{"client_id":r[0],"min_temp":r[1],"max_temp":r[2]} for r in rows]


# ── Alarm reset ───────────────────────────────────────────────────────────────

@app.post("/alarm/reset/{client_id}")
def reset_alarm(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE thresholds SET alert_active=0,breach_since=NULL WHERE client_id=:cid"),
            {"cid": client_id})
    return {"status": "reset"}


# ── Contacts ──────────────────────────────────────────────────────────────────

@app.get("/contacts/{client_id}")
def get_contacts(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id,type,value FROM contacts WHERE client_id=:cid ORDER BY id"),
            {"cid": client_id}).fetchall()
    return [{"id":r[0],"type":r[1],"value":r[2]} for r in rows]

@app.post("/contacts/{client_id}")
def add_contact(client_id: str, c: Contact, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT OR IGNORE INTO contacts (client_id,type,value) VALUES (:cid,:type,:val)"),
            {"cid": client_id, "type": c.type.lower().strip(), "val": c.value.strip()})
    return {"status": "added"}

@app.delete("/contacts/{client_id}/{contact_id}")
def delete_contact(client_id: str, contact_id: int, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        conn.execute(text(
            "DELETE FROM contacts WHERE id=:id AND client_id=:cid"),
            {"id": contact_id, "cid": client_id})
    return {"status": "deleted"}


# ── Vehicle assignments ───────────────────────────────────────────────────────

def _sensor_ids_for_client(conn, client_id: str) -> set:
    inv = {r[0] for r in conn.execute(text(
        "SELECT sensor_id FROM sensor_inventory WHERE client_id=:cid"), {"cid": client_id}).fetchall()}
    existing = {r[0] for r in conn.execute(text(
        "SELECT sensor_id FROM sensor_health WHERE client_id=:cid"), {"cid": client_id}).fetchall()}
    return inv | existing

@app.get("/assignments/{client_id}")
def get_assignments(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,sensor_id,plate,assigned_at,driver_name,shipment_notes FROM sensor_assignments
            WHERE client_id=:cid AND unassigned_at IS NULL ORDER BY sensor_id"""),
            {"cid": client_id}).fetchall()
    return [{"id":r[0],"sensor_id":r[1],"plate":r[2],"assigned_at":r[3],
             "driver_name":r[4] or "","shipment_notes":r[5] or ""} for r in rows]

@app.post("/assignments/{client_id}")
def assign_vehicle(client_id: str, body: AssignVehicle, request: Request):
    _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    with engine.connect() as conn:
        authorized = _sensor_ids_for_client(conn, client_id)
    if body.sensor_id not in authorized:
        raise HTTPException(403, f"Sensor '{body.sensor_id}' is not assigned to client '{client_id}'")
    plate = body.plate.strip().upper()
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE sensor_assignments SET unassigned_at=:ts
            WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"""),
            {"ts": ts, "sid": body.sensor_id, "cid": client_id})
        conn.execute(text("""
            INSERT INTO sensor_assignments (sensor_id,client_id,plate,assigned_at,driver_name,shipment_notes)
            VALUES (:sid,:cid,:plate,:ts,:driver,:notes)"""),
            {"sid": body.sensor_id, "cid": client_id, "plate": plate, "ts": ts,
             "driver": body.driver_name, "notes": body.shipment_notes})
        conn.execute(text("""
            INSERT OR IGNORE INTO sensor_health (sensor_id,client_id,plate)
            VALUES (:sid,:cid,:plate)"""),
            {"sid": body.sensor_id, "cid": client_id, "plate": plate})
        conn.execute(text(
            "UPDATE sensor_health SET plate=:plate WHERE sensor_id=:sid AND client_id=:cid"),
            {"plate": plate, "sid": body.sensor_id, "cid": client_id})
    return {"status": "assigned"}

@app.delete("/assignments/{client_id}/{assignment_id}")
def unassign_vehicle(client_id: str, assignment_id: int, request: Request):
    _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT sensor_id FROM sensor_assignments WHERE id=:id AND client_id=:cid"),
            {"id": assignment_id, "cid": client_id}).fetchone()
        conn.execute(text(
            "UPDATE sensor_assignments SET unassigned_at=:ts WHERE id=:id AND client_id=:cid"),
            {"ts": ts, "id": assignment_id, "cid": client_id})
        if row:
            conn.execute(text(
                "UPDATE sensor_health SET plate='' WHERE sensor_id=:sid AND client_id=:cid"),
                {"sid": row[0], "cid": client_id})
    return {"status": "unassigned"}

@app.get("/assignment_history/{client_id}")
def get_assignment_history(client_id: str, request: Request, limit: int = 100):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,sensor_id,plate,assigned_at,unassigned_at,driver_name,shipment_notes FROM sensor_assignments
            WHERE client_id=:cid ORDER BY assigned_at DESC LIMIT :limit"""),
            {"cid": client_id, "limit": limit}).fetchall()
    return [{"id":r[0],"sensor_id":r[1],"plate":r[2],"assigned_at":r[3],"unassigned_at":r[4],
             "driver_name":r[5] or "","shipment_notes":r[6] or ""} for r in rows]


# ── Vehicle assignments (FMB920 + EYE Sensor → Plate) ────────────────────────

@app.get("/vehicle_assignments/{client_id}")
def get_vehicle_assignments(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,imei,eye_mac,plate,driver_name,notes,assigned_at
            FROM vehicle_assignments
            WHERE client_id=:cid AND unassigned_at IS NULL
            ORDER BY assigned_at DESC"""), {"cid": client_id}).fetchall()
    return [{"id":r[0],"imei":r[1],"eye_mac":r[2] or "","plate":r[3],
             "driver_name":r[4] or "","notes":r[5] or "","assigned_at":r[6]} for r in rows]

@app.get("/vehicle_assignments/{client_id}/history")
def get_vehicle_assignment_history(client_id: str, request: Request, limit: int = 100):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,imei,eye_mac,plate,driver_name,notes,assigned_at,unassigned_at
            FROM vehicle_assignments
            WHERE client_id=:cid ORDER BY assigned_at DESC LIMIT :limit"""),
            {"cid": client_id, "limit": limit}).fetchall()
    return [{"id":r[0],"imei":r[1],"eye_mac":r[2] or "","plate":r[3],
             "driver_name":r[4] or "","notes":r[5] or "",
             "assigned_at":r[6],"unassigned_at":r[7]} for r in rows]

@app.post("/vehicle_assignments/{client_id}")
def create_vehicle_assignment(client_id: str, body: VehicleAssignmentCreate, request: Request):
    if request.headers.get("X-Admin-Key", "") == ADMIN_KEY and ADMIN_KEY:
        pass  # admin bypass — allowed to assign on behalf of any client
    else:
        _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    plate = body.plate.strip().upper()
    # Verify the GPS device belongs to this client
    with engine.connect() as conn:
        dev = conn.execute(text(
            "SELECT sensor_id FROM device_registry WHERE imei=:imei AND client_id=:cid"),
            {"imei": body.imei, "cid": client_id}).fetchone()
    if not dev:
        raise HTTPException(403, f"GPS device '{body.imei}' not found for client '{client_id}'")
    gps_sensor_id = dev[0]
    with engine.begin() as conn:
        # Close previous vehicle assignment for same IMEI
        conn.execute(text("""
            UPDATE vehicle_assignments SET unassigned_at=:ts
            WHERE client_id=:cid AND imei=:imei AND unassigned_at IS NULL"""),
            {"ts": ts, "cid": client_id, "imei": body.imei})
        # Create new vehicle assignment
        conn.execute(text("""
            INSERT INTO vehicle_assignments (client_id,imei,eye_mac,plate,driver_name,notes,assigned_at)
            VALUES (:cid,:imei,:eye_mac,:plate,:driver,:notes,:ts)"""),
            {"cid": client_id, "imei": body.imei, "eye_mac": body.eye_mac,
             "plate": plate, "driver": body.driver_name,
             "notes": body.notes, "ts": ts})
        # Mirror to gps_vehicle_assignments for fleet_status compatibility
        conn.execute(text("""
            UPDATE gps_vehicle_assignments SET unassigned_at=:ts
            WHERE imei=:imei AND unassigned_at IS NULL"""),
            {"ts": ts, "imei": body.imei})
        conn.execute(text("""
            INSERT INTO gps_vehicle_assignments (imei,plate,assigned_at)
            VALUES (:imei,:plate,:ts)"""),
            {"imei": body.imei, "plate": plate, "ts": ts})
        # Update sensor_health plate for the GPS sensor_id
        conn.execute(text("""
            INSERT OR IGNORE INTO sensor_health (sensor_id,client_id,plate)
            VALUES (:sid,:cid,:plate)"""),
            {"sid": gps_sensor_id, "cid": client_id, "plate": plate})
        conn.execute(text(
            "UPDATE sensor_health SET plate=:plate WHERE sensor_id=:sid AND client_id=:cid"),
            {"plate": plate, "sid": gps_sensor_id, "cid": client_id})
        # Also close/open sensor_assignments for the GPS sensor_id
        conn.execute(text("""
            UPDATE sensor_assignments SET unassigned_at=:ts
            WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"""),
            {"ts": ts, "sid": gps_sensor_id, "cid": client_id})
        conn.execute(text("""
            INSERT INTO sensor_assignments (sensor_id,client_id,plate,assigned_at,driver_name,shipment_notes)
            VALUES (:sid,:cid,:plate,:ts,:driver,:notes)"""),
            {"sid": gps_sensor_id, "cid": client_id, "plate": plate, "ts": ts,
             "driver": body.driver_name, "notes": body.notes})
    # If eye_mac provided, update ble_sensor_assignments and push RMS whitelist
    if body.eye_mac:
        with engine.connect() as conn:
            bs_row = conn.execute(text(
                "SELECT id FROM ble_sensors WHERE mac_address=:mac AND client_id=:cid"),
                {"mac": body.eye_mac, "cid": client_id}).fetchone()
        if bs_row:
            with engine.begin() as conn:
                conn.execute(text("""
                    UPDATE ble_sensor_assignments SET unassigned_at=:ts
                    WHERE ble_sensor_id=:sid AND unassigned_at IS NULL"""),
                    {"ts": ts, "sid": bs_row[0]})
                conn.execute(text("""
                    INSERT INTO ble_sensor_assignments (ble_sensor_id, device_imei, assigned_at)
                    VALUES (:sid, :imei, :ts)"""),
                    {"sid": bs_row[0], "imei": body.imei, "ts": ts})
            _push_ble_whitelist(body.imei)
    return {"status": "assigned"}

@app.delete("/vehicle_assignments/{client_id}/{assignment_id}")
def delete_vehicle_assignment(client_id: str, assignment_id: int, request: Request):
    _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT imei FROM vehicle_assignments WHERE id=:id AND client_id=:cid"),
            {"id": assignment_id, "cid": client_id}).fetchone()
        conn.execute(text(
            "UPDATE vehicle_assignments SET unassigned_at=:ts WHERE id=:id AND client_id=:cid"),
            {"ts": ts, "id": assignment_id, "cid": client_id})
        if row:
            imei = row[0]
            conn.execute(text("""
                UPDATE gps_vehicle_assignments SET unassigned_at=:ts
                WHERE imei=:imei AND unassigned_at IS NULL"""),
                {"ts": ts, "imei": imei})
            dev = conn.execute(text(
                "SELECT sensor_id FROM device_registry WHERE imei=:imei AND client_id=:cid"),
                {"imei": imei, "cid": client_id}).fetchone()
            if dev:
                conn.execute(text(
                    "UPDATE sensor_health SET plate='' WHERE sensor_id=:sid AND client_id=:cid"),
                    {"sid": dev[0], "cid": client_id})
                conn.execute(text("""
                    UPDATE sensor_assignments SET unassigned_at=:ts
                    WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"""),
                    {"ts": ts, "sid": dev[0], "cid": client_id})
    return {"status": "unassigned"}


# ── Vehicle assignment EDIT — closes the old row and opens a new one,
#    so the change is preserved in history for both client and admin.
@app.patch("/vehicle_assignments/{client_id}/{assignment_id}")
def edit_vehicle_assignment(client_id: str, assignment_id: int,
                            body: VehicleAssignmentCreate, request: Request):
    _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    with engine.connect() as conn:
        old = conn.execute(text("""
            SELECT imei,eye_mac,plate,driver_name,notes
            FROM vehicle_assignments WHERE id=:id AND client_id=:cid
              AND unassigned_at IS NULL"""),
            {"id": assignment_id, "cid": client_id}).fetchone()
    if not old:
        raise HTTPException(404, "Active assignment not found")
    new_imei  = (body.imei or old[0]).strip()
    new_eye   = (body.eye_mac or "").strip()
    new_plate = (body.plate or old[2]).strip().upper()
    new_drv   = body.driver_name or ""
    new_notes = body.notes or ""
    with engine.begin() as conn:
        # Close old assignment (preserves it in history)
        conn.execute(text(
            "UPDATE vehicle_assignments SET unassigned_at=:ts WHERE id=:id"),
            {"ts": ts, "id": assignment_id})
        # Insert new assignment with updated values
        conn.execute(text("""
            INSERT INTO vehicle_assignments
              (client_id,imei,eye_mac,plate,driver_name,notes,assigned_at)
            VALUES (:cid,:imei,:mac,:plate,:drv,:nts,:ts)"""),
            {"cid": client_id, "imei": new_imei, "mac": new_eye,
             "plate": new_plate, "drv": new_drv, "nts": new_notes, "ts": ts})
        # Sync gps_vehicle_assignments
        conn.execute(text(
            "UPDATE gps_vehicle_assignments SET unassigned_at=:ts "
            "WHERE imei=:imei AND unassigned_at IS NULL"),
            {"ts": ts, "imei": new_imei})
        conn.execute(text(
            "INSERT INTO gps_vehicle_assignments (imei,plate,assigned_at) "
            "VALUES (:imei,:plate,:ts)"),
            {"imei": new_imei, "plate": new_plate, "ts": ts})
        # Sync sensor_health plate + sensor_assignments
        dev = conn.execute(text(
            "SELECT sensor_id FROM device_registry WHERE imei=:imei AND client_id=:cid"),
            {"imei": new_imei, "cid": client_id}).fetchone()
        if dev:
            conn.execute(text(
                "UPDATE sensor_health SET plate=:plate WHERE sensor_id=:sid AND client_id=:cid"),
                {"plate": new_plate, "sid": dev[0], "cid": client_id})
            conn.execute(text(
                "UPDATE sensor_assignments SET unassigned_at=:ts "
                "WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"),
                {"ts": ts, "sid": dev[0], "cid": client_id})
            conn.execute(text("""
                INSERT INTO sensor_assignments
                  (sensor_id,client_id,plate,assigned_at,driver_name,shipment_notes)
                VALUES (:sid,:cid,:plate,:ts,:drv,:nts)"""),
                {"sid": dev[0], "cid": client_id, "plate": new_plate,
                 "ts": ts, "drv": new_drv, "nts": new_notes})
    return {"status": "edited"}


# ── Inactive vehicles: plates the client has used historically that
#    are not currently assigned. Used for the "reactivate" workflow.
@app.get("/inactive_vehicles/{client_id}")
def get_inactive_vehicles(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT plate, MAX(unassigned_at) as last_used,
                   MAX(driver_name) as driver
            FROM vehicle_assignments
            WHERE client_id=:cid AND unassigned_at IS NOT NULL
              AND plate NOT IN (
                SELECT plate FROM vehicle_assignments
                WHERE client_id=:cid AND unassigned_at IS NULL)
            GROUP BY plate
            ORDER BY last_used DESC"""), {"cid": client_id}).fetchall()
    return [{"plate": r[0], "last_used": r[1], "driver": r[2] or ""} for r in rows]


@app.post("/vehicle_assignments/{client_id}/reactivate")
def reactivate_vehicle(client_id: str, body: VehicleAssignmentCreate, request: Request):
    """Re-attach an existing (inactive) plate to a (possibly new) GPS device."""
    _check_client(request, client_id)
    plate = body.plate.strip().upper()
    ts = datetime.utcnow().isoformat()
    with engine.connect() as conn:
        already = conn.execute(text("""
            SELECT id FROM vehicle_assignments
            WHERE client_id=:cid AND plate=:plate AND unassigned_at IS NULL"""),
            {"cid": client_id, "plate": plate}).fetchone()
    if already:
        raise HTTPException(409, f"Plate '{plate}' is already active")
    # Reuse the create logic
    return create_vehicle_assignment(client_id, body, request)


# ── Sensor health ─────────────────────────────────────────────────────────────

@app.get("/sensor_health/{client_id}")
def get_sensor_health(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        offline_mins = (conn.execute(text(
            "SELECT offline_after_mins FROM thresholds WHERE client_id=:cid"),
            {"cid": client_id}).fetchone() or [60])[0]
        health_rows = conn.execute(text(
            "SELECT sensor_id,last_seen,battery_level,plate,last_lat,last_lng FROM sensor_health WHERE client_id=:cid ORDER BY sensor_id"),
            {"cid": client_id}).fetchall()
        health_map = {r[0]: r for r in health_rows}
        all_ids = sorted(_sensor_ids_for_client(conn, client_id))
        # Serial-number lookup: FMB920 (device_registry) + EYE sensors (ble_sensors)
        serial_map: dict = {}
        try:
            for r in conn.execute(text(
                "SELECT sensor_id,serial_number FROM device_registry "
                "WHERE client_id=:cid AND serial_number IS NOT NULL AND serial_number!=''"),
                {"cid": client_id}).fetchall():
                serial_map[r[0]] = r[1]
        except Exception: pass
        try:
            for r in conn.execute(text(
                "SELECT mac_address,serial_number FROM ble_sensors "
                "WHERE client_id=:cid AND serial_number IS NOT NULL AND serial_number!=''"),
                {"cid": client_id}).fetchall():
                serial_map.setdefault(r[0], r[1])
        except Exception: pass

    now = datetime.utcnow()
    result = []
    with engine.connect() as conn:
        for sensor_id in all_ids:
            h        = health_map.get(sensor_id)
            last_seen = h[1] if h else None
            battery   = h[2] if h else None
            plate     = h[3] if h else ""
            lat       = h[4] if h else None
            lng       = h[5] if h else None
            elapsed = None; status = "unknown"
            if last_seen:
                elapsed = (now - datetime.fromisoformat(last_seen)).total_seconds() / 60
                status = "online" if elapsed < 10 else ("warning" if elapsed < offline_mins else "offline")
            last_temp_row = conn.execute(text(
                "SELECT temperature FROM readings WHERE sensor_id=:sid AND client_id=:cid ORDER BY timestamp DESC LIMIT 1"),
                {"sid": sensor_id, "cid": client_id}).fetchone()
            result.append({
                "sensor_id":    sensor_id,
                "serial_number": serial_map.get(sensor_id, ""),
                "last_seen":    last_seen,
                "elapsed_mins": round(elapsed) if elapsed is not None else None,
                "battery_level": battery,
                "plate":        _current_plate(conn, sensor_id, client_id, plate),
                "lat":          lat,
                "lng":          lng,
                "status":       status,
                "last_temp":    last_temp_row[0] if last_temp_row else None,
            })
    return result


@app.get("/client_sensors/{client_id}")
def get_client_sensors(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT si.sensor_id,si.hardware_id,si.notes,si.assigned_at,
                   sh.last_seen,sh.battery_level,sh.plate
            FROM sensor_inventory si
            LEFT JOIN sensor_health sh ON si.sensor_id=sh.sensor_id AND sh.client_id=si.client_id
            WHERE si.client_id=:cid ORDER BY si.sensor_id"""), {"cid": client_id}).fetchall()
        inv_ids = {r[0] for r in rows}
        legacy = conn.execute(text(
            "SELECT sensor_id,NULL,NULL,NULL,last_seen,battery_level,plate FROM sensor_health WHERE client_id=:cid ORDER BY sensor_id"),
            {"cid": client_id}).fetchall()
    result = [{"sensor_id":r[0],"hardware_id":r[1],"notes":r[2],"assigned_at":r[3],
               "last_seen":r[4],"battery_level":r[5],"plate":r[6] or ""} for r in rows]
    for r in legacy:
        if r[0] not in inv_ids:
            result.append({"sensor_id":r[0],"hardware_id":None,"notes":"(legacy — not in inventory)",
                           "assigned_at":None,"last_seen":r[4],"battery_level":r[5],"plate":r[6] or ""})
    result.sort(key=lambda x: x["sensor_id"])
    return result


@app.get("/gps_devices/{client_id}")
def get_client_gps_devices(client_id: str, request: Request):
    """Return GPS devices (from device_registry) assigned to this client, with current vehicle plate."""
    _check_client(request, client_id)
    with engine.connect() as conn:
        devices = conn.execute(text("""
            SELECT d.imei, d.sensor_id, d.notes, d.registered_at,
                   g.plate, g.assigned_at AS plate_assigned_at,
                   sh.last_seen, sh.battery_level, sh.last_lat, sh.last_lng,
                   COALESCE(d.serial_number,'')
            FROM device_registry d
            LEFT JOIN gps_vehicle_assignments g ON g.imei=d.imei AND g.unassigned_at IS NULL
            LEFT JOIN sensor_health sh ON sh.sensor_id=d.sensor_id AND sh.client_id=d.client_id
            WHERE d.client_id=:cid ORDER BY d.sensor_id"""), {"cid": client_id}).fetchall()
    return [{"imei": r[0], "sensor_id": r[1], "notes": r[2], "registered_at": r[3],
             "plate": r[4] or "", "plate_assigned_at": r[5],
             "last_seen": r[6], "battery_level": r[7],
             "last_lat": r[8], "last_lng": r[9],
             "serial_number": r[10]} for r in devices]


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/alerts/{client_id}")
def get_alerts(client_id: str, request: Request, limit: int = 50):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,sensor_id,temperature,direction,timestamp FROM alerts
            WHERE client_id=:cid ORDER BY timestamp DESC LIMIT :limit"""),
            {"cid": client_id, "limit": limit}).fetchall()
    return [{"id":r[0],"sensor_id":r[1],"temperature":r[2],"direction":r[3],"timestamp":r[4]} for r in rows]

# ── Alarm rules ──────────────────────────────────────────────────────────────

@app.get("/alarm_rules/{client_id}")
def get_alarm_rules(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,name,sensor_id,min_temp,max_temp,alert_delay_mins,
                   status,created_at,breach_since,
                   COALESCE(rule_type,'temperature'),
                   speed_kmh_limit
            FROM alarm_rules WHERE client_id=:cid ORDER BY created_at"""),
            {"cid": client_id}).fetchall()
    return [{"id":r[0],"name":r[1],"sensor_id":r[2],"min_temp":r[3],"max_temp":r[4],
             "alert_delay_mins":r[5],"status":r[6],"created_at":r[7],
             "breach_since":r[8],"rule_type":r[9],"speed_kmh_limit":r[10]} for r in rows]

@app.post("/alarm_rules/{client_id}")
def create_alarm_rule(client_id: str, body: AlarmRuleCreate, request: Request):
    _check_client(request, client_id)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO alarm_rules
              (client_id,name,sensor_id,min_temp,max_temp,alert_delay_mins,status,created_at,
               rule_type,speed_kmh_limit)
            VALUES (:cid,:name,:sid,:mn,:mx,:dl,'active',:ts,:rtype,:spd)"""),
            {"cid": client_id, "name": body.name, "sid": body.sensor_id,
             "mn": body.min_temp, "mx": body.max_temp,
             "dl": body.alert_delay_mins, "ts": ts,
             "rtype": body.rule_type, "spd": body.speed_kmh_limit})
    return {"status": "created"}

@app.patch("/alarm_rules/{client_id}/{rule_id}")
def patch_alarm_rule(client_id: str, rule_id: int, body: AlarmRulePatch, request: Request):
    _check_client(request, client_id)
    status = body.status if body.status in ("active", "inactive") else "active"
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE alarm_rules SET status=:st,breach_since=NULL WHERE id=:id AND client_id=:cid"),
            {"st": status, "id": rule_id, "cid": client_id})
    return {"status": "updated"}

@app.delete("/alarm_rules/{client_id}/{rule_id}")
def delete_alarm_rule(client_id: str, rule_id: int, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        conn.execute(text(
            "DELETE FROM alarm_rules WHERE id=:id AND client_id=:cid"),
            {"id": rule_id, "cid": client_id})
    return {"status": "deleted"}


# ── Fleet status ──────────────────────────────────────────────────────────────

@app.get("/fleet_status/{client_id}")
def get_fleet_status(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        offline_mins = (conn.execute(text(
            "SELECT offline_after_mins FROM thresholds WHERE client_id=:cid"),
            {"cid": client_id}).fetchone() or [60])[0]
        health_rows = conn.execute(text(
            "SELECT sensor_id,last_seen,battery_level,plate,last_lat,last_lng FROM sensor_health WHERE client_id=:cid ORDER BY sensor_id"),
            {"cid": client_id}).fetchall()
        health_map = {r[0]: r for r in health_rows}
        all_ids = sorted(_sensor_ids_for_client(conn, client_id))
        now = datetime.utcnow()
        result = []
        for sensor_id in all_ids:
            h         = health_map.get(sensor_id)
            last_seen  = h[1] if h else None
            battery    = h[2] if h else None
            plate      = h[3] if h else ""
            last_lat   = h[4] if h else None
            last_lng   = h[5] if h else None
            elapsed = None; status = "unknown"
            if last_seen:
                elapsed = (now - datetime.fromisoformat(last_seen)).total_seconds() / 60
                status = "online" if elapsed < 10 else ("warning" if elapsed < offline_mins else "offline")
            last_temp = conn.execute(text(
                "SELECT temperature FROM readings WHERE sensor_id=:sid AND client_id=:cid ORDER BY timestamp DESC LIMIT 1"),
                {"sid": sensor_id, "cid": client_id}).fetchone()
            last2 = conn.execute(text(
                "SELECT lat,lng,timestamp FROM readings WHERE sensor_id=:sid AND client_id=:cid AND lat IS NOT NULL AND lng IS NOT NULL ORDER BY timestamp DESC LIMIT 2"),
                {"sid": sensor_id, "cid": client_id}).fetchall()
            speed_kmh = None; is_moving = False
            if len(last2) >= 2:
                lat1, lng1, ts1 = last2[0]; lat2, lng2, ts2 = last2[1]
                try:
                    dt = (datetime.fromisoformat(ts1) - datetime.fromisoformat(ts2)).total_seconds()
                    if 0 < dt < 3600:
                        dlat = (lat1 - lat2) * math.pi / 180
                        dlon = (lng1 - lng2) * math.pi / 180
                        a = math.sin(dlat/2)**2 + math.cos(lat2*math.pi/180)*math.cos(lat1*math.pi/180)*math.sin(dlon/2)**2
                        dist = 6371 * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
                        speed_kmh = round(dist / dt * 3600, 1)
                        is_moving = speed_kmh > 2
                except Exception: pass
            asgn = _current_assignment(conn, sensor_id, client_id, plate)
            result.append({
                "sensor_id":      sensor_id,
                "plate":          asgn["plate"],
                "driver_name":    asgn["driver_name"],
                "shipment_notes": asgn["shipment_notes"],
                "status":         status,
                "elapsed_mins":   round(elapsed) if elapsed is not None else None,
                "battery_level":  battery,
                "lat":            last_lat,
                "lng":            last_lng,
                "temperature":    last_temp[0] if last_temp else None,
                "speed_kmh":      speed_kmh,
                "is_moving":      is_moving,
                "last_seen":      last_seen,
            })
    return result


# ── Weekly history ────────────────────────────────────────────────────────────

@app.get("/weekly_history/{client_id}")
def get_weekly_history(client_id: str, request: Request, sensor_id: str = "", days: int = 7):
    _check_client(request, client_id)
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    q = "SELECT sensor_id,temperature,timestamp,lat,lng FROM readings WHERE client_id=:cid AND timestamp>=:since"
    p: dict = {"cid": client_id, "since": since}
    if sensor_id: q += " AND sensor_id=:sid"; p["sid"] = sensor_id
    q += " ORDER BY timestamp ASC"
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    return [{"sensor_id":r[0],"temperature":r[1],"timestamp":r[2],"lat":r[3],"lng":r[4]} for r in rows]


# ── Export CSV ────────────────────────────────────────────────────────────────

@app.get("/export/{client_id}")
def export_readings(client_id: str, request: Request,
                    sensor_id: str = "", interval: int = 0,
                    from_dt: str = "", to_dt: str = ""):
    _check_client(request, client_id)
    q = """SELECT r.sensor_id,r.temperature,r.timestamp,COALESCE(sh.plate,''),r.lat,r.lng
           FROM readings r LEFT JOIN sensor_health sh ON r.sensor_id=sh.sensor_id AND r.client_id=sh.client_id
           WHERE r.client_id=:cid"""
    p: dict = {"cid": client_id}
    if sensor_id: q += " AND r.sensor_id=:sid";    p["sid"]     = sensor_id
    if from_dt:   q += " AND r.timestamp>=:from_dt"; p["from_dt"] = from_dt
    if to_dt:     q += " AND r.timestamp<=:to_dt";   p["to_dt"]   = to_dt
    q += " ORDER BY r.timestamp ASC"
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    if interval > 0:
        sampled: list = []; last_ts = None
        for row in rows:
            try:
                ts = datetime.fromisoformat(row[2])
            except Exception:
                continue
            if last_ts is None or (ts - last_ts).total_seconds() >= interval * 60:
                sampled.append(row); last_ts = ts
        rows = sampled
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp_utc","sensor_id","plate","temperature_c","lat","lng"])
    for row in rows:
        w.writerow([row[2],row[0],row[3],row[1],row[4],row[5]])
    return StreamingResponse(io.BytesIO(buf.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=polarix_{client_id}.csv"})


# ── Compliance Export ──────────────────────────────────────────────────────────

@app.get("/export/compliance/{client_id}")
def export_compliance(client_id: str, request: Request,
                      from_dt: str = "", to_dt: str = "",
                      format: str = "csv", interval: int = 0):
    """
    Full EU compliance export: all temperature readings + all alerts + threshold
    change history for the requested date range.  JWT auth required.

    format=csv  (default) — multi-section CSV with clearly labelled sections
    format=html           — printable HTML suitable for browser-based PDF save
    interval              — 0=all readings, >0=average into N-minute buckets
    """
    _check_client(request, client_id)

    # Default range: last 5 years
    if not from_dt:
        from_dt = (datetime.utcnow() - timedelta(days=5*365)).strftime("%Y-%m-%dT%H:%M:%S")
    if not to_dt:
        to_dt = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    with engine.connect() as conn:
        readings = conn.execute(text("""
            SELECT r.timestamp, r.sensor_id, r.temperature, r.lat, r.lng,
                   COALESCE(sh.plate,'') as plate
            FROM readings r
            LEFT JOIN sensor_health sh
                ON r.sensor_id=sh.sensor_id AND r.client_id=sh.client_id
            WHERE r.client_id=:cid
              AND r.reading_type='temperature'
              AND (:from_dt='' OR r.timestamp>=:from_dt)
              AND (:to_dt='' OR r.timestamp<=:to_dt)
            ORDER BY r.timestamp ASC"""),
            {"cid": client_id, "from_dt": from_dt, "to_dt": to_dt}).fetchall()

        alerts = conn.execute(text("""
            SELECT timestamp, sensor_id, temperature, direction
            FROM alerts
            WHERE client_id=:cid
              AND (:from_dt='' OR timestamp>=:from_dt)
              AND (:to_dt='' OR timestamp<=:to_dt)
            ORDER BY timestamp ASC"""),
            {"cid": client_id, "from_dt": from_dt, "to_dt": to_dt}).fetchall()

        th_history = conn.execute(text("""
            SELECT changed_at, min_temp, max_temp, alert_delay_mins,
                   offline_after_mins, data_retention_years
            FROM threshold_history
            WHERE client_id=:cid
              AND (:from_dt='' OR changed_at>=:from_dt)
              AND (:to_dt='' OR changed_at<=:to_dt)
            ORDER BY changed_at ASC"""),
            {"cid": client_id, "from_dt": from_dt, "to_dt": to_dt}).fetchall()

        current_thresh = conn.execute(text("""
            SELECT min_temp, max_temp, alert_delay_mins, offline_after_mins,
                   COALESCE(data_retention_years,5)
            FROM thresholds WHERE client_id=:cid"""),
            {"cid": client_id}).fetchone()

    # Resample readings into N-minute buckets if interval > 0
    if interval > 0:
        from collections import defaultdict
        import math as _math
        buckets: dict = defaultdict(lambda: {"timestamps": [], "temps": [], "plate": ""})
        for r in readings:
            try:
                ts = datetime.fromisoformat(r[0].replace("Z", ""))
                bucket_ms = _math.floor(ts.timestamp() / (interval * 60)) * interval * 60
            except Exception:
                continue
            k = f"{r[1]}|{bucket_ms}"
            b = buckets[k]
            b["timestamps"].append(ts)
            if r[2] is not None:
                b["temps"].append(r[2])
            if not b["plate"] and r[5]:
                b["plate"] = r[5]
        resampled = []
        for k in sorted(buckets):
            b = buckets[k]
            if not b["temps"]:
                continue
            avg_ts = datetime.utcfromtimestamp(
                sum(t.timestamp() for t in b["timestamps"]) / len(b["timestamps"])
            ).strftime("%Y-%m-%dT%H:%M:%S")
            avg_temp = sum(b["temps"]) / len(b["temps"])
            sensor_id = k.split("|")[0]
            resampled.append((avg_ts, sensor_id, avg_temp, None, None, b["plate"]))
        readings = resampled

    generated_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S UTC")
    retention_yrs = current_thresh[4] if current_thresh else 5
    safe_min = current_thresh[0] if current_thresh else None
    safe_max = current_thresh[1] if current_thresh else None
    compliance_note = (
        f"Records retained for {retention_yrs} years in compliance with "
        "EU ATP Regulation and EC 852/2004"
    )

    if format == "html":
        def _row_cls(temp):
            if temp is None or safe_min is None: return ""
            return ' class="bad"' if temp < safe_min or temp > safe_max else ' class="ok"'

        rd_rows = "".join(
            f"<tr><td>{r[0][:16].replace('T',' ')}</td>"
            f"<td>{r[1]}</td>"
            f"<td{_row_cls(r[2])}>{f'{r[2]:.1f}' if r[2] is not None else '—'}°C</td>"
            f"<td>{r[5] or '—'}</td></tr>"
            for r in readings
        )
        al_rows = "".join(
            f"<tr><td>{a[0][:16].replace('T',' ')}</td>"
            f"<td>{a[1]}</td>"
            f"<td class='bad'>{f'{a[2]:.1f}' if a[2] else '—'}°C</td>"
            f"<td>{'Too High' if a[3]=='too_high' else 'Too Low'}</td></tr>"
            for a in alerts
        ) or "<tr><td colspan='4' style='color:#27ae60;'>No alerts in this period</td></tr>"
        th_rows = "".join(
            f"<tr><td>{h[0][:16].replace('T',' ')}</td>"
            f"<td>{h[1]}°C</td><td>{h[2]}°C</td>"
            f"<td>{h[3]} min</td><td>{h[5] or 5} yr</td></tr>"
            for h in th_history
        ) or "<tr><td colspan='5' style='color:#888;'>No changes recorded in this period</td></tr>"

        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>Polarix Compliance Export — {client_id}</title>
<style>
  body{{font-family:Arial,sans-serif;font-size:11px;color:#1a1a1a;padding:20px;max-width:1000px;margin:0 auto;}}
  h1{{font-size:18px;color:#1a5fa8;margin-bottom:2px;}}
  h2{{font-size:13px;color:#1a5fa8;border-bottom:2px solid #1a5fa8;padding-bottom:3px;margin:18px 0 6px;}}
  .meta{{color:#555;font-size:10px;margin-bottom:16px;line-height:1.8;}}
  .compliance{{background:#e8f0fe;border:1px solid #aec6f5;border-radius:4px;padding:8px 12px;
               font-size:10px;color:#1a5fa8;margin-bottom:14px;font-weight:600;}}
  table{{width:100%;border-collapse:collapse;margin-bottom:10px;}}
  th{{background:#1a5fa8;color:#fff;padding:4px 7px;text-align:left;font-size:10px;}}
  td{{padding:3px 7px;border-bottom:1px solid #eee;font-size:10px;}}
  .ok{{color:#27ae60;font-weight:700;}} .bad{{color:#c0392b;font-weight:700;}}
  footer{{margin-top:20px;padding-top:8px;border-top:1px solid #ccc;font-size:9px;
          color:#888;text-align:center;}}
  @media print{{@page{{margin:12mm;}}button{{display:none;}}}}
</style></head><body>
<h1>Polarix — EU Compliance Export</h1>
<div class="compliance">{compliance_note}</div>
<div class="meta">
  <b>Client:</b> {client_id}<br/>
  <b>Period:</b> {from_dt[:10]} to {to_dt[:10]}<br/>
  <b>Safe temperature range:</b> {f"{safe_min}–{safe_max}°C" if safe_min is not None else "not configured"}<br/>
  <b>Generated:</b> {generated_at}<br/>
  <b>Total readings:</b> {len(readings)}{f" (averaged every {interval} min)" if interval > 0 else ""} &nbsp;·&nbsp; <b>Total alerts:</b> {len(alerts)}
</div>
<h2>Temperature Readings ({len(readings)}{f" — {interval}-min averages" if interval > 0 else ""})</h2>
<table>
  <thead><tr><th>Timestamp (UTC)</th><th>Sensor</th><th>Temperature</th><th>Vehicle</th></tr></thead>
  <tbody>{rd_rows or "<tr><td colspan='4'>No readings in this period</td></tr>"}</tbody>
</table>
<h2>Temperature Alerts ({len(alerts)})</h2>
<table>
  <thead><tr><th>Timestamp (UTC)</th><th>Sensor</th><th>Temperature</th><th>Direction</th></tr></thead>
  <tbody>{al_rows}</tbody>
</table>
<h2>Threshold Configuration Changes ({len(th_history)})</h2>
<table>
  <thead><tr><th>Changed At (UTC)</th><th>Min Temp</th><th>Max Temp</th><th>Alert Delay</th><th>Retention</th></tr></thead>
  <tbody>{th_rows}</tbody>
</table>
<footer>
  Polarix Cold-Chain Monitoring &nbsp;·&nbsp; {compliance_note}<br/>
  Report generated: {generated_at}
</footer>
<script>window.onload=()=>window.print();</script>
</body></html>"""
        return StreamingResponse(
            io.BytesIO(html.encode("utf-8")),
            media_type="text/html",
            headers={"Content-Disposition":
                     f"inline; filename=compliance_{client_id}_{from_dt[:10]}_{to_dt[:10]}.html"})

    # Default: CSV
    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow(["# Polarix EU Compliance Export"])
    w.writerow(["# Client", client_id])
    w.writerow(["# Period", from_dt[:10], "to", to_dt[:10]])
    w.writerow(["# Generated", generated_at])
    w.writerow(["# " + compliance_note])
    w.writerow([])

    if interval > 0:
        w.writerow([f"# Reading interval: averaged every {interval} minutes"])
    w.writerow(["## SECTION 1: TEMPERATURE READINGS"])
    w.writerow(["timestamp_utc","sensor_id","temperature_c","plate","lat","lng"])
    for r in readings:
        w.writerow([r[0], r[1], r[2], r[5], r[3], r[4]])
    w.writerow([])

    w.writerow(["## SECTION 2: TEMPERATURE ALERTS"])
    w.writerow(["timestamp_utc","sensor_id","temperature_c","direction"])
    for a in alerts:
        w.writerow([a[0], a[1], a[2], a[3]])
    w.writerow([])

    w.writerow(["## SECTION 3: THRESHOLD CONFIGURATION CHANGES"])
    w.writerow(["changed_at","min_temp_c","max_temp_c","alert_delay_mins",
                "offline_after_mins","data_retention_years"])
    for h in th_history:
        w.writerow([h[0], h[1], h[2], h[3], h[4], h[5]])

    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=compliance_{client_id}_{from_dt[:10]}_{to_dt[:10]}.csv"})


# ── CSV Import ────────────────────────────────────────────────────────────────

@app.post("/import/{client_id}")
async def import_csv(client_id: str, request: Request, file: UploadFile = File(...)):
    _check_client(request, client_id)
    raw = await file.read()
    try:
        text_content = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text_content = raw.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text_content))
    imported = 0; skipped = 0; errors: list = []

    for i, row in enumerate(reader, 1):
        if len(errors) >= 10:
            break
        try:
            # Auto-detect column names (our format, HOBO logger, generic)
            ts_raw   = (row.get("timestamp_utc") or row.get("timestamp") or
                        row.get("Date Time") or row.get("Date/Time") or "").strip()
            temp_raw = (row.get("temperature_c") or row.get("temperature") or
                        row.get("Ch1: Temp") or "").strip()
            sid_raw  = (row.get("sensor_id") or client_id).strip()

            if not ts_raw or not temp_raw:
                skipped += 1; continue

            temp_val = float(temp_raw.replace(",", ".").split()[0])

            # Normalize timestamp to ISO format
            ts_clean = ts_raw.replace("/", "-")
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                        "%m-%d-%Y %H:%M", "%d-%m-%Y %H:%M"):
                try:
                    ts_clean = datetime.strptime(ts_raw, fmt).isoformat()
                    break
                except Exception:
                    pass

            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO readings (sensor_id,client_id,temperature,timestamp)
                    VALUES (:sid,:cid,:temp,:ts)"""),
                    {"sid": sid_raw[:64], "cid": client_id, "temp": temp_val, "ts": ts_clean})
            imported += 1
        except Exception as e:
            errors.append(f"Row {i}: {e}")

    return {"imported": imported, "skipped": skipped, "errors": errors}


# ── Server-side temperature chart (PNG for PDF embedding) ─────────────────────

@app.get("/chart/{client_id}")
def get_chart(client_id: str, request: Request, sensor_id: str = "", days: int = 7,
              from_dt: str = "", to_dt: str = ""):
    _check_client(request, client_id)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    if from_dt:
        since = from_dt
        until = to_dt or datetime.utcnow().isoformat()
    else:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        until = datetime.utcnow().isoformat()

    # Determine how many hours the window spans to pick x-axis format
    try:
        span_hours = (datetime.fromisoformat(until) - datetime.fromisoformat(since)).total_seconds() / 3600
    except Exception:
        span_hours = days * 24

    with engine.connect() as conn:
        trow = conn.execute(text(
            "SELECT min_temp,max_temp FROM thresholds WHERE client_id=:cid"), {"cid": client_id}).fetchone()
        q = ("SELECT temperature,timestamp FROM readings "
             "WHERE client_id=:cid AND timestamp>=:since AND timestamp<=:until")
        p: dict = {"cid": client_id, "since": since, "until": until}
        if sensor_id: q += " AND sensor_id=:sid"; p["sid"] = sensor_id
        q += " ORDER BY timestamp ASC LIMIT 5000"
        rows = conn.execute(text(q), p).fetchall()

    min_t = trow[0] if trow else 2.0
    max_t = trow[1] if trow else 8.0

    fig, ax = plt.subplots(figsize=(10, 3.5), facecolor="#161b22")
    ax.set_facecolor("#0d1117")

    if rows:
        ts_list = []
        for r in rows:
            try: ts_list.append(datetime.fromisoformat(r[1]))
            except Exception: ts_list.append(None)
        valid = [(t, r[0]) for t, r in zip(ts_list, rows) if t is not None]
        if valid:
            times, temps = zip(*valid)
            ax.plot(times, temps, color="#58a6ff", linewidth=1.5, zorder=3)
            ax.axhline(min_t, color="#388bfd", linestyle="--", linewidth=1, alpha=0.7, label=f"Min {min_t}°C")
            ax.axhline(max_t, color="#f85149", linestyle="--", linewidth=1, alpha=0.7, label=f"Max {max_t}°C")
            ax.fill_between(times, temps, max_t, where=[t > max_t for t in temps], color="#f85149", alpha=0.3)
            ax.fill_between(times, temps, min_t, where=[t < min_t for t in temps], color="#388bfd", alpha=0.3)

    # Show time on x-axis when range ≤ 3 days, otherwise date+time
    if span_hours <= 72:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M"))
    else:
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m\n%H:%M"))
    fig.autofmt_xdate(rotation=30)
    ax.tick_params(colors="#8b949e", labelsize=8)
    ax.set_ylabel("°C", color="#8b949e", fontsize=9)
    for spine in ax.spines.values(): spine.set_edgecolor("#30363d")
    ax.legend(facecolor="#1f2937", edgecolor="#30363d", labelcolor="#e6edf3", fontsize=8)
    ax.grid(True, color="#30363d", alpha=0.5)

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png",
        headers={"Cache-Control": "no-cache"})


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/login")
def auth_login(req: LoginRequest, request: Request):
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT password_hash FROM client_passwords WHERE client_id=:cid"),
            {"cid": req.client_id}).fetchone()

    if not row:
        raise HTTPException(401, "Invalid credentials")
    if not _verify(req.password, row[0]):
        raise HTTPException(401, "Invalid credentials")

    # Auto-upgrade SHA-256 hash to bcrypt on first successful login
    if not row[0].startswith("$2"):
        with engine.begin() as conn:
            conn.execute(text(
                "UPDATE client_passwords SET password_hash=:ph WHERE client_id=:cid"),
                {"ph": _hash_new(req.password), "cid": req.client_id})

    token = _make_token(req.client_id, user_id=None, request=request)
    return {"status": "ok", "token": token, "client_id": req.client_id, "role": "owner"}


@app.post("/auth/user_login")
def auth_user_login(req: UserLogin, request: Request):
    """Login with email + password — for additional users a client has created."""
    email = req.email.strip().lower()
    with engine.connect() as conn:
        # If client_id is given, scope to it; otherwise find by email alone
        # (admin should ensure global uniqueness, but we tolerate duplicates by picking
        # the first active match)
        if req.client_id:
            row = conn.execute(text(
                "SELECT id,client_id,password_hash,role,status,name FROM users "
                "WHERE client_id=:cid AND email=:email LIMIT 1"),
                {"cid": req.client_id.strip(), "email": email}).fetchone()
        else:
            row = conn.execute(text(
                "SELECT id,client_id,password_hash,role,status,name FROM users "
                "WHERE email=:email AND status='active' LIMIT 1"),
                {"email": email}).fetchone()

    if not row:
        raise HTTPException(401, "Invalid credentials")
    user_id, client_id, ph, role, status, name = row
    if status != "active":
        raise HTTPException(403, f"User is {status}")
    if not _verify(req.password, ph):
        raise HTTPException(401, "Invalid credentials")

    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET last_login=:ts WHERE id=:id"),
                     {"ts": ts, "id": user_id})

    token = _make_token(client_id, user_id=user_id, request=request)
    return {"status": "ok", "token": token, "client_id": client_id,
            "user_id": user_id, "role": role, "name": name}


@app.post("/auth/set_password")
def set_password(req: LoginRequest):
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT password_hash FROM client_passwords WHERE client_id=:cid"),
            {"cid": req.client_id}).fetchone()
    if row:
        return {"status": "already_set"}
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO client_passwords (client_id,password_hash,created_at) VALUES (:cid,:ph,:ts)"),
            {"cid": req.client_id, "ph": _hash_new(req.password), "ts": ts})
    return {"status": "set"}


# ── User management (multi-user per client) ───────────────────────────────────
# A client always has one implicit "owner" (the client_id + client_passwords row).
# Extra users live in `users`, scoped by client_id. `max_users` on thresholds
# controls the limit; default 1 means only the owner login works until upgraded.

def _count_users(conn, client_id: str) -> int:
    return conn.execute(text(
        "SELECT COUNT(*) FROM users WHERE client_id=:cid AND status='active'"),
        {"cid": client_id}).scalar() or 0


def _max_users(conn, client_id: str) -> int:
    row = conn.execute(text(
        "SELECT COALESCE(max_users,1) FROM thresholds WHERE client_id=:cid"),
        {"cid": client_id}).fetchone()
    return int(row[0]) if row else 1


@app.get("/users/{client_id}")
def list_users(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,email,name,role,status,created_at,last_login
            FROM users WHERE client_id=:cid ORDER BY created_at"""),
            {"cid": client_id}).fetchall()
        limit = _max_users(conn, client_id)
        used  = _count_users(conn, client_id)
    return {"users": [{"id": r[0], "email": r[1], "name": r[2], "role": r[3],
                       "status": r[4], "created_at": r[5], "last_login": r[6]}
                      for r in rows],
            "max_users": limit, "used": used,
            "can_add": used < limit}


@app.post("/users/{client_id}")
def create_user(client_id: str, body: UserCreate, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        used = _count_users(conn, client_id)
        limit = _max_users(conn, client_id)
    if used >= limit:
        raise HTTPException(402, f"User limit reached ({used}/{limit}). "
                                 f"Ask admin to raise max_users for this client.")
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        try:
            conn.execute(text("""
                INSERT INTO users (client_id,email,name,role,password_hash,status,created_at)
                VALUES (:cid,:email,:name,:role,:ph,'active',:ts)"""),
                {"cid": client_id, "email": body.email, "name": body.name,
                 "role": body.role, "ph": _hash_new(body.password), "ts": ts})
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, f"User '{body.email}' already exists for this client")
            raise
    return {"status": "created"}


@app.patch("/users/{client_id}/{user_id}")
def update_user(client_id: str, user_id: int, body: UserUpdate, request: Request):
    _check_client(request, client_id)
    fields = body.dict(exclude_unset=True)
    if "password" in fields and fields["password"]:
        fields["password_hash"] = _hash_new(fields.pop("password"))
    else:
        fields.pop("password", None)
    fields = {k: v for k, v in fields.items() if v is not None}
    if not fields:
        return {"status": "no-op"}
    set_clause = ", ".join(f"{k}=:{k}" for k in fields)
    fields["uid"] = user_id; fields["cid"] = client_id
    with engine.begin() as conn:
        r = conn.execute(text(
            f"UPDATE users SET {set_clause} WHERE id=:uid AND client_id=:cid"),
            fields)
        if r.rowcount == 0:
            raise HTTPException(404, "User not found")
    return {"status": "updated"}


@app.delete("/users/{client_id}/{user_id}")
def delete_user(client_id: str, user_id: int, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        r = conn.execute(text("DELETE FROM users WHERE id=:uid AND client_id=:cid"),
                          {"uid": user_id, "cid": client_id})
        if r.rowcount == 0:
            raise HTTPException(404, "User not found")
        # Revoke any open sessions for this user
        conn.execute(text("""
            UPDATE user_sessions SET revoked_at=:ts WHERE user_id=:uid AND revoked_at IS NULL"""),
            {"ts": datetime.utcnow().isoformat(), "uid": user_id})
    return {"status": "deleted"}


@app.get("/sessions/{client_id}")
def list_sessions(client_id: str, request: Request, active_only: int = 1):
    _check_client(request, client_id)
    now = datetime.utcnow().isoformat()
    with engine.connect() as conn:
        q = """SELECT s.id,s.user_id,s.jti,s.issued_at,s.expires_at,s.ip,
                      s.user_agent,s.revoked_at,
                      COALESCE(u.email,'(owner login)') as email,
                      COALESCE(u.name,'')
               FROM user_sessions s
               LEFT JOIN users u ON s.user_id=u.id
               WHERE s.client_id=:cid"""
        if active_only:
            q += " AND s.revoked_at IS NULL AND s.expires_at>:now"
        q += " ORDER BY s.issued_at DESC LIMIT 100"
        rows = conn.execute(text(q), {"cid": client_id, "now": now}).fetchall()
    return [{"id": r[0], "user_id": r[1], "jti": r[2], "issued_at": r[3],
             "expires_at": r[4], "ip": r[5], "user_agent": r[6],
             "revoked_at": r[7], "email": r[8], "name": r[9]} for r in rows]


@app.delete("/sessions/{client_id}/{session_id}")
def revoke_session(client_id: str, session_id: int, request: Request):
    _check_client(request, client_id)
    with engine.begin() as conn:
        r = conn.execute(text("""
            UPDATE user_sessions SET revoked_at=:ts
            WHERE id=:id AND client_id=:cid AND revoked_at IS NULL"""),
            {"ts": datetime.utcnow().isoformat(), "id": session_id, "cid": client_id})
    return {"status": "revoked" if r.rowcount else "no-op"}


# Admin: raise/lower the user-limit for a client (billing gate)
@app.patch("/admin/clients/{client_id}/max_users")
def admin_set_max_users(client_id: str, request: Request, n: int = 1):
    _check_admin(request)
    if n < 1 or n > 50:
        raise HTTPException(400, "n must be between 1 and 50")
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT OR IGNORE INTO thresholds (client_id,min_temp,max_temp,
                alert_active,reactivate,alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,2.0,8.0,0,1,0,0,60)"""), {"cid": client_id})
        conn.execute(text("UPDATE thresholds SET max_users=:n WHERE client_id=:cid"),
                     {"n": n, "cid": client_id})
    return {"status": "updated", "max_users": n}


@app.post("/auth/change_password")
def change_password(req: ChangePasswordRequest):
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT password_hash FROM client_passwords WHERE client_id=:cid"),
            {"cid": req.client_id}).fetchone()
    if not row or not _verify(req.password, row[0]):
        raise HTTPException(401, "Wrong current password")
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE client_passwords SET password_hash=:ph WHERE client_id=:cid"),
            {"ph": _hash_new(req.new_password), "cid": req.client_id})
    return {"status": "changed"}


# ── Demo mode ─────────────────────────────────────────────────────────────────

@app.post("/demo/start")
def demo_start():
    """Create or reset demo_client and return a short-lived JWT for the demo session."""
    demo_id = "demo_client"
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO thresholds
              (client_id,min_temp,max_temp,alert_active,reactivate,alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,2.0,8.0,0,1,0,0,60)
            ON CONFLICT(client_id) DO UPDATE SET alert_active=0,breach_since=NULL"""),
            {"cid": demo_id})
        conn.execute(text("""
            INSERT OR REPLACE INTO client_passwords (client_id,password_hash,created_at)
            VALUES (:cid,:ph,:ts)"""),
            {"cid": demo_id, "ph": _hash_new("demo"), "ts": ts})
    return {"client_id": demo_id, "token": _make_token(demo_id)}


# ── Admin — Client management ─────────────────────────────────────────────────

_PAGE_SIZE = 20

@app.get("/admin/clients")
def admin_list_clients(request: Request, page: int = 1):
    _check_admin(request)
    offset = (page - 1) * _PAGE_SIZE
    with engine.connect() as conn:
        total = conn.execute(text("SELECT COUNT(*) FROM thresholds")).scalar() or 0
        rows = conn.execute(text("""
            SELECT t.client_id,t.min_temp,t.max_temp,
                   COUNT(DISTINCT sh.sensor_id) as sensor_count,
                   cp.created_at
            FROM thresholds t
            LEFT JOIN sensor_health sh ON t.client_id=sh.client_id
            LEFT JOIN client_passwords cp ON t.client_id=cp.client_id
            GROUP BY t.client_id ORDER BY t.client_id
            LIMIT :limit OFFSET :offset"""),
            {"limit": _PAGE_SIZE, "offset": offset}).fetchall()
        sh_only = conn.execute(text("""
            SELECT DISTINCT sh.client_id FROM sensor_health sh
            WHERE sh.client_id NOT IN (SELECT client_id FROM thresholds)""")).fetchall()
    result = [{"client_id":r[0],"min_temp":r[1],"max_temp":r[2],
               "sensor_count":r[3],"has_password":r[4] is not None} for r in rows]
    for r in sh_only:
        result.append({"client_id":r[0],"min_temp":None,"max_temp":None,
                       "sensor_count":0,"has_password":False})
    return {"page": page, "page_size": _PAGE_SIZE, "total": total, "clients": result}

@app.post("/admin/clients")
def admin_create_client(request: Request, body: AdminClientCreate):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO thresholds
              (client_id,min_temp,max_temp,alert_active,reactivate,alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,:min,:max,0,1,0,0,60)
            ON CONFLICT(client_id) DO UPDATE SET min_temp=excluded.min_temp,max_temp=excluded.max_temp"""),
            {"cid": body.client_id, "min": body.min_temp, "max": body.max_temp})
        conn.execute(text("""
            INSERT OR REPLACE INTO client_passwords (client_id,password_hash,created_at)
            VALUES (:cid,:ph,:ts)"""),
            {"cid": body.client_id, "ph": _hash_new(body.password), "ts": ts})
    return {"status": "created", "client_id": body.client_id}

@app.get("/admin/clients/{client_id}")
def admin_get_client(client_id: str, request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        thresh = conn.execute(text(
            "SELECT min_temp,max_temp,alert_active,alert_delay_mins,offline_after_mins,messages_sent,COALESCE(data_retention_years,5) FROM thresholds WHERE client_id=:cid"),
            {"cid": client_id}).fetchone()
        sensors = conn.execute(text("""
            SELECT si.sensor_id,si.hardware_id,si.notes,sh.last_seen,sh.battery_level,sh.plate,sh.last_lat,sh.last_lng
            FROM sensor_inventory si
            LEFT JOIN sensor_health sh ON si.sensor_id=sh.sensor_id AND si.client_id=sh.client_id
            WHERE si.client_id=:cid ORDER BY si.sensor_id"""), {"cid": client_id}).fetchall()
        legacy_sh = conn.execute(text(
            "SELECT sensor_id,NULL,NULL,last_seen,battery_level,plate,last_lat,last_lng FROM sensor_health WHERE client_id=:cid ORDER BY sensor_id"),
            {"cid": client_id}).fetchall()
        contacts = conn.execute(text(
            "SELECT type,value FROM contacts WHERE client_id=:cid"), {"cid": client_id}).fetchall()
        recent_alerts = conn.execute(text(
            "SELECT sensor_id,temperature,direction,timestamp FROM alerts WHERE client_id=:cid ORDER BY timestamp DESC LIMIT 10"),
            {"cid": client_id}).fetchall()
        alarm_rules = conn.execute(text(
            "SELECT name,sensor_id,min_temp,max_temp,alert_delay_mins,status FROM alarm_rules WHERE client_id=:cid ORDER BY created_at"),
            {"cid": client_id}).fetchall()
        reading_count = conn.execute(text(
            "SELECT COUNT(*) FROM readings WHERE client_id=:cid"), {"cid": client_id}).scalar() or 0
        pw_row = conn.execute(text(
            "SELECT created_at FROM client_passwords WHERE client_id=:cid"), {"cid": client_id}).fetchone()

    inv_ids = {r[0] for r in sensors}
    all_sensors = [{"sensor_id":r[0],"hardware_id":r[1],"notes":r[2],"last_seen":r[3],"battery":r[4],"plate":r[5],"lat":r[6],"lng":r[7]} for r in sensors]
    for r in legacy_sh:
        if r[0] not in inv_ids:
            all_sensors.append({"sensor_id":r[0],"hardware_id":None,"notes":"legacy","last_seen":r[3],"battery":r[4],"plate":r[5],"lat":r[6],"lng":r[7]})

    return {
        "client_id": client_id,
        "threshold": {"min_temp":thresh[0],"max_temp":thresh[1],"alert_active":thresh[2],
                      "alert_delay_mins":thresh[3],"offline_after_mins":thresh[4],
                      "messages_sent":thresh[5],"data_retention_years":thresh[6]} if thresh else None,
        "sensors": all_sensors,
        "contacts": [{"type":r[0],"value":r[1]} for r in contacts],
        "recent_alerts": [{"sensor_id":r[0],"temperature":r[1],"direction":r[2],"timestamp":r[3]} for r in recent_alerts],
        "alarm_rules": [{"name":r[0],"sensor_id":r[1],"min_temp":r[2],"max_temp":r[3],"delay":r[4],"status":r[5]} for r in alarm_rules],
        "reading_count": reading_count,
        "has_password": pw_row is not None,
        "created_at": pw_row[0] if pw_row else None,
    }

@app.delete("/admin/clients/{client_id}")
def admin_delete_client(client_id: str, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM thresholds WHERE client_id=:cid"),                  {"cid": client_id})
        conn.execute(text("DELETE FROM client_passwords WHERE client_id=:cid"),            {"cid": client_id})
        conn.execute(text("DELETE FROM contacts WHERE client_id=:cid"),                    {"cid": client_id})
        conn.execute(text("DELETE FROM readings WHERE client_id=:cid"),                    {"cid": client_id})
        conn.execute(text("DELETE FROM alerts WHERE client_id=:cid"),                      {"cid": client_id})
        conn.execute(text("DELETE FROM sensor_health WHERE client_id=:cid"),               {"cid": client_id})
        conn.execute(text("DELETE FROM sensor_assignments WHERE client_id=:cid"),          {"cid": client_id})
        conn.execute(text("DELETE FROM alarm_rules WHERE client_id=:cid"),                 {"cid": client_id})
        conn.execute(text("DELETE FROM vehicle_assignments WHERE client_id=:cid"),         {"cid": client_id})
        conn.execute(text("DELETE FROM sensor_inventory WHERE client_id=:cid"),            {"cid": client_id})
        conn.execute(text("DELETE FROM ble_sensors WHERE client_id=:cid"),                 {"cid": client_id})
        # GPS vehicle assignments and BLE sensor assignments are keyed by IMEI, not client_id
        # Clean up via device_registry which is client-scoped
        imeis = [r[0] for r in conn.execute(text(
            "SELECT imei FROM device_registry WHERE client_id=:cid"), {"cid": client_id}).fetchall()]
        for imei in imeis:
            conn.execute(text("DELETE FROM gps_vehicle_assignments WHERE imei=:imei"), {"imei": imei})
            conn.execute(text("DELETE FROM ble_sensor_assignments WHERE device_imei=:imei"), {"imei": imei})
        conn.execute(text("DELETE FROM device_registry WHERE client_id=:cid"),             {"cid": client_id})
    return {"status": "deleted"}


# ── Admin — Stripe subscription management ────────────────────────────────────

class SubscriptionAssign(BaseModel):
    plan: str  # "starter" | "growth" | "fleet"

@app.post("/admin/clients/{client_id}/subscription")
def assign_subscription(client_id: str, body: SubscriptionAssign, request: Request):
    _check_admin(request)
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured — set STRIPE_SECRET_KEY in .env")
    import stripe as _stripe
    _stripe.api_key = STRIPE_SECRET_KEY
    plan_prices = {"starter": STRIPE_PRICE_STARTER, "growth": STRIPE_PRICE_GROWTH, "fleet": STRIPE_PRICE_FLEET}
    price_id = plan_prices.get(body.plan)
    if not price_id:
        raise HTTPException(400, f"Unknown plan '{body.plan}'. Valid: starter, growth, fleet")
    if not price_id:
        raise HTTPException(503, f"Stripe price ID for plan '{body.plan}' not configured")

    with engine.connect() as conn:
        billing = conn.execute(text(
            "SELECT stripe_customer_id, stripe_subscription_id FROM client_billing WHERE client_id=:cid"),
            {"cid": client_id}).fetchone()

    customer_id = billing[0] if billing else None
    old_sub_id  = billing[1] if billing else None

    try:
        if not customer_id:
            customer = _stripe.Customer.create(metadata={"polarix_client_id": client_id})
            customer_id = customer.id

        if old_sub_id:
            _stripe.Subscription.cancel(old_sub_id)

        subscription = _stripe.Subscription.create(
            customer=customer_id,
            items=[{"price": price_id}],
            metadata={"polarix_client_id": client_id, "plan": body.plan},
        )
        period_end = datetime.utcfromtimestamp(subscription.current_period_end).isoformat()

        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO client_billing
                  (client_id,stripe_customer_id,stripe_subscription_id,plan,subscription_status,current_period_end)
                VALUES (:cid,:cust,:sub,:plan,:status,:end)
                ON CONFLICT(client_id) DO UPDATE SET
                  stripe_customer_id=excluded.stripe_customer_id,
                  stripe_subscription_id=excluded.stripe_subscription_id,
                  plan=excluded.plan,
                  subscription_status=excluded.subscription_status,
                  current_period_end=excluded.current_period_end"""),
                {"cid": client_id, "cust": customer_id, "sub": subscription.id,
                 "plan": body.plan, "status": subscription.status, "end": period_end})

        return {"status": "ok", "subscription_id": subscription.id,
                "plan": body.plan, "subscription_status": subscription.status,
                "current_period_end": period_end}
    except Exception as e:
        raise HTTPException(502, f"Stripe error: {e}")


@app.get("/admin/clients/{client_id}/subscription")
def get_subscription(client_id: str, request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT stripe_customer_id,stripe_subscription_id,plan,subscription_status,current_period_end "
            "FROM client_billing WHERE client_id=:cid"), {"cid": client_id}).fetchone()
    if not row or not row[1]:
        return {"subscription_status": "none", "plan": None, "current_period_end": None}

    if STRIPE_SECRET_KEY:
        try:
            import stripe as _stripe
            _stripe.api_key = STRIPE_SECRET_KEY
            sub = _stripe.Subscription.retrieve(row[1])
            period_end = datetime.utcfromtimestamp(sub.current_period_end).isoformat()
            with engine.begin() as conn:
                conn.execute(text(
                    "UPDATE client_billing SET subscription_status=:s,current_period_end=:e WHERE client_id=:cid"),
                    {"s": sub.status, "e": period_end, "cid": client_id})
            return {"subscription_id": row[1], "plan": row[2],
                    "subscription_status": sub.status, "current_period_end": period_end}
        except Exception:
            pass

    return {"subscription_id": row[1], "plan": row[2],
            "subscription_status": row[3], "current_period_end": row[4]}


@app.delete("/admin/clients/{client_id}/subscription")
def cancel_subscription(client_id: str, request: Request):
    _check_admin(request)
    if not STRIPE_SECRET_KEY:
        raise HTTPException(503, "Stripe not configured — set STRIPE_SECRET_KEY in .env")
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT stripe_subscription_id FROM client_billing WHERE client_id=:cid"),
            {"cid": client_id}).fetchone()
    if not row or not row[0]:
        raise HTTPException(404, "No active subscription for this client")
    try:
        import stripe as _stripe
        _stripe.api_key = STRIPE_SECRET_KEY
        sub = _stripe.Subscription.modify(row[0], cancel_at_period_end=True)
        period_end = datetime.utcfromtimestamp(sub.current_period_end).isoformat()
        with engine.begin() as conn:
            conn.execute(text(
                "UPDATE client_billing SET subscription_status=:s,current_period_end=:e WHERE client_id=:cid"),
                {"s": sub.status, "e": period_end, "cid": client_id})
        return {"status": "cancelled_at_period_end", "current_period_end": period_end}
    except Exception as e:
        raise HTTPException(502, f"Stripe error: {e}")


# ── Admin — Sensor inventory ──────────────────────────────────────────────────

@app.get("/admin/sensors")
def admin_list_sensors(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT si.id,si.hardware_id,si.sensor_id,si.client_id,si.notes,
                   si.registered_at,si.assigned_at,
                   sh.last_seen,sh.battery_level,sh.plate,sh.last_lat,sh.last_lng
            FROM sensor_inventory si
            LEFT JOIN sensor_health sh ON si.sensor_id=sh.sensor_id AND si.client_id=sh.client_id
            ORDER BY si.registered_at DESC""")).fetchall()
    return [{"id":r[0],"hardware_id":r[1],"sensor_id":r[2],"client_id":r[3],
             "notes":r[4],"registered_at":r[5],"assigned_at":r[6],
             "last_seen":r[7],"battery_level":r[8],"plate":r[9],
             "lat":r[10],"lng":r[11]} for r in rows]

@app.post("/admin/sensors")
def admin_register_sensor(request: Request, body: SensorRegister):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO sensor_inventory (hardware_id,sensor_id,client_id,notes,registered_at,assigned_at)
                VALUES (:hw,:sid,:cid,:notes,:ts,:ats)"""),
                {"hw": body.hardware_id.strip().upper(), "sid": body.sensor_id,
                 "cid": body.client_id, "notes": body.notes.strip(),
                 "ts": ts, "ats": ts if body.client_id.strip() else None})
    except Exception:
        raise HTTPException(409, "Hardware ID already registered")
    return {"status": "registered"}

@app.put("/admin/sensors/{sensor_id}/assign")
def admin_assign_sensor(sensor_id: int, request: Request, body: SensorAssignToClient):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text(
            "UPDATE sensor_inventory SET client_id=:cid,assigned_at=:ts WHERE id=:id"),
            {"cid": body.client_id.strip(),
             "ts": ts if body.client_id.strip() else None,
             "id": sensor_id})
    return {"status": "assigned"}

@app.delete("/admin/sensors/{sensor_id}")
def admin_delete_sensor(sensor_id: int, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM sensor_inventory WHERE id=:id"), {"id": sensor_id})
    return {"status": "deleted"}


@app.get("/admin/moving_count")
def admin_moving_count(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        pairs = conn.execute(text(
            "SELECT DISTINCT sensor_id,client_id FROM sensor_health WHERE last_lat IS NOT NULL AND last_lng IS NOT NULL")).fetchall()
        moving = 0
        for sensor_id, client_id in pairs:
            pts = conn.execute(text("""
                SELECT lat,lng,timestamp FROM readings
                WHERE sensor_id=:sid AND client_id=:cid AND lat IS NOT NULL AND lng IS NOT NULL
                ORDER BY timestamp DESC LIMIT 2"""),
                {"sid": sensor_id, "cid": client_id}).fetchall()
            if len(pts) < 2: continue
            p1, p2 = pts[0], pts[1]
            dt_sec = (datetime.fromisoformat(p1[2]) - datetime.fromisoformat(p2[2])).total_seconds()
            if dt_sec <= 0: continue
            dlat = math.radians(p2[0] - p1[0]); dlng = math.radians(p2[1] - p1[1])
            a = math.sin(dlat/2)**2 + math.cos(math.radians(p1[0]))*math.cos(math.radians(p2[0]))*math.sin(dlng/2)**2
            dist_m = 6371000 * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
            if (dist_m / dt_sec) * 3.6 > 2: moving += 1
    return {"moving": moving, "total_with_gps": len(pairs)}


@app.get("/admin/status")
def admin_status(request: Request):
    _check_admin(request)
    return {
        "twilio_sid":    bool(os.getenv("TWILIO_SID")),
        "twilio_token":  bool(os.getenv("TWILIO_TOKEN")),
        "twilio_from":   bool(os.getenv("TWILIO_FROM")),
        "smtp_user":     bool(os.getenv("SMTP_USER")),
        "smtp_pass":     bool(os.getenv("SMTP_PASS")),
        "admin_key_set": bool(ADMIN_KEY),
        "jwt_set":       bool(JWT_SECRET),
        "database_url":  DATABASE_URL.split("://")[0],
    }


# ── Admin: SQLite backup ──────────────────────────────────────────────────────

@app.post("/admin/backup")
def admin_trigger_backup(request: Request):
    """Run an immediate SQLite backup and return its metadata."""
    _check_admin(request)
    return run_sqlite_backup()


@app.get("/admin/backups")
def admin_list_backups(request: Request):
    """List all available SQLite backups (newest first)."""
    _check_admin(request)
    if not _is_sqlite():
        return {"enabled": False, "reason": "DATABASE_URL is not sqlite", "backups": []}
    if not os.path.isdir(BACKUP_DIR):
        return {"enabled": True, "backups": [], "retention_days": BACKUP_RETENTION_DAYS}
    files = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not (fname.startswith("canary_") and fname.endswith(".db")):
            continue
        fp = os.path.join(BACKUP_DIR, fname)
        try:
            files.append({"file": fname, "size_bytes": os.path.getsize(fp),
                          "created": datetime.utcfromtimestamp(os.path.getmtime(fp)).isoformat()})
        except Exception:
            pass
    return {"enabled": True, "backups": files, "retention_days": BACKUP_RETENTION_DAYS}


@app.post("/admin/clients/{client_id}/purge_orphans")
def admin_purge_orphans(client_id: str, request: Request, dry_run: int = 0):
    """Delete orphan sensor data for a client.
    Orphans = sensor_health rows with sensor_ids not in device_registry or ble_sensors.
    dry_run=1: preview only, no deletion.
    """
    _check_admin(request)
    with engine.connect() as conn:
        gps_sids = {r[0] for r in conn.execute(text(
            "SELECT sensor_id FROM device_registry WHERE client_id=:cid"), {"cid": client_id}).fetchall()}
        eye_macs = {r[0] for r in conn.execute(text(
            "SELECT mac_address FROM ble_sensors WHERE client_id=:cid"), {"cid": client_id}).fetchall()}
        known = gps_sids | eye_macs
        all_sh = {r[0] for r in conn.execute(text(
            "SELECT sensor_id FROM sensor_health WHERE client_id=:cid"), {"cid": client_id}).fetchall()}
        orphan_sids = list(all_sh - known)

    if dry_run:
        # Count orphan readings without deleting
        reading_count = 0
        with engine.connect() as conn:
            for sid in orphan_sids:
                cnt = conn.execute(text(
                    "SELECT COUNT(*) FROM readings WHERE client_id=:cid AND sensor_id=:sid"),
                    {"cid": client_id, "sid": sid}).scalar() or 0
                reading_count += cnt
        return {
            "orphan_sensors": orphan_sids,
            "registered_gps": len(gps_sids),
            "registered_eye": len(eye_macs),
            "orphan_reading_count": reading_count,
        }

    if not orphan_sids:
        return {"deleted_sensors": [], "deleted_readings": 0, "deleted_alerts": 0}

    deleted_readings = 0; deleted_alerts = 0
    with engine.begin() as conn:
        for sid in orphan_sids:
            conn.execute(text(
                "DELETE FROM sensor_health WHERE client_id=:cid AND sensor_id=:sid"),
                {"cid": client_id, "sid": sid})
            r = conn.execute(text(
                "DELETE FROM readings WHERE client_id=:cid AND sensor_id=:sid"),
                {"cid": client_id, "sid": sid})
            deleted_readings += r.rowcount
            r = conn.execute(text(
                "DELETE FROM alerts WHERE client_id=:cid AND sensor_id=:sid"),
                {"cid": client_id, "sid": sid})
            deleted_alerts += r.rowcount

    return {"deleted_sensors": orphan_sids, "deleted_readings": deleted_readings,
            "deleted_alerts": deleted_alerts}


@app.get("/notifier_status")
def notifier_status():
    """Public endpoint — returns which alert channels are configured (no secrets exposed)."""
    return {
        "whatsapp": bool(os.getenv("TWILIO_SID") and os.getenv("TWILIO_TOKEN") and os.getenv("TWILIO_FROM")),
        "sms":      bool(os.getenv("TWILIO_SID") and os.getenv("TWILIO_TOKEN")),
        "email":    bool(os.getenv("SMTP_USER") and os.getenv("SMTP_PASS")),
    }


# ── Device registry (Teltonika IMEI mapping) ──────────────────────────────────

@app.post("/admin/register_device")
def register_device(d: DeviceRegistryCreate, request: Request):
    _check_admin(request)
    # Auto-derive sensor_id from IMEI tail if not provided
    sid = d.sensor_id or f"gps-{d.imei[-6:]}"
    rms_id = d.rms_device_id.strip() if d.rms_device_id else ""
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO device_registry (imei, sensor_id, client_id, notes, registered_at, rms_device_id, serial_number)
            VALUES (:imei, :sid, :cid, :notes, :ts, :rms, :sn)
            ON CONFLICT(imei) DO UPDATE SET
              sensor_id=excluded.sensor_id,
              client_id=excluded.client_id,
              notes=excluded.notes,
              rms_device_id=excluded.rms_device_id,
              serial_number=excluded.serial_number"""),
            {"imei": d.imei, "sid": sid, "cid": d.client_id,
             "notes": d.notes, "ts": ts, "rms": rms_id, "sn": d.serial_number})
        # Ensure client has a thresholds row so they can log in
        conn.execute(text("""
            INSERT OR IGNORE INTO thresholds (client_id,min_temp,max_temp,alert_active,reactivate,
              alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,2.0,8.0,0,1,0,0,60)"""), {"cid": d.client_id})
    return {"status": "registered", "sensor_id": sid}


@app.get("/admin/devices")
def list_devices(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT imei, sensor_id, client_id, notes, registered_at, COALESCE(rms_device_id,''), COALESCE(serial_number,'') "
            "FROM device_registry ORDER BY registered_at DESC")).fetchall()
    return [{"imei": r[0], "sensor_id": r[1], "client_id": r[2],
             "notes": r[3], "registered_at": r[4], "rms_device_id": r[5], "serial_number": r[6]} for r in rows]


@app.delete("/admin/devices/{imei}")
def delete_device(imei: str, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM device_registry WHERE imei=:imei"), {"imei": imei})
    return {"status": "deleted"}


class DevicePatch(BaseModel):
    serial_number: Optional[str] = None
    notes: Optional[str] = None


@app.patch("/admin/devices/{imei}")
def patch_device(imei: str, body: DevicePatch, request: Request):
    _check_admin(request)
    updates = {}
    if body.serial_number is not None:
        updates["serial_number"] = body.serial_number.strip()
    if body.notes is not None:
        updates["notes"] = body.notes.strip()
    if not updates:
        return {"status": "no_change"}
    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    updates["imei"] = imei
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE device_registry SET {set_clause} WHERE imei=:imei"), updates)
    return {"status": "updated"}


# ── GPS Vehicle Assignments ────────────────────────────────────────────────────

@app.get("/admin/gps_vehicle_assignments")
def list_gps_vehicle_assignments(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT g.id, g.imei, g.plate, g.assigned_at,
                   d.sensor_id, d.client_id, d.notes
            FROM gps_vehicle_assignments g
            LEFT JOIN device_registry d ON d.imei = g.imei
            WHERE g.unassigned_at IS NULL
            ORDER BY g.assigned_at DESC""")).fetchall()
    return [{"id": r[0], "imei": r[1], "plate": r[2], "assigned_at": r[3],
             "sensor_id": r[4], "client_id": r[5], "notes": r[6]} for r in rows]


@app.get("/admin/gps_vehicle_assignment_history")
def gps_vehicle_assignment_history(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT g.id, g.imei, g.plate, g.assigned_at, g.unassigned_at,
                   d.sensor_id, d.client_id
            FROM gps_vehicle_assignments g
            LEFT JOIN device_registry d ON d.imei = g.imei
            ORDER BY g.assigned_at DESC LIMIT 200""")).fetchall()
    return [{"id": r[0], "imei": r[1], "plate": r[2], "assigned_at": r[3],
             "unassigned_at": r[4], "sensor_id": r[5], "client_id": r[6]} for r in rows]


@app.post("/admin/gps_vehicle_assignments")
def assign_gps_to_vehicle(d: GpsVehicleAssign, request: Request):
    _check_admin(request)
    now = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        # Verify IMEI is registered
        dev = conn.execute(text(
            "SELECT sensor_id, client_id FROM device_registry WHERE imei=:imei"),
            {"imei": d.imei}).fetchone()
        if not dev:
            raise HTTPException(404, "IMEI not registered in device registry")
        # Unassign any active assignment for this IMEI
        conn.execute(text("""
            UPDATE gps_vehicle_assignments SET unassigned_at=:now
            WHERE imei=:imei AND unassigned_at IS NULL"""), {"now": now, "imei": d.imei})
        # Create new assignment
        conn.execute(text("""
            INSERT INTO gps_vehicle_assignments (imei, plate, assigned_at)
            VALUES (:imei, :plate, :now)"""), {"imei": d.imei, "plate": d.plate, "now": now})
        # Mirror to sensor_assignments so the plate shows in the client dashboard
        conn.execute(text("""
            UPDATE sensor_assignments SET unassigned_at=:now
            WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"""),
            {"now": now, "sid": dev[0], "cid": dev[1]})
        conn.execute(text("""
            INSERT INTO sensor_assignments (sensor_id, client_id, plate, assigned_at)
            VALUES (:sid, :cid, :plate, :now)"""),
            {"sid": dev[0], "cid": dev[1], "plate": d.plate, "now": now})
        # Mirror to vehicle_assignments so it appears in client dashboard
        conn.execute(text("""
            UPDATE vehicle_assignments SET unassigned_at=:now
            WHERE client_id=:cid AND imei=:imei AND unassigned_at IS NULL"""),
            {"now": now, "cid": dev[1], "imei": d.imei})
        conn.execute(text("""
            INSERT INTO vehicle_assignments (client_id,imei,eye_mac,plate,driver_name,notes,assigned_at)
            VALUES (:cid,:imei,'',  :plate,'',    '',    :now)"""),
            {"cid": dev[1], "imei": d.imei, "plate": d.plate, "now": now})
    return {"status": "assigned", "imei": d.imei, "plate": d.plate}


@app.delete("/admin/gps_vehicle_assignments/{imei}")
def unassign_gps_from_vehicle(imei: str, request: Request):
    _check_admin(request)
    now = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        dev = conn.execute(text(
            "SELECT sensor_id, client_id FROM device_registry WHERE imei=:imei"),
            {"imei": imei}).fetchone()
        conn.execute(text("""
            UPDATE gps_vehicle_assignments SET unassigned_at=:now
            WHERE imei=:imei AND unassigned_at IS NULL"""), {"now": now, "imei": imei})
        if dev:
            conn.execute(text("""
                UPDATE sensor_assignments SET unassigned_at=:now
                WHERE sensor_id=:sid AND client_id=:cid AND unassigned_at IS NULL"""),
                {"now": now, "sid": dev[0], "cid": dev[1]})
    return {"status": "unassigned"}


# ── Admin: reset client password ──────────────────────────────────────────────

@app.post("/admin/clients/{client_id}/reset_password")
def admin_reset_password(client_id: str, body: ResetPassword, request: Request):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT OR IGNORE INTO thresholds (client_id,min_temp,max_temp,alert_active,reactivate,
              alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,2.0,8.0,0,1,0,0,60)"""), {"cid": client_id})
        conn.execute(text("""
            INSERT OR REPLACE INTO client_passwords (client_id,password_hash,created_at)
            VALUES (:cid,:ph,:ts)"""),
            {"cid": client_id, "ph": _hash_new(body.new_password), "ts": ts})
    return {"status": "reset", "client_id": client_id}


@app.patch("/admin/clients/{client_id}/retention")
def admin_set_retention(client_id: str, request: Request, years: int = 5):
    """Admin-only: set data_retention_years for a client (default 5)."""
    _check_admin(request)
    if years < 1 or years > 10:
        raise HTTPException(400, "data_retention_years must be between 1 and 10")
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT OR IGNORE INTO thresholds
              (client_id,min_temp,max_temp,alert_active,reactivate,
               alert_delay_mins,messages_sent,offline_after_mins,data_retention_years)
            VALUES (:cid,2.0,8.0,0,1,0,0,60,:yrs)"""),
            {"cid": client_id, "yrs": years})
        conn.execute(text("""
            UPDATE thresholds SET data_retention_years=:yrs WHERE client_id=:cid"""),
            {"yrs": years, "cid": client_id})
        conn.execute(text("""
            INSERT INTO threshold_history
              (client_id,changed_at,min_temp,max_temp,alert_delay_mins,
               offline_after_mins,data_retention_years)
            SELECT :cid,:ts,min_temp,max_temp,alert_delay_mins,
                   offline_after_mins,:yrs
            FROM thresholds WHERE client_id=:cid"""),
            {"cid": client_id, "ts": datetime.utcnow().isoformat(), "yrs": years})
    return {"status": "updated", "data_retention_years": years}


@app.post("/admin/clients/{client_id}/purge_orphans")
def admin_purge_orphans(client_id: str, request: Request, dry_run: int = 0):
    """Delete sensor_health rows and (optionally) readings whose sensor_id is
    NOT registered in device_registry OR ble_sensors for this client.
    Useful when a client has "ghost" sensors from before registration was tight.

    Set dry_run=1 to preview counts without deleting anything.
    """
    _check_admin(request)
    with engine.connect() as conn:
        known_gps = set(r[0] for r in conn.execute(text(
            "SELECT sensor_id FROM device_registry WHERE client_id=:cid"),
            {"cid": client_id}).fetchall() if r[0])
        known_eye = set(r[0] for r in conn.execute(text(
            "SELECT mac_address FROM ble_sensors WHERE client_id=:cid"),
            {"cid": client_id}).fetchall() if r[0])
        known = known_gps | known_eye
        all_health = [r[0] for r in conn.execute(text(
            "SELECT sensor_id FROM sensor_health WHERE client_id=:cid"),
            {"cid": client_id}).fetchall()]
        orphans = [sid for sid in all_health if sid not in known]
        reading_count = 0
        if orphans:
            reading_count = conn.execute(text(
                "SELECT COUNT(*) FROM readings WHERE client_id=:cid AND sensor_id IN :sids"
            ).bindparams(__import__("sqlalchemy").bindparam("sids", expanding=True)),
                {"cid": client_id, "sids": orphans}).scalar() or 0

    if dry_run:
        return {"status": "dry_run", "client_id": client_id,
                "registered_gps": len(known_gps), "registered_eye": len(known_eye),
                "orphan_sensors": orphans, "orphan_reading_count": reading_count}

    if not orphans:
        return {"status": "ok", "deleted_sensors": [], "deleted_readings": 0}

    with engine.begin() as conn:
        for sid in orphans:
            conn.execute(text(
                "DELETE FROM readings WHERE client_id=:cid AND sensor_id=:sid"),
                {"cid": client_id, "sid": sid})
            conn.execute(text(
                "DELETE FROM sensor_health WHERE client_id=:cid AND sensor_id=:sid"),
                {"cid": client_id, "sid": sid})
    return {"status": "purged", "client_id": client_id,
            "deleted_sensors": orphans, "deleted_readings": reading_count}


@app.patch("/admin/clients/{client_id}/can_import")
def admin_set_can_import(client_id: str, request: Request, enabled: int = 0):
    """Admin-only: grant or revoke CSV import permission for a client."""
    _check_admin(request)
    if enabled not in (0, 1):
        raise HTTPException(400, "enabled must be 0 or 1")
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT OR IGNORE INTO thresholds
              (client_id,min_temp,max_temp,alert_active,reactivate,
               alert_delay_mins,messages_sent,offline_after_mins)
            VALUES (:cid,2.0,8.0,0,1,0,0,60)"""), {"cid": client_id})
        conn.execute(text(
            "UPDATE thresholds SET can_import=:v WHERE client_id=:cid"),
            {"v": enabled, "cid": client_id})
    return {"status": "updated", "can_import": enabled}


# ── Admin: Vehicles ───────────────────────────────────────────────────────────

@app.get("/admin/vehicles")
def admin_list_vehicles(request: Request, client_id: str = ""):
    _check_admin(request)
    with engine.connect() as conn:
        q = "SELECT id,plate,client_id,label,created_at FROM vehicles"
        p: dict = {}
        if client_id:
            q += " WHERE client_id=:cid"; p["cid"] = client_id
        q += " ORDER BY plate"
        rows = conn.execute(text(q), p).fetchall()
    return [{"id": r[0], "plate": r[1], "client_id": r[2], "label": r[3], "created_at": r[4]} for r in rows]

@app.post("/admin/vehicles")
def admin_create_vehicle(v: VehicleCreate, request: Request):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        try:
            conn.execute(text("""
                INSERT INTO vehicles (plate,client_id,label,created_at)
                VALUES (:plate,:cid,:label,:ts)
                ON CONFLICT(plate,client_id) DO UPDATE SET label=excluded.label"""),
                {"plate": v.plate, "cid": v.client_id, "label": v.label, "ts": ts})
        except Exception as e:
            raise HTTPException(409, str(e))
    return {"status": "created", "plate": v.plate}

@app.delete("/admin/vehicles/{vehicle_id}")
def admin_delete_vehicle(vehicle_id: int, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM vehicles WHERE id=:id"), {"id": vehicle_id})
    return {"status": "deleted"}


# ── Admin: SIM Cards ──────────────────────────────────────────────────────────
# Track every SIM you insert into an FMB920. ICCID is the unique key. A SIM can
# be (un)assigned to a device IMEI; the assignment history is kept forever so
# admin can answer "which SIM was in vehicle X on date Y" and "what does this
# SIM cost me per month".

@app.get("/admin/sims")
def admin_list_sims(request: Request, client_id: str = "", status: str = ""):
    _check_admin(request)
    q = """SELECT s.id,s.iccid,s.phone_number,s.carrier,s.plan,s.status,
                  s.monthly_cost_eur,s.activated_at,s.expires_at,s.notes,s.created_at,
                  sa.imei,sa.client_id,sa.assigned_at
           FROM sim_cards s
           LEFT JOIN sim_assignments sa
             ON sa.sim_id=s.id AND sa.unassigned_at IS NULL
           WHERE 1=1"""
    p: dict = {}
    if status:
        q += " AND s.status=:st"; p["st"] = status.strip().lower()
    if client_id:
        q += " AND sa.client_id=:cid"; p["cid"] = client_id.strip()
    q += " ORDER BY s.created_at DESC"
    with engine.connect() as conn:
        rows = conn.execute(text(q), p).fetchall()
    return [{
        "id": r[0], "iccid": r[1], "phone_number": r[2], "carrier": r[3],
        "plan": r[4], "status": r[5], "monthly_cost_eur": r[6],
        "activated_at": r[7], "expires_at": r[8], "notes": r[9],
        "created_at": r[10],
        "assigned_imei": r[11] or "", "assigned_client_id": r[12] or "",
        "assigned_at": r[13] or "",
    } for r in rows]


@app.post("/admin/sims")
def admin_register_sim(s: SimCardCreate, request: Request):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        try:
            res = conn.execute(text("""
                INSERT INTO sim_cards (iccid,phone_number,carrier,plan,status,
                    monthly_cost_eur,activated_at,expires_at,notes,created_at)
                VALUES (:iccid,:phone,:carrier,:plan,:status,:cost,
                        :act,:exp,:notes,:ts)"""),
                {"iccid": s.iccid, "phone": s.phone_number, "carrier": s.carrier,
                 "plan": s.plan, "status": s.status, "cost": s.monthly_cost_eur,
                 "act": s.activated_at or None, "exp": s.expires_at or None,
                 "notes": s.notes, "ts": ts})
        except Exception as e:
            if "UNIQUE" in str(e):
                raise HTTPException(409, f"SIM with ICCID {s.iccid} already exists")
            raise
    return {"status": "registered", "iccid": s.iccid}


@app.patch("/admin/sims/{sim_id}")
def admin_update_sim(sim_id: int, body: SimCardUpdate, request: Request):
    _check_admin(request)
    updates = {k: v for k, v in body.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return {"status": "no-op"}
    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    updates["sim_id"] = sim_id
    with engine.begin() as conn:
        r = conn.execute(text(f"UPDATE sim_cards SET {set_clause} WHERE id=:sim_id"),
                          updates)
        if r.rowcount == 0:
            raise HTTPException(404, "SIM not found")
    return {"status": "updated"}


@app.delete("/admin/sims/{sim_id}")
def admin_delete_sim(sim_id: int, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        r = conn.execute(text("DELETE FROM sim_cards WHERE id=:id"), {"id": sim_id})
        if r.rowcount == 0:
            raise HTTPException(404, "SIM not found")
        # Close any open assignments (don't lose history)
        conn.execute(text(
            "UPDATE sim_assignments SET unassigned_at=:ts WHERE sim_id=:id AND unassigned_at IS NULL"),
            {"ts": datetime.utcnow().isoformat(), "id": sim_id})
    return {"status": "deleted"}


@app.get("/admin/sims/{sim_id}/history")
def admin_sim_history(sim_id: int, request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id,imei,client_id,assigned_at,unassigned_at,notes
            FROM sim_assignments WHERE sim_id=:id
            ORDER BY assigned_at DESC"""), {"id": sim_id}).fetchall()
    return [{"id": r[0], "imei": r[1], "client_id": r[2], "assigned_at": r[3],
             "unassigned_at": r[4], "notes": r[5] or ""} for r in rows]


@app.post("/admin/sims/{sim_id}/assign")
def admin_assign_sim(sim_id: int, body: SimAssign, request: Request):
    """Attach a SIM to an FMB920 (by IMEI). Closes any previous SIM assignment
    on the same SIM and any previous SIM on the same IMEI."""
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    # Auto-resolve client_id from device_registry if not given
    cid = body.client_id
    with engine.connect() as conn:
        sim = conn.execute(text("SELECT id FROM sim_cards WHERE id=:id"),
                           {"id": sim_id}).fetchone()
        if not sim:
            raise HTTPException(404, "SIM not found")
        if not cid:
            dev = conn.execute(text("SELECT client_id FROM device_registry WHERE imei=:imei"),
                               {"imei": body.imei}).fetchone()
            cid = dev[0] if dev else ""
    with engine.begin() as conn:
        # Close any current assignment of THIS SIM
        conn.execute(text(
            "UPDATE sim_assignments SET unassigned_at=:ts WHERE sim_id=:id AND unassigned_at IS NULL"),
            {"ts": ts, "id": sim_id})
        # Close any current SIM on THIS IMEI (one SIM per device)
        conn.execute(text(
            "UPDATE sim_assignments SET unassigned_at=:ts WHERE imei=:imei AND unassigned_at IS NULL"),
            {"ts": ts, "imei": body.imei})
        conn.execute(text("""
            INSERT INTO sim_assignments (sim_id,imei,client_id,assigned_at,notes)
            VALUES (:sid,:imei,:cid,:ts,:notes)"""),
            {"sid": sim_id, "imei": body.imei, "cid": cid, "ts": ts, "notes": body.notes})
    return {"status": "assigned", "client_id": cid}


@app.post("/admin/sims/{sim_id}/unassign")
def admin_unassign_sim(sim_id: int, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        r = conn.execute(text(
            "UPDATE sim_assignments SET unassigned_at=:ts "
            "WHERE sim_id=:id AND unassigned_at IS NULL"),
            {"ts": datetime.utcnow().isoformat(), "id": sim_id})
    return {"status": "unassigned" if r.rowcount else "no-op"}


# ── Admin: BLE Sensors ────────────────────────────────────────────────────────

@app.get("/admin/ble_sensors")
def admin_list_ble_sensors(request: Request, client_id: str = ""):
    _check_admin(request)
    with engine.connect() as conn:
        q = """SELECT bs.id, bs.mac_address, bs.client_id, bs.label,
                      bs.battery_level, bs.last_seen, bs.registered_at,
                      bsa.device_imei, bsa.assigned_at, COALESCE(bs.serial_number,'')
               FROM ble_sensors bs
               LEFT JOIN ble_sensor_assignments bsa
                 ON bsa.ble_sensor_id=bs.id AND bsa.unassigned_at IS NULL"""
        p: dict = {}
        if client_id:
            q += " WHERE bs.client_id=:cid"; p["cid"] = client_id
        q += " ORDER BY bs.registered_at DESC"
        rows = conn.execute(text(q), p).fetchall()
    return [{"id":r[0],"mac_address":r[1],"client_id":r[2],"label":r[3],
             "battery_level":r[4],"last_seen":r[5],"registered_at":r[6],
             "current_device_imei":r[7] or "","current_assigned_at":r[8],"serial_number":r[9]} for r in rows]

@app.post("/admin/ble_sensors")
def admin_register_ble_sensor(s: BleSensorCreate, request: Request):
    _check_admin(request)
    ts = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        try:
            conn.execute(text("""
                INSERT INTO ble_sensors (mac_address,client_id,serial_number,label,registered_at)
                VALUES (:mac,:cid,:sn,:label,:ts)
                ON CONFLICT(mac_address) DO UPDATE SET
                  client_id=excluded.client_id, serial_number=excluded.serial_number, label=excluded.label"""),
                {"mac": s.mac_address, "cid": s.client_id, "sn": s.serial_number, "label": s.label, "ts": ts})
        except Exception as e:
            raise HTTPException(409, str(e))
    return {"status": "registered"}

@app.delete("/admin/ble_sensors/{sensor_id}")
def admin_delete_ble_sensor(sensor_id: int, request: Request):
    _check_admin(request)
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM ble_sensors WHERE id=:id"), {"id": sensor_id})
    return {"status": "deleted"}


class BleSensorPatch(BaseModel):
    serial_number: Optional[str] = None
    label: Optional[str] = None


@app.patch("/admin/ble_sensors/{sensor_id}")
def admin_patch_ble_sensor(sensor_id: int, body: BleSensorPatch, request: Request):
    _check_admin(request)
    updates = {}
    if body.serial_number is not None:
        updates["serial_number"] = body.serial_number.strip()
    if body.label is not None:
        updates["label"] = body.label.strip()
    if not updates:
        return {"status": "no_change"}
    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    updates["id"] = sensor_id
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE ble_sensors SET {set_clause} WHERE id=:id"), updates)
    return {"status": "updated"}


# ── Admin: BLE Sensor Assignments & Reassign ──────────────────────────────────

@app.get("/admin/ble_sensor_assignments")
def admin_list_ble_assignments(request: Request):
    _check_admin(request)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT bsa.id, bs.mac_address, bs.label, bs.client_id,
                   bsa.device_imei, bsa.assigned_at, bsa.unassigned_at
            FROM ble_sensor_assignments bsa
            JOIN ble_sensors bs ON bs.id=bsa.ble_sensor_id
            ORDER BY bsa.assigned_at DESC LIMIT 200""")).fetchall()
    return [{"id":r[0],"mac_address":r[1],"label":r[2],"client_id":r[3],
             "device_imei":r[4],"assigned_at":r[5],"unassigned_at":r[6]} for r in rows]

@app.post("/admin/ble_sensor_assignments")
def admin_assign_ble_sensor(body: BleReassign, request: Request):
    _check_admin(request)
    now = datetime.utcnow().isoformat()
    with engine.begin() as conn:
        sensor = conn.execute(text("SELECT id FROM ble_sensors WHERE id=:id"), {"id": body.ble_sensor_id}).fetchone()
        if not sensor:
            raise HTTPException(404, "BLE sensor not found")
        device = conn.execute(text("SELECT imei FROM device_registry WHERE imei=:imei"), {"imei": body.new_device_imei}).fetchone()
        if not device:
            raise HTTPException(404, "GPS device IMEI not registered")
        conn.execute(text("""
            UPDATE ble_sensor_assignments SET unassigned_at=:now
            WHERE ble_sensor_id=:sid AND unassigned_at IS NULL"""),
            {"now": now, "sid": body.ble_sensor_id})
        conn.execute(text("""
            INSERT INTO ble_sensor_assignments (ble_sensor_id, device_imei, assigned_at)
            VALUES (:sid, :imei, :now)"""),
            {"sid": body.ble_sensor_id, "imei": body.new_device_imei, "now": now})
    rms_result = _push_ble_whitelist(body.new_device_imei)
    return {"status": "assigned", "rms": rms_result}

@app.post("/admin/reassign")
def admin_reassign(body: BleReassign, request: Request):
    """Reassign a BLE sensor to a new GPS device.
    Closes current assignment, opens new one, pushes BLE whitelist
    to both old and new GPS devices via Teltonika RMS API."""
    _check_admin(request)
    now = datetime.utcnow().isoformat()
    with engine.connect() as conn:
        sensor = conn.execute(text("SELECT id,mac_address,label FROM ble_sensors WHERE id=:id"),
            {"id": body.ble_sensor_id}).fetchone()
        if not sensor:
            raise HTTPException(404, "BLE sensor not found")
        device = conn.execute(text("SELECT imei FROM device_registry WHERE imei=:imei"),
            {"imei": body.new_device_imei}).fetchone()
        if not device:
            raise HTTPException(404, "GPS device IMEI not registered")
        old_asgn = conn.execute(text("""
            SELECT id, device_imei FROM ble_sensor_assignments
            WHERE ble_sensor_id=:sid AND unassigned_at IS NULL"""),
            {"sid": body.ble_sensor_id}).fetchone()
    old_imei = old_asgn[1] if old_asgn else None
    with engine.begin() as conn:
        if old_asgn:
            conn.execute(text("""
                UPDATE ble_sensor_assignments SET unassigned_at=:now WHERE id=:id"""),
                {"now": now, "id": old_asgn[0]})
        conn.execute(text("""
            INSERT INTO ble_sensor_assignments (ble_sensor_id, device_imei, assigned_at)
            VALUES (:sid, :imei, :now)"""),
            {"sid": body.ble_sensor_id, "imei": body.new_device_imei, "now": now})
    rms_new = _push_ble_whitelist(body.new_device_imei)
    rms_old = _push_ble_whitelist(old_imei) if old_imei and old_imei != body.new_device_imei else None
    return {
        "status": "reassigned",
        "sensor": {"id": sensor[0], "mac": sensor[1], "label": sensor[2]},
        "from_device": old_imei,
        "to_device": body.new_device_imei,
        "rms_new_device": rms_new,
        "rms_old_device": rms_old,
    }


# ── Client: BLE sensor view ───────────────────────────────────────────────────

@app.get("/ble_sensors/{client_id}")
def get_client_ble_sensors(client_id: str, request: Request):
    _check_client(request, client_id)
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT bs.id, bs.mac_address, bs.label, bs.battery_level, bs.last_seen,
                   bsa.device_imei, d.sensor_id AS gps_sensor_id, bsa.assigned_at,
                   COALESCE(bs.serial_number,'')
            FROM ble_sensors bs
            LEFT JOIN ble_sensor_assignments bsa ON bsa.ble_sensor_id=bs.id AND bsa.unassigned_at IS NULL
            LEFT JOIN device_registry d ON d.imei=bsa.device_imei
            WHERE bs.client_id=:cid ORDER BY bs.id"""), {"cid": client_id}).fetchall()
    return [{"id":r[0],"mac_address":r[1],"label":r[2],"battery_level":r[3],
             "last_seen":r[4],"device_imei":r[5] or "","gps_sensor_id":r[6] or "",
             "assigned_at":r[7],"serial_number":r[8]} for r in rows]
