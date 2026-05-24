"""
Polarix — Teltonika Codec 8 / Codec 8E TCP server.

Listens on TCP_PORT (default 8005).
Protocol:
  1. Device sends 2-byte big-endian IMEI length + IMEI string.
  2. Server responds 0x01 (accept) or 0x00 (reject/unknown IMEI).
  3. Device sends AVL data packets; server responds with accepted-record count.

AVL IO IDs used:
  72  — Temperature (2-byte signed int16, value × 10; e.g. 235 = 23.5 °C)
  113 — Battery level (1-byte uint8, 0–100 %)
"""
import asyncio
import struct
import logging
from datetime import datetime
from sqlalchemy import text

logger = logging.getLogger("teltonika")
TCP_PORT = 8005


# ── Codec 8 / 8E AVL decoder ──────────────────────────────────────────────────

def _read_uint(data: bytes, pos: int, size: int, signed: bool = False):
    fmt = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}[size]
    if signed and size in (2, 4, 8):
        fmt = fmt.replace("H", "h").replace("I", "i").replace("Q", "q")
    return struct.unpack_from(fmt, data, pos)[0], pos + size


def _decode_avl(payload: bytes, extended: bool) -> list:
    """
    Parse AVL records.
    payload starts at the byte after codec_id (i.e. Number-of-Data-1).
    """
    id_sz  = 2 if extended else 1
    cnt_sz = 2 if extended else 1

    pos = 0
    n_records = payload[pos]; pos += 1

    records = []
    for _ in range(n_records):
        # Timestamp — 8 bytes, ms since Unix epoch
        ts_ms, pos = _read_uint(payload, pos, 8)
        timestamp = datetime.utcfromtimestamp(ts_ms / 1000.0).isoformat()

        # Priority — 1 byte, ignored
        pos += 1

        # GPS element
        lng_raw, pos = _read_uint(payload, pos, 4, signed=True)
        lat_raw, pos = _read_uint(payload, pos, 4, signed=True)
        pos += 2  # altitude
        pos += 2  # angle
        sats = payload[pos]; pos += 1
        speed, pos = _read_uint(payload, pos, 2)

        lat = round(lat_raw / 1e7, 7)
        lng = round(lng_raw / 1e7, 7)
        has_fix = sats >= 1 and lat != 0.0 and lng != 0.0

        # IO element
        if extended:
            pos += 2  # event IO ID (2 bytes)
            pos += 2  # total IO count (2 bytes)
        else:
            pos += 1  # event IO ID (1 byte)
            pos += 1  # total IO count (1 byte)

        io: dict = {}
        for io_bytes in (1, 2, 4, 8):
            if extended:
                cnt, pos = _read_uint(payload, pos, 2)
            else:
                cnt = payload[pos]; pos += 1

            for _ in range(cnt):
                if extended:
                    io_id, pos = _read_uint(payload, pos, 2)
                else:
                    io_id = payload[pos]; pos += 1

                raw_val, pos = _read_uint(payload, pos, io_bytes)
                io[io_id] = raw_val

        # ── Extract meaningful values ──────────────────────────────────────
        # Temperature: IO ID 72, 2-byte signed int16, ×10
        temperature = None
        if 72 in io:
            raw_t = io[72]
            if raw_t >= 0x8000:   # two's complement
                raw_t -= 0x10000
            temperature = round(raw_t / 10.0, 1)

        # Battery: IO ID 113, 1-byte uint8, direct %
        battery = io.get(113)

        records.append({
            "timestamp":   timestamp,
            "lat":         lat if has_fix else None,
            "lng":         lng if has_fix else None,
            "speed":       speed,
            "satellites":  sats,
            "temperature": temperature,
            "battery":     battery,
        })

    return records


# ── Client handler ─────────────────────────────────────────────────────────────

async def _handle_client(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter,
                         engine) -> None:
    addr = writer.get_extra_info("peername")
    logger.info("[TCP] New connection from %s", addr)

    try:
        # ── IMEI handshake ───────────────────────────────────────────────────
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout=30)
        imei_len = struct.unpack(">H", hdr)[0]
        if imei_len > 50:
            logger.warning("[TCP] Implausible IMEI length %d from %s", imei_len, addr)
            return
        imei_raw = await asyncio.wait_for(reader.readexactly(imei_len), timeout=30)
        imei = imei_raw.decode("ascii", errors="ignore").strip()
        logger.info("[TCP] IMEI=%s from %s", imei, addr)

        # Lookup device registry
        with engine.connect() as conn:
            row = conn.execute(text(
                "SELECT sensor_id, client_id FROM device_registry WHERE imei=:imei"),
                {"imei": imei}).fetchone()

        if not row:
            logger.warning("[TCP] IMEI %s not in device_registry — rejecting", imei)
            writer.write(b"\x00")
            await writer.drain()
            return

        sensor_id, client_id = row[0], row[1]
        logger.info("[TCP] IMEI %s → sensor=%s client=%s", imei, sensor_id, client_id)
        writer.write(b"\x01")   # accept
        await writer.drain()

        # ── AVL data loop ────────────────────────────────────────────────────
        while not reader.at_eof():
            try:
                preamble = await asyncio.wait_for(reader.readexactly(4), timeout=120)
            except asyncio.TimeoutError:
                logger.debug("[TCP] Timeout waiting for data from %s", addr)
                break

            if preamble != b"\x00\x00\x00\x00":
                logger.warning("[TCP] Bad preamble %s from %s", preamble.hex(), addr)
                break

            data_len_b = await reader.readexactly(4)
            data_len = struct.unpack(">I", data_len_b)[0]
            if data_len > 65536:
                logger.warning("[TCP] Implausible data_len=%d", data_len)
                break

            payload = await reader.readexactly(data_len)
            _crc    = await reader.readexactly(4)   # CRC-16 not verified

            codec_id = payload[0]
            if codec_id == 0x08:
                extended = False
            elif codec_id == 0x8E:
                extended = True
            else:
                logger.warning("[TCP] Unsupported codec 0x%02X from %s", codec_id, addr)
                break

            try:
                records = _decode_avl(payload[1:], extended)
            except Exception as e:
                logger.error("[TCP] Decode error for %s: %s", imei, e)
                writer.write(struct.pack(">I", 0))
                await writer.drain()
                continue

            now_ts = datetime.utcnow().isoformat()
            for rec in records:
                try:
                    with engine.begin() as conn:
                        # GPS row — tagged 'gps' so charts/history show EYE Sensor rows only
                        conn.execute(text("""
                            INSERT INTO readings
                              (sensor_id, client_id, temperature, timestamp, lat, lng, reading_type)
                            VALUES (:sid, :cid, :temp, :ts, :lat, :lng, 'gps')"""),
                            {"sid": sensor_id, "cid": client_id,
                             "temp": rec["temperature"], "ts": rec["timestamp"],
                             "lat": rec["lat"], "lng": rec["lng"]})

                        conn.execute(text("""
                            INSERT INTO sensor_health
                              (sensor_id, client_id, last_seen, battery_level,
                               last_lat, last_lng, offline_alerted, battery_alerted)
                            VALUES (:sid, :cid, :ts, :bat, :lat, :lng, 0, 0)
                            ON CONFLICT(sensor_id, client_id) DO UPDATE SET
                              last_seen     = excluded.last_seen,
                              battery_level = COALESCE(excluded.battery_level,
                                                       sensor_health.battery_level),
                              last_lat      = COALESCE(excluded.last_lat,
                                                       sensor_health.last_lat),
                              last_lng      = COALESCE(excluded.last_lng,
                                                       sensor_health.last_lng),
                              offline_alerted = 0"""),
                            {"sid": sensor_id, "cid": client_id,
                             "ts": rec["timestamp"], "bat": rec["battery"],
                             "lat": rec["lat"], "lng": rec["lng"]})

                    if rec["battery"] and rec["battery"] > 25:
                        with engine.begin() as conn:
                            conn.execute(text(
                                "UPDATE sensor_health SET battery_alerted=0 "
                                "WHERE sensor_id=:sid AND client_id=:cid"),
                                {"sid": sensor_id, "cid": client_id})

                    # Temperature row — look up paired EYE Sensor MAC
                    if rec["temperature"] is not None:
                        with engine.connect() as conn:
                            eye_row = conn.execute(text("""
                                SELECT eye_mac FROM vehicle_assignments
                                WHERE client_id=:cid AND imei=:imei
                                  AND eye_mac != '' AND unassigned_at IS NULL
                                ORDER BY assigned_at DESC LIMIT 1"""),
                                {"cid": client_id, "imei": imei}).fetchone()
                        eye_mac = eye_row[0] if eye_row else None
                        temp_sid = eye_mac if eye_mac else sensor_id
                        with engine.begin() as conn:
                            conn.execute(text("""
                                INSERT INTO readings
                                  (sensor_id, client_id, temperature, timestamp, lat, lng, reading_type)
                                VALUES (:sid, :cid, :temp, :ts, NULL, NULL, 'temperature')"""),
                                {"sid": temp_sid, "cid": client_id,
                                 "temp": rec["temperature"], "ts": rec["timestamp"]})
                            conn.execute(text("""
                                INSERT INTO sensor_health
                                  (sensor_id, client_id, last_seen, offline_alerted, battery_alerted)
                                VALUES (:sid, :cid, :ts, 0, 0)
                                ON CONFLICT(sensor_id, client_id) DO UPDATE SET
                                  last_seen=excluded.last_seen, offline_alerted=0"""),
                                {"sid": temp_sid, "cid": client_id, "ts": rec["timestamp"]})

                    logger.debug("[TCP] Record from %s: temp=%s lat=%s lng=%s",
                                 sensor_id, rec["temperature"], rec["lat"], rec["lng"])

                except Exception as e:
                    logger.error("[TCP] DB insert error for %s: %s", sensor_id, e)

            # Acknowledge all received records (device will not retransmit)
            writer.write(struct.pack(">I", len(records)))
            await writer.drain()
            logger.info("[TCP] Processed %d record(s) from %s (%s)",
                        len(records), imei, addr)

    except asyncio.IncompleteReadError:
        logger.info("[TCP] Connection closed by %s", addr)
    except Exception as e:
        logger.error("[TCP] Unhandled error for %s: %s", addr, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── Public entry point ────────────────────────────────────────────────────────

async def run_tcp_server(engine) -> None:
    """Start Teltonika TCP server. Designed to run as an asyncio background task.
    On hosts that don't allow raw TCP (Railway, most PaaS), this skips silently —
    devices should be configured for HTTP mode and POST to /teltonika/http instead."""
    try:
        server = await asyncio.start_server(
            lambda r, w: _handle_client(r, w, engine),
            "0.0.0.0", TCP_PORT
        )
    except (OSError, PermissionError) as e:
        print(f"[Teltonika] TCP server disabled (port {TCP_PORT} unavailable: {e}). "
              f"Use HTTP mode: POST to /teltonika/http")
        return
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("[TCP] Teltonika server listening on %s", addrs)
    print(f"[Teltonika] TCP server listening on port {TCP_PORT}")
    async with server:
        await server.serve_forever()
