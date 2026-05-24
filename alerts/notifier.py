"""
Polarix - Alert Engine
Channels: WhatsApp, SMS (Twilio), Email (SMTP/Gmail)
Alert types: temperature breach, sensor offline, battery low

Email alerts activate automatically when SMTP_USER and SMTP_PASS are set in .env.
No code changes needed — see .env.example for Gmail App Password setup instructions.
"""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from twilio.rest import Client


# ── Shared helpers ─────────────────────────────────────────────────────────

def _twilio():
    return Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))


def _send_whatsapp(value, text):
    _twilio().messages.create(body=text, from_=os.getenv("TWILIO_FROM"), to=value)


def _send_sms(value, text):
    from_num = os.getenv("TWILIO_SMS_FROM") or os.getenv("TWILIO_FROM", "").replace("whatsapp:", "")
    _twilio().messages.create(body=text, from_=from_num, to=value)


def _send_email(to_addr, subject, text_body, html_body):
    host  = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port  = int(os.getenv("SMTP_PORT", "587"))
    user  = os.getenv("SMTP_USER", "")
    pwd   = os.getenv("SMTP_PASS", "")
    from_ = os.getenv("SMTP_FROM", user)
    if not user or not pwd:
        print("[EMAIL] SMTP_USER / SMTP_PASS not set — skipping")
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_
    msg["To"]      = to_addr
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))
    with smtplib.SMTP(host, port) as s:
        s.ehlo(); s.starttls(); s.login(user, pwd)
        s.sendmail(from_, to_addr, msg.as_string())


def _dispatch(contacts, text, subject, html_fn, *html_args):
    """Send to all contacts. One failure does not stop others."""
    for c in contacts:
        try:
            t, v = c["type"], c["value"]
            if   t == "whatsapp": _send_whatsapp(v, text);                         print(f"[ALERT] WA  → {v}")
            elif t == "sms":      _send_sms(v, text);                              print(f"[ALERT] SMS → {v}")
            elif t == "email":    _send_email(v, subject, text, html_fn(*html_args)); print(f"[ALERT] Email → {v}")
        except Exception as e:
            print(f"[ALERT ERROR] {c.get('type')} {c.get('value')}: {e}")


# ── Temperature breach ─────────────────────────────────────────────────────

def _temp_text(sensor_id, temperature, min_temp, max_temp):
    d = "TOO HIGH 🔴" if temperature > max_temp else "TOO LOW 🔵"
    return (f"🌡️ Polarix ALERT\n"
            f"Sensor : {sensor_id}\n"
            f"Temp   : {temperature}°C  ({d})\n"
            f"Range  : {min_temp}°C – {max_temp}°C\n"
            f"Check your cold chain immediately.")


def _temp_html(sensor_id, temperature, min_temp, max_temp):
    d     = "TOO HIGH" if temperature > max_temp else "TOO LOW"
    arrow = "↑" if temperature > max_temp else "↓"
    col   = "#f85149" if temperature > max_temp else "#388bfd"
    bg    = "#da363322" if temperature > max_temp else "#1f6feb22"
    bdr   = "#da363366" if temperature > max_temp else "#1f6feb66"
    dev   = abs(round(temperature - (max_temp if temperature > max_temp else min_temp), 1))
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1117;margin:0;padding:28px;font-family:-apple-system,sans-serif;">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;">
  <div style="background:#1f2937;padding:16px 22px;border-bottom:1px solid #30363d;">
    <span style="color:#58a6ff;font-size:15px;font-weight:700;">🌡️ Polarix</span>
    <span style="float:right;background:{bg};color:{col};border:1px solid {bdr};padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">TEMPERATURE ALERT</span>
  </div>
  <div style="text-align:center;padding:26px 22px 18px;">
    <div style="font-size:62px;font-weight:800;color:{col};line-height:1;">{temperature}°C</div>
    <div style="color:{col};font-size:17px;font-weight:700;margin-top:7px;">{arrow} {d}</div>
  </div>
  <div style="padding:0 22px 22px;">
    <table style="width:100%;border-collapse:collapse;color:#e6edf3;font-size:13px;">
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;width:130px;">Sensor</td><td style="padding:9px 0;font-weight:600;">{sensor_id}</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Safe range</td><td style="padding:9px 0;font-weight:600;">{min_temp}°C – {max_temp}°C</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Deviation</td><td style="padding:9px 0;font-weight:600;color:{col};">{dev}°C outside limit</td></tr>
    </table>
    <div style="margin-top:14px;padding:12px;background:{bg};border:1px solid {bdr};border-radius:6px;color:{col};font-size:13px;">
      ⚠ Check your cold chain immediately. Product may be at risk.
    </div>
  </div>
  <div style="background:#0d1117;padding:10px 22px;border-top:1px solid #30363d;">
    <p style="color:#8b949e;font-size:11px;margin:0;">© Polarix — polarix.es · Automated alert · Do not reply</p>
  </div>
</div></body></html>"""


def send_alert_all(contacts, sensor_id, temperature, min_temp, max_temp):
    subject = f"🚨 Polarix Alert: {sensor_id} at {temperature}°C"
    _dispatch(contacts, _temp_text(sensor_id, temperature, min_temp, max_temp),
              subject, _temp_html, sensor_id, temperature, min_temp, max_temp)


def send_alert(contact, sensor_id, temperature, min_temp, max_temp):
    """Backward-compat: single WhatsApp contact."""
    send_alert_all([{"type": "whatsapp", "value": contact}], sensor_id, temperature, min_temp, max_temp)


# ── Sensor offline ─────────────────────────────────────────────────────────

def _offline_text(sensor_id, vehicle_name, elapsed_mins):
    v = f" ({vehicle_name})" if vehicle_name else ""
    return (f"📡 Polarix — SENSOR OFFLINE\n"
            f"Sensor  : {sensor_id}{v}\n"
            f"Last seen : {elapsed_mins} minutes ago\n"
            f"Possible causes: power loss, WiFi drop, dead battery.\n"
            f"Check the sensor immediately.")


def _offline_html(sensor_id, vehicle_name, elapsed_mins):
    v = f" · {vehicle_name}" if vehicle_name else ""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1117;margin:0;padding:28px;font-family:-apple-system,sans-serif;">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;">
  <div style="background:#1f2937;padding:16px 22px;border-bottom:1px solid #30363d;">
    <span style="color:#58a6ff;font-size:15px;font-weight:700;">🌡️ Polarix</span>
    <span style="float:right;background:#d2992222;color:#d29922;border:1px solid #d2992266;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">SENSOR OFFLINE</span>
  </div>
  <div style="text-align:center;padding:26px 22px 18px;">
    <div style="font-size:48px;">📡</div>
    <div style="color:#d29922;font-size:20px;font-weight:800;margin-top:8px;">No Signal</div>
    <div style="color:#8b949e;font-size:13px;margin-top:4px;">Last seen {elapsed_mins} minutes ago</div>
  </div>
  <div style="padding:0 22px 22px;">
    <table style="width:100%;border-collapse:collapse;color:#e6edf3;font-size:13px;">
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;width:130px;">Sensor</td><td style="padding:9px 0;font-weight:600;">{sensor_id}{v}</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Silent for</td><td style="padding:9px 0;font-weight:600;color:#d29922;">{elapsed_mins} minutes</td></tr>
    </table>
    <div style="margin-top:14px;padding:12px;background:#d2992222;border:1px solid #d2992266;border-radius:6px;color:#d29922;font-size:13px;">
      Check power, WiFi connection, and battery level on site.
    </div>
  </div>
  <div style="background:#0d1117;padding:10px 22px;border-top:1px solid #30363d;">
    <p style="color:#8b949e;font-size:11px;margin:0;">© Polarix — polarix.es · Automated alert · Do not reply</p>
  </div>
</div></body></html>"""


def send_alert_offline(contacts, sensor_id, vehicle_name, elapsed_mins):
    subject = f"📡 Polarix Alert: {sensor_id} offline ({elapsed_mins} min)"
    _dispatch(contacts, _offline_text(sensor_id, vehicle_name, elapsed_mins),
              subject, _offline_html, sensor_id, vehicle_name, elapsed_mins)


# ── Battery low ────────────────────────────────────────────────────────────

def _battery_text(sensor_id, vehicle_name, battery_pct):
    v = f" ({vehicle_name})" if vehicle_name else ""
    return (f"🔋 Polarix — LOW BATTERY\n"
            f"Sensor  : {sensor_id}{v}\n"
            f"Battery : {battery_pct}%\n"
            f"Replace the battery soon to avoid monitoring gaps.")


def _battery_html(sensor_id, vehicle_name, battery_pct):
    v    = f" · {vehicle_name}" if vehicle_name else ""
    col  = "#f85149" if battery_pct <= 10 else "#d29922"
    bg   = "#da363322" if battery_pct <= 10 else "#d2992222"
    bdr  = "#da363366" if battery_pct <= 10 else "#d2992266"
    bars = max(1, round(battery_pct / 10))
    bar_html = "".join([f'<span style="display:inline-block;width:14px;height:20px;background:{col};border-radius:2px;margin-right:3px;opacity:{1 if i<bars else 0.2};"></span>' for i in range(10)])
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1117;margin:0;padding:28px;font-family:-apple-system,sans-serif;">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;">
  <div style="background:#1f2937;padding:16px 22px;border-bottom:1px solid #30363d;">
    <span style="color:#58a6ff;font-size:15px;font-weight:700;">🌡️ Polarix</span>
    <span style="float:right;background:{bg};color:{col};border:1px solid {bdr};padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">LOW BATTERY</span>
  </div>
  <div style="text-align:center;padding:26px 22px 18px;">
    <div style="font-size:48px;">🔋</div>
    <div style="color:{col};font-size:20px;font-weight:800;margin-top:8px;">{battery_pct}% Remaining</div>
    <div style="margin-top:12px;">{bar_html}</div>
  </div>
  <div style="padding:0 22px 22px;">
    <table style="width:100%;border-collapse:collapse;color:#e6edf3;font-size:13px;">
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;width:130px;">Sensor</td><td style="padding:9px 0;font-weight:600;">{sensor_id}{v}</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Battery</td><td style="padding:9px 0;font-weight:600;color:{col};">{battery_pct}%</td></tr>
    </table>
    <div style="margin-top:14px;padding:12px;background:{bg};border:1px solid {bdr};border-radius:6px;color:{col};font-size:13px;">
      Replace the battery soon. Sensor will go offline when battery is depleted.
    </div>
  </div>
  <div style="background:#0d1117;padding:10px 22px;border-top:1px solid #30363d;">
    <p style="color:#8b949e;font-size:11px;margin:0;">© Polarix — polarix.es · Automated alert · Do not reply</p>
  </div>
</div></body></html>"""


def send_alert_battery(contacts, sensor_id, vehicle_name, battery_pct):
    subject = f"🔋 Polarix Alert: {sensor_id} battery low ({battery_pct}%)"
    _dispatch(contacts, _battery_text(sensor_id, vehicle_name, battery_pct),
              subject, _battery_html, sensor_id, vehicle_name, battery_pct)


# ── Speed exceeded ─────────────────────────────────────────────────────────────

def _speed_text(sensor_id, speed_kmh, limit_kmh):
    return (f"🚨 Polarix — SPEED ALERT\n"
            f"Vehicle : {sensor_id}\n"
            f"Speed   : {speed_kmh} km/h\n"
            f"Limit   : {limit_kmh} km/h\n"
            f"Reduce speed immediately.")


def _speed_html(sensor_id, speed_kmh, limit_kmh):
    over = round(speed_kmh - limit_kmh, 1)
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head>
<body style="background:#0d1117;margin:0;padding:28px;font-family:-apple-system,sans-serif;">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;">
  <div style="background:#1f2937;padding:16px 22px;border-bottom:1px solid #30363d;">
    <span style="color:#58a6ff;font-size:15px;font-weight:700;">🌡️ Polarix</span>
    <span style="float:right;background:#da363322;color:#f85149;border:1px solid #da363366;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">SPEED ALERT</span>
  </div>
  <div style="text-align:center;padding:26px 22px 18px;">
    <div style="font-size:62px;font-weight:800;color:#f85149;line-height:1;">{speed_kmh} <span style="font-size:24px;">km/h</span></div>
    <div style="color:#f85149;font-size:17px;font-weight:700;margin-top:7px;">↑ SPEED EXCEEDED</div>
  </div>
  <div style="padding:0 22px 22px;">
    <table style="width:100%;border-collapse:collapse;color:#e6edf3;font-size:13px;">
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;width:130px;">Vehicle</td><td style="padding:9px 0;font-weight:600;">{sensor_id}</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Speed limit</td><td style="padding:9px 0;font-weight:600;">{limit_kmh} km/h</td></tr>
      <tr style="border-top:1px solid #30363d;"><td style="padding:9px 0;color:#8b949e;">Over limit</td><td style="padding:9px 0;font-weight:600;color:#f85149;">+{over} km/h</td></tr>
    </table>
    <div style="margin-top:14px;padding:12px;background:#da363322;border:1px solid #da363366;border-radius:6px;color:#f85149;font-size:13px;">
      ⚠ Reduce speed immediately.
    </div>
  </div>
  <div style="background:#0d1117;padding:10px 22px;border-top:1px solid #30363d;">
    <p style="color:#8b949e;font-size:11px;margin:0;">© Polarix — polarix.es · Automated alert · Do not reply</p>
  </div>
</div></body></html>"""


def send_alert_speed(contacts, sensor_id, speed_kmh, limit_kmh):
    subject = f"🚨 Polarix Alert: {sensor_id} — {speed_kmh} km/h (limit {limit_kmh} km/h)"
    _dispatch(contacts, _speed_text(sensor_id, speed_kmh, limit_kmh),
              subject, _speed_html, sensor_id, speed_kmh, limit_kmh)
