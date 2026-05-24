# Polarix — Pending Builds

Items tracked here were scoped but not yet implemented. Each entry includes a complexity estimate and implementation notes so a future session can pick up immediately.

---

## Item 4 — PDF Report with Embedded Map (Route + Movement Summary)

**Complexity:** Large (2–4 days)

**Description:**  
The current PDF (jsPDF) embeds a server-side matplotlib temperature chart. This item adds a visual route map and a movement/stop duration summary table to the same PDF.

**Implementation options:**
- **Option A (client-side, easiest):** Use Leaflet's `leaflet-image` plugin to render the current map canvas to a PNG blob, then embed with `doc.addImage()`. Works offline. Requires the map to already be rendered at print time.
- **Option B (server-side):** Add a `GET /map_image/{client_id}` endpoint using `staticmap` or `folium` Python libraries to generate a route PNG server-side. Slower but works without a visible browser map.

**Movement summary table fields:** Sensor, Date, Total Moving Time, Total Stopped Time, Distance (km), Max Speed, Avg Temp.

**Data already available:** `gps_history` endpoint returns lat/lng/speed/timestamp per point. Calculate segments client-side: contiguous speed > 2 km/h = moving, else stopped.

---

## Item 9 — Reconsider "Recent Readings" Section

**Complexity:** Small (design decision + 1–2h implementation)

**Description:**  
"Recent Readings" shows the last 20 readings in the Overview tab. Consider whether this adds value alongside the Fleet Table and Sensor Tiles.

**Options:**
- Keep as-is (some users want to see raw numbers quickly)
- Move to History tab (less clutter on Overview)
- Replace with a mini sparkline per sensor on the sensor tiles
- Remove entirely

**Recommendation:** Move to History tab or hide behind a collapsible toggle on Overview. The Fleet Table already shows current temperature; raw readings feel redundant there.

---

## Item 10 — Smarter PDF/CSV Export

**Complexity:** Medium (1–2 days)

**Description:**  
Currently export is scoped to sensor + date range. Users want more control:

- **CSV:** Choose columns (temp-only, GPS+temp, all fields)
- **PDF:** Choose date range independent of the map chip selector; optionally include route map (see Item 4); multi-sensor export (one section per sensor)
- **EN 12830 compliance header** on PDF should be more prominent with client name, sensor ID, calibration notes field

**Implementation notes:**
- Export modal (small dialog) with checkboxes instead of separate buttons
- Backend `GET /export/{client_id}` already supports `sensor_id`, `from_dt`, `to_dt` — just need better UI wiring
- PDF generation is fully client-side (jsPDF) — multi-sensor means looping and calling `doc.addPage()`

---

## Item 11 — Historical Chart Tooltip with City Name

**Complexity:** Medium (3–6 hours)

**Description:**  
When hovering over a data point on the 7-day temperature Chart.js chart, the tooltip currently shows date + temp. This item adds the city/location name resolved from the GPS coordinates of that reading.

**Implementation notes:**
- The `weekly_history` endpoint returns readings with `lat`/`lng` per point
- Chart.js custom tooltip callback (`plugins.tooltip.callbacks.label`) can call `reverseGeocode()` — but it's async, so the tooltip needs to show "Loading…" then update
- Use the existing `geocodeCache` + `_geoQ` Nominatim queue — do NOT make direct fetch calls in the tooltip callback
- Alternative: pre-geocode all visible points when chart data loads, store in a `pointLocations` map keyed by index, reference synchronously in the tooltip

**Recommended approach:** Pre-geocode on data load, store results, render synchronously in tooltip.

---

## Item 14 — Vehicle Icons, Telematics Look, Client-Customizable Colors

**Complexity:** Large (3–5 days)

**Description:**  
Current dashboard uses generic colored dots on the map and simple sensor tiles. This item brings a more professional telematics feel:

- **Map markers:** SVG truck/van icons instead of circles; icon color matches sensor color; icon rotates to match heading (angle from GPS)
- **Sensor tiles:** Larger, card-style with vehicle silhouette icon; client can pick vehicle type (truck, van, refrigerated trailer, motorcycle)
- **Color theming:** Per-client accent color stored in `thresholds` table or a new `client_config` table; applied to sensor tiles and map markers
- **Fleet status icons:** Moving truck icon vs parked icon in fleet table Movement column

**Implementation notes:**
- SVG icons can be embedded as data URIs in Leaflet `L.divIcon`
- Vehicle type preference: add `vehicle_type` column to `sensor_assignments` or new `client_config` table
- CSS custom properties already support theming via `--acc`; extend to `--sensor-color-N`

---

## Item 15 — Admin Panel CRM Redesign

**Complexity:** Large (3–5 days)

**Description:**  
Current admin panel (`admin.html`) is a functional list. Upgrade to a CRM-style interface:

- **Client profile page:** Click a client row → dedicated page showing all sensors, recent readings, alert history, contacts, active assignments, subscription plan
- **Sensor assignment UI:** Drag-and-drop or dropdown to assign sensors to clients directly from admin
- **Usage metrics:** Readings count last 30 days, last seen, alert count, active/inactive status badge
- **Bulk operations:** Select multiple clients → bulk delete, export, or re-assign sensors
- **Search/filter:** Client name search, filter by active/inactive, filter by sensor count

**Implementation notes:**
- Admin panel is currently a separate `admin.html` with `X-Admin-Key` header auth — keep the same auth pattern
- New page: `admin_client.html?client_id=xxx` — or implement as a slide-in panel within `admin.html`
- Backend already has all needed endpoints; may need `GET /admin/clients/{client_id}` for full profile

---

## Item 16 — Vehicle/Sensor Assignment Panel Redesign

**Complexity:** Medium (1–2 days)

**Description:**  
The current Settings → Vehicle Assignments section shows a list of active assignments and a form to add new ones. Improvements:

- **Visual assignment map:** Show which sensors are currently assigned vs unassigned at a glance
- **Assignment timeline view:** Gantt-style bar chart showing which sensor was in which vehicle over time (data is already in `assignment_history`)
- **Quick swap:** Button to quickly move a sensor from one vehicle plate to another without delete + re-add
- **Plate autocomplete:** As user types a plate, suggest previously used plates from assignment history
- **Bulk unassign:** Unassign all sensors at once (end of day / route complete)

**Implementation notes:**
- `GET /assignment_history/{client_id}` returns full history — enough for a timeline
- Gantt chart: could use a simple HTML/CSS grid (no extra library needed for basic version)
- Plate autocomplete: collect unique plates from history and use a `<datalist>` element

---

---

## Item 17 — SMTP Email Configuration (Required for Email Alerts)

**Complexity:** Trivial (5 minutes — env vars only, no code needed)

**Description:**
Email alert delivery is fully implemented in `alerts/notifier.py` and the client UI already has an "Email" option in the Alert Contacts dropdown. The only blocker is missing SMTP credentials in `.env`.

**What to add to `.env`:**
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx   ← Gmail App Password (not your login password)
SMTP_FROM=Polarix Alerts <your@gmail.com>
```

**How to get Gmail App Password:**
1. Enable 2-Step Verification on the Gmail account
2. Go to myaccount.google.com/apppasswords
3. Create an App Password named "Polarix"
4. Paste the 16-character code as SMTP_PASS

**Alternative providers (better deliverability than Gmail for transactional email):**
- Brevo: free 300 emails/day — `smtp-relay.brevo.com` port 587
- Resend: free 3,000/month — `smtp.resend.com` port 587
- Both require a verified sender domain eventually

**In production (.env.production):** Set all 5 SMTP vars via Railway's environment variable UI — never commit real credentials.

---

*Last updated: 2026-05-24*
