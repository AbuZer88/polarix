# Polarix — Deploy Checklist (Staging + Production)

This is the step-by-step you follow once to put the backend on Railway with HTTPS, Postgres, and Sentry. Allow ~30 minutes if you've never used Railway before.

---

## Staging Setup (do this BEFORE production — test here first)

### A. Create the Railway staging service

1. Railway dashboard → your project → **+ New Service** → **Deploy from GitHub** → same repo
2. Name it `polarix-staging`
3. In **Variables** tab, add all values from `.env.staging` (replace `REPLACE_WITH_*` with real values):
   - Generate secrets: `python -c "import secrets; print(secrets.token_hex(32))"`
   - `ADMIN_KEY`, `JWT_SECRET`, `DATABASE_URL=sqlite:///canary_staging.db`
   - `ENVIRONMENT=staging` ← this activates the orange banner in both dashboards
   - `SMTP_*`, `TWILIO_*`, `TELTONIKA_HTTP_TOKEN` (use a different token than prod)
4. Railway auto-deploys. Visit `https://polarix-staging.up.railway.app/health`
   - Should return: `{"environment": "staging", "status": "ok"}`
   - Open dashboard → orange "⚠ STAGING ENVIRONMENT" banner should appear at top

### B. Test with the simulator

```powershell
# Register a test device in admin panel first, then:
python tests/simulate_fmm920.py --imei YOUR_TEST_IMEI --host https://polarix-staging.up.railway.app
```

### C. Fix deploy workflow

```
1. Bug found on production
2. Fix locally → make dev → test on http://localhost:8080
3. make staging → test on http://localhost:8001 (local staging sim)
4. make deploy-staging → verify on Railway staging URL
5. Confirmed good → make deploy-prod (prints warning, requires manual command)
```

---

## 1. One-time accounts (free tiers — no credit card needed to start)

- [ ] **Railway** — https://railway.app — sign in with GitHub
- [ ] **Sentry** — https://sentry.io — create a "FastAPI" project, copy the DSN
- [ ] **GitHub** — push this repo (Railway deploys from GitHub)

## 2. Push to GitHub

```powershell
cd "C:\Users\ahmad\Downloads\coldchainProject\coldchain-canary"
git init                    # only if no .git yet
git add .
git status                  # verify canary.db and .env are NOT staged
git commit -m "Polarix v2.0 — initial production-ready commit"
git branch -M main
gh repo create polarix --private --source . --remote origin --push
# OR manually create the repo on github.com and push:
#   git remote add origin git@github.com:<you>/polarix.git
#   git push -u origin main
```

## 3. Create the Railway project

1. On https://railway.app/new click **Deploy from GitHub repo** → pick `polarix`
2. Railway detects Python via `requirements.txt` + `Procfile`
3. Wait for the first build (~3 min). It will fail on first boot because env vars aren't set yet — that's expected.

## 4. Add Postgres (Railway managed)

1. In the project canvas click **+ New → Database → PostgreSQL**
2. It auto-provisions and gives you a `DATABASE_URL` env var on the Postgres service
3. In your **backend service** → **Variables** tab, add a **reference** to that variable:
   - Click **Add Variable Reference** → pick Postgres → `DATABASE_URL`

## 5. Set all required env vars (in the backend service Variables tab)

Generate `JWT_SECRET`:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

| Variable | Value | Notes |
|---|---|---|
| `JWT_SECRET` | (output from command above) | **REQUIRED**. App refuses to start without it |
| `ADMIN_KEY` | Pick a long random string | **REQUIRED**. Login to admin panel uses this |
| `DATABASE_URL` | (auto from Postgres ref) | Set in step 4 |
| `ENVIRONMENT` | `production` | Shown in `/health` |
| `CORS_ORIGINS` | `https://your-railway-domain.up.railway.app` | Comma-sep list. **Required for browser access** |
| `SENTRY_DSN` | From your Sentry FastAPI project | Optional but strongly recommended |
| `SENTRY_TRACES_RATE` | `0.1` | 10% of requests traced. Bigger = more cost |
| `APP_VERSION` | `polarix@2.0.0` | Tagged on Sentry events |
| `TWILIO_SID` | From Twilio console | Optional — only if you want WhatsApp / SMS alerts |
| `TWILIO_TOKEN` | From Twilio console | Optional |
| `TWILIO_FROM` | `whatsapp:+14155238886` (sandbox) | Optional |
| `SMTP_HOST` | `smtp.gmail.com` | Optional — only if you want email alerts |
| `SMTP_PORT` | `587` | Optional |
| `SMTP_USER` | Your Gmail address | Optional |
| `SMTP_PASS` | Gmail **App Password** (NOT your account password) | Optional |
| `SMTP_FROM` | `Polarix Alerts <user@gmail.com>` | Optional |
| `TELTONIKA_HTTP_TOKEN` | Pick a random string | Required if you use GPS hardware. Configure in FMB920 too |

After saving, Railway will redeploy automatically.

## 6. Verify the deployment

Replace `<RAILWAY_URL>` with your `*.up.railway.app` URL:

```powershell
curl https://<RAILWAY_URL>/health
# Expect: {"app":"Polarix","status":"ok","version":"2.0.0","environment":"production"}

curl -H "X-Admin-Key: <YOUR_ADMIN_KEY>" https://<RAILWAY_URL>/admin/status
# Expect: jwt_set: true, admin_key_set: true, database_url: "postgresql"
```

Open `https://<RAILWAY_URL>/dashboard/admin.html` in your browser → log in with `ADMIN_KEY`.

## 7. Update CORS once Railway URL is known

If you set `CORS_ORIGINS` to a placeholder in step 5, update it now to the actual Railway URL.

If you later add a custom domain (e.g. `app.polarix.es`), append it:
```
CORS_ORIGINS=https://polarix-prod.up.railway.app,https://app.polarix.es
```

## 8. Configure Teltonika devices (FMB920) for HTTP mode

Railway only exposes HTTP/HTTPS — **TCP port 8005 will not be reachable**. So configure each FMB920 to push via HTTP instead:

In Teltonika Configurator → **GPRS settings**:
- Data Protocol: **HTTP / HTTPS**
- Server URL: `https://<RAILWAY_URL>/teltonika/http`
- HTTP Header: `X-Teltonika-Token: <TELTONIKA_HTTP_TOKEN value>`

See `hardware/HARDWARE.md` for full configurator screens.

## 9. Test the full pipeline

From your laptop:
```powershell
python tests/simulate_fmm920.py --host https://<RAILWAY_URL> --imei 352656100001234
```

The dashboard should show readings appearing live. The alarm engine should fire on the breach reading.

## 10. Set up monitoring

- [ ] Add an **uptime check** (free at https://uptimerobot.com or https://betterstack.com) pointing at `https://<RAILWAY_URL>/health` every 5 min
- [ ] Verify Sentry receives a test error: `curl https://<RAILWAY_URL>/sentry-debug` (only if you add this route; or trigger any backend error)
- [ ] Bookmark the Railway logs page

## 11. Backup the SQLite snapshot before switching to Postgres (already done locally)

Since Railway will use Postgres, your existing `canary.db` data won't migrate automatically. If you have customer data in SQLite:
- Run `POST /admin/backup` once locally to snapshot
- Use a Postgres migration script (manual `pg_dump`/`psql` or `sqlite3 -> postgres` ETL)

For a fresh launch this is fine; new data writes straight to Postgres on Railway.

---

## Quick Smoke Test After Deploy

| Check | Command / URL | Expect |
|---|---|---|
| Health | `GET /health` | `status: ok` |
| HTTPS | URL starts `https://` | Browser shows lock icon |
| CORS blocks evil.com | Browser console fetch from `evil.com` | Blocked by CORS |
| Login | `POST /auth/login` | 200 + JWT |
| Admin panel | `/dashboard/admin.html` | Log in with `ADMIN_KEY` |
| Client dashboard | `/dashboard/?client=<id>` | Loads |
| Sentry test | Trigger a 500 error | Appears in Sentry within 30s |
| Backup endpoint | `POST /admin/backup` | Returns `{status:"skipped", reason:"not sqlite"}` on Postgres — this is correct |

---

## How to Pause Railway (Save Costs During Pre-Launch)

Suspending a service preserves all data, environment variables, and config. No charges while suspended. Takes ~30 seconds to resume.

**To pause:**
1. Go to https://railway.com → your project
2. Click the service (`polarix` or `polarix-staging`)
3. **Settings** tab → scroll to **Danger Zone** → click **Suspend Service**
4. Confirm — service stops immediately, billing stops, data is preserved

**To resume:**
1. Same location → **Resume Service**
2. Railway rebuilds and redeploys automatically (~2–3 minutes)
3. Verify with: `curl https://polarix-production.up.railway.app/health`

**When to use this:**
- Pre-launch: no paying clients yet → pause production when not testing
- Weekend / holiday: pause if no devices are sending data
- Both prod + staging can be paused independently

**Important:** SQLite DB is stored on a Railway volume. It persists across suspensions. If you switch to PostgreSQL later, the managed DB is always-on regardless of service state.

---

## What you CANNOT do via me (the assistant)

1. Push the repo to GitHub on your behalf (needs your GitHub credentials)
2. Click "Deploy" on Railway (needs your Railway login)
3. Create the Sentry project (needs your Sentry login)
4. Add a custom DNS record (needs your domain registrar)

But everything in the code is ready. Run the steps above one at a time — when something fails, check Railway logs first, then come back and ask me.
