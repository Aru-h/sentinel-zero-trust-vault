# Deploying Sentinel Zero Trust to Render

## What you get
- **sentinel-backend** — Flask API on `https://sentinel-zero-trust-vault.onrender.com`
- **sentinel-frontend** — React static site on `https://sentinel-zero-trust-vault.vercel.app`

---

## Step 1 — Prepare your repo

Make sure your repository has this structure:

```
your-repo/
├── render.yaml              ← Render Blueprint config
├── frontend/
│   ├── vite.config.ts
│   ├── package.json
│   └── constants.ts         ← uses built-in zero-config API routing
└── backend/
    ├── app.py
    ├── requirements.txt
    └── templates/
```

Push everything to GitHub (or GitLab/Bitbucket).

If this is your first push, run:

```bash
git init
git add .
git commit -m "Prepare frontend/backend layout for deployment"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If the repo already exists and you just changed files:

```bash
git add .
git commit -m "Update deployment-ready repo structure"
git push
```

---

## Step 2 — Deploy via Blueprint

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. Click **New → Blueprint**
3. Connect your GitHub account and select your repo
4. Render will detect `render.yaml` and show both services
5. Click **Apply** — Render deploys both simultaneously

---

## Step 3 — Set passwords (Secret environment variables)

The `render.yaml` marks passwords as `sync: false`, meaning Render will
ask you to fill them in before deploying. Set strong passwords for:

| Variable | Example |
|----------|---------|
| `ADMIN_PASSWORD` | `Adm!n_S3nt1n3l#2025` |
| `HR_PASSWORD` | `HR_S3cur3!Pass` |
| `DEV_PASSWORD` | `D3v_Z3r0Tru5t!` |
| `FIN_PASSWORD` | `F1n4nc3_V@ult!` |

> These are the passwords users log in with. Do NOT use the old defaults.

---

## Step 4 — Wire up the URLs (the key step)

After both services finish deploying:

### 4a — Update the backend's allowed origins
1. Go to your **sentinel-backend** service → **Environment**
2. Update `CORS_ORIGINS` to your actual frontend URL:
   ```
   https://sentinel-zero-trust-vault.vercel.app
   ```
3. Click **Save Changes** — backend redeploys automatically

> Frontend-to-backend routing is zero-config now: client requests use relative paths and deployment rewrites/proxies route them to backend.

---

## Step 5 — Test it

Open `https://sentinel-zero-trust-vault.vercel.app` and log in with:

| Username | Password (whatever you set) |
|----------|-----------------------------|
| `admin1` | `ADMIN_PASSWORD` value |
| `dev1`   | `DEV_PASSWORD` value |
| `hr1`    | `HR_PASSWORD` value |
| `fin1`   | `FIN_PASSWORD` value |

---

## Render Free Tier — What to know

| Thing | Free tier behaviour |
|-------|---------------------|
| **Backend spin-up** | Sleeps after 15 min of inactivity; first request takes ~30s |
| **SQLite disk** | Persistent (survives redeploys), 1GB allocated |
| **Frontend** | Always-on static CDN, no sleep |
| **Custom domains** | Supported on free tier |

---

## Local development (still works)

```bash
# Backend
cd backend
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py

# Frontend (separate terminal)
cd frontend
npm install && npm run dev
```

---

## Troubleshooting

**Login works but requests fail with 401 / cookies not sent**
→ Backend `SESSION_COOKIE_SAMESITE` must be `None` and `SECURE` must be `True`.
  The provided `app.py` sets this automatically when `FLASK_ENV=production`.
  Check that env var is set correctly on the backend service.

**Frontend shows "Connection error"**
→ Backend may be down/asleep or unreachable. Try opening the backend URL directly in a browser first.

**"Too many login attempts" immediately**
→ The rate limiter is per-worker and in-memory. On Render free tier with 2
  Gunicorn workers, each worker tracks attempts independently. This is fine
  for a demo — if you need stricter limits add Redis.

**Backend crashes on startup**
→ Check Render logs. Most likely a missing env var (`SECRET_KEY` or a password).
