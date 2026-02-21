# Fix frontend ↔ backend integration (Vercel + Render)

## Your live URLs
- Frontend: `https://sentinel-zero-trust-vault.vercel.app`
- Backend: `https://sentinel-zero-trust-vault.onrender.com`

## 1) Vercel project config (`vercel.json` at repo root)
Use this exact root file so Vercel builds from `frontend/`, serves `frontend/dist`, and routes API/auth requests to backend:

```json
{
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://sentinel-zero-trust-vault.onrender.com/api/:path*"
    },
    {
      "source": "/login",
      "destination": "https://sentinel-zero-trust-vault.onrender.com/login"
    },
    {
      "source": "/logout",
      "destination": "https://sentinel-zero-trust-vault.onrender.com/logout"
    }
  ]
}
```

## 2) Backend CORS allowlist
Set backend `CORS_ORIGINS` to:

```bash
https://sentinel-zero-trust-vault.vercel.app
```

## 3) Backend production cookie settings
Ensure backend runs with:

```bash
FLASK_ENV=production
```

This enables secure cross-site session cookies (`SameSite=None`, `Secure=True`).

## 4) Deploy/redeploy
- Redeploy backend (Render)
- Redeploy frontend (Vercel)

## 5) Quick verification
Open the frontend and confirm:
- Login request goes to `/login` (rewritten to Render backend)
- API calls go to `/api/*`
- Session persists after login

## If Render shows `Could not open requirements.txt`
Your backend service is running from repo root instead of `backend/`.

Fix either way:
- Set **Root Directory** to `backend` in Render service settings, then redeploy.
- Or keep root at repo root; this repo now has a fallback build/start command in `render.yaml` that handles both paths.

## If Render shows `No module named 'your_application'`
Render is using its default start command (`gunicorn your_application.wsgi`).
This repo now includes a compatible module at `your_application/wsgi.py` that maps to `backend.app`.
If you still see the error, clear the service cache and redeploy the latest commit.
