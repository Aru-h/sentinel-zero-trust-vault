# Fix frontend ↔ backend integration (Vercel + Render)

## Your live URLs
- Frontend: `https://sentinel-zero-trust-vault.vercel.app`
- Backend: `https://sentinel-zero-trust-vault.onrender.com`

## 1) Vercel rewrite config (`frontend/vercel.json`)
Use this exact file so frontend API/auth requests route to backend:

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
