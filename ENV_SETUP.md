# Sentinel Zero Trust — Environment Setup

## Backend (.env or shell exports)

```bash
# Required — server refuses to start without this
SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">

# Set to 'production' to enforce HTTPS cookies and disable dev defaults
FLASK_ENV=development

# User passwords — required in production, defaults used in dev if absent
ADMIN_PASSWORD=<strong-password>
HR_PASSWORD=<strong-password>
DEV_PASSWORD=<strong-password>
FIN_PASSWORD=<strong-password>

# Allowed frontend origins (comma-separated)
CORS_ORIGINS=http://localhost:5173

# Never enable debug in production
FLASK_DEBUG=false
```

## Frontend (.env.local)

```bash
# Backend API URL — no trailing slash
VITE_API_URL=http://localhost:5001
```

> **Do not commit `.env` or `.env.local` to version control.**
> Add both to `.gitignore`.

## Quick start (development)

```bash
# Terminal 1 — backend
cd backend
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py

# Terminal 2 — frontend
echo "VITE_API_URL=http://localhost:5001" > .env.local
npm install
npm run dev
```
