# Sentinel Zero Trust — Environment Setup

## Backend (.env or shell exports)

```bash
# Required — server refuses to start without this
SECRET_KEY=<run: python -c "import secrets; print(secrets.token_hex(32))">

# Set to 'production' to enforce HTTPS cookies and disable dev defaults
FLASK_ENV=development

# Allowed frontend origins (comma-separated)
CORS_ORIGINS=http://localhost:5173

# Never enable debug in production
FLASK_DEBUG=false
```

## Frontend

No frontend environment variables are required. API/auth routes are proxied automatically in development and rewritten automatically on Vercel.

## Quick start (development)

```bash
# Terminal 1 — backend
cd backend
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py

# Terminal 2 — frontend
cd frontend
npm install
npm run dev
```
