<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Sentinel Zero Trust Vault

This repository is split into separate applications:

- `frontend/` — Vite + React app
- `backend/` — Flask API

## Run locally

### Frontend

**Prerequisites:** Node.js

```bash
cd frontend
npm install
npm run dev
```

### Backend

```bash
cd backend
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```
