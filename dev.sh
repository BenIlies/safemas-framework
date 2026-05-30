#!/usr/bin/env bash
# Start backend (FastAPI :8000) and frontend (Vite :5173) for local development.
set -e
cd "$(dirname "$0")"

# backend
if [ ! -d backend/.venv ]; then
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install -q -r backend/requirements.txt
fi
backend/.venv/bin/uvicorn main:app --app-dir backend --reload --port 8000 &
BACK=$!

# frontend
if [ ! -d frontend/node_modules ]; then
  (cd frontend && npm install)
fi
(cd frontend && npm run dev) &
FRONT=$!

trap "kill $BACK $FRONT 2>/dev/null" EXIT
echo "SafeMAS running -> http://localhost:5173  (API :8000)"
wait
