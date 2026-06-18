# Execution Playbook

Use PowerShell on Windows. Copy-paste each command block.

## Prerequisites
- Python 3.11+ installed and on PATH
- Node.js 18+ and npm installed
- Git (optional)
- (Optional) PostgreSQL if you want real DB; otherwise the app may fallback to SQLite

## 1) Prepare repository (one-time)
```powershell
cd "H:\Live_Projects\Hacking_projects\Packet-Intel"
# optional: create project venv (recreate if you need clean state)
python -m venv .venv
. .venv\Scripts\Activate.ps1

# upgrade packaging tools
pip install --upgrade pip setuptools wheel
```

## 2) Install backend Python dependencies
```powershell
# ensure you're in venv and project root
. .venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
# If you hit pyyaml build errors, install binary wheel first
pip install pyyaml==6.0.3 --only-binary=:all:
```

## 3) Run backend
Preferred (from project root, using package import path):
```powershell
. .venv\Scripts\Activate.ps1
# run with module style so imports resolve correctly
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
If you run from inside `backend/` directory instead, use:
```powershell
cd backend
. ..\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

## 4) Install frontend deps and run dev server
Open a new PowerShell (or use the same) and run:
```powershell
cd "H:\Live_Projects\Hacking_projects\Packet-Intel\frontend"
# remove old node modules & lockfile if you're in a broken state
Remove-Item -Recurse -Force node_modules,package-lock.json -ErrorAction SilentlyContinue

npm install
# run Vite dev server
npm run dev
# or run Vite directly if PATH issues:
npx vite
```
Note: If your Windows path contains an ampersand `&` in a parent folder name, use quoted paths as shown above or use PowerShell (it handles `&` inside quoted paths). Avoid running from cmd.exe where `&` is treated specially.

## 5) Common troubleshooting
- "No module named 'app'": ensure you're running `python -m uvicorn backend.app.main:app` from project root, or run `python -m uvicorn app.main:app` from inside `backend/`.
- Pydantic/typing TypeError (Subscripted generics): recreate and activate a clean `.venv`, then reinstall pinned `pydantic` and `fastapi`:
```powershell
Remove-Item -Recurse -Force .venv
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install "pydantic==1.10.26" "fastapi==0.95.2" "uvicorn[standard]==0.22.0"
pip install -r backend/requirements.txt
```
- Vite not found / path issues: use `npx vite` or run from the `frontend` folder with `npm run dev` in PowerShell and ensure `node` and `npm` are on PATH.
- If Wireshark/manuf warning appears from scapy, it's informational only; install `manuf` file or ignore.

## 6) Useful commands
```powershell
# list installed Python packages (inside venv)
pip freeze

# show node / npm versions
node -v
npm -v
```

---
If you want, I can: (A) add these commands into a runnable `setup.ps1` and `start.ps1`, or (B) commit this `execute.md` into the repo. Tell me which to do next.A 