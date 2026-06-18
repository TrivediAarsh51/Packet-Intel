# =============================================================================
# Start script for Packet-Intel
# Run this from PowerShell in the repo root:
#     .\start.ps1
#
# What it does (per execute.md):
#   1. Creates/activates a Python venv
#   2. Installs backend deps (with pyyaml binary-wheel fallback)
#   3. Installs frontend deps (npm)
#   4. Starts backend (uvicorn) in its own window, with fallback import path
#   5. Starts frontend (vite dev server) in its own window
# =============================================================================

param(
    [switch]$CleanVenv,      # pass -CleanVenv to delete and recreate .venv
    [switch]$CleanFrontend   # pass -CleanFrontend to wipe node_modules/lockfile
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }

# -----------------------------------------------------------------------
# 0) Resolve paths & sanity checks
# -----------------------------------------------------------------------
$projRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projRoot
Write-Host "Project root: $projRoot" -ForegroundColor Green

if ($projRoot -match '&') {
    Write-Host "[WARN] Project path contains '&' - some npm-generated .cmd shims (e.g. 'vite') do not quote paths correctly on Windows and may fail with errors like 'Packet is not recognized' or 'Cannot find module ...vite.js'." -ForegroundColor Yellow
    Write-Host "[WARN] This script includes a direct-node fallback for vite, but renaming the project folder to remove '&' is the more robust long-term fix." -ForegroundColor Yellow
}

$backendReq   = Join-Path $projRoot 'backend\requirements.txt'
$frontendPath = Join-Path $projRoot 'frontend'
$venvPath     = Join-Path $projRoot '.venv'
$activate     = Join-Path $venvPath 'Scripts\Activate.ps1'

if (-Not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Err "Python not found on PATH. Install Python 3.11+ and re-run."
    exit 1
}
if (-Not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Err "npm not found on PATH. Install Node.js 18+ and re-run."
    exit 1
}
if (-Not (Test-Path $backendReq)) {
    Write-Err "Could not find backend/requirements.txt under $projRoot"
    exit 1
}
if (-Not (Test-Path $frontendPath)) {
    Write-Err "Could not find frontend/ folder under $projRoot"
    exit 1
}

# -----------------------------------------------------------------------
# 1) Create / clean venv
# -----------------------------------------------------------------------
if ($CleanVenv -and (Test-Path $venvPath)) {
    Write-Step "Removing existing virtual environment (-CleanVenv)..."
    Remove-Item -Recurse -Force $venvPath
}

if (-Not (Test-Path $activate)) {
    Write-Step "Creating virtual environment..."
    python -m venv .venv
    if (-Not (Test-Path $activate)) {
        Write-Err "Virtual environment creation failed (activate script not found)."
        exit 1
    }
}

Write-Step "Activating virtual environment..."
. $activate

# -----------------------------------------------------------------------
# 2) Upgrade pip tooling
# -----------------------------------------------------------------------
Write-Step "Upgrading pip, setuptools, wheel..."
python -m pip install --upgrade pip setuptools wheel
if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to upgrade pip/setuptools/wheel."
    exit 1
}

# -----------------------------------------------------------------------
# 3) Install backend deps (with pyyaml binary-wheel fallback, per execute.md)
# -----------------------------------------------------------------------
Write-Step "Installing backend dependencies..."
pip install -r backend/requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Initial backend install failed - retrying with pyyaml binary wheel first..."
    pip install pyyaml --only-binary=:all:
    pip install -r backend/requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Backend dependency installation failed. See errors above."
        Write-Host "Troubleshooting tip (from execute.md): try a clean venv with pinned pydantic/fastapi:" -ForegroundColor Yellow
        Write-Host '  Remove-Item -Recurse -Force .venv' -ForegroundColor Yellow
        Write-Host '  python -m venv .venv' -ForegroundColor Yellow
        Write-Host '  . .venv\Scripts\Activate.ps1' -ForegroundColor Yellow
        Write-Host '  pip install "pydantic==1.10.26" "fastapi==0.95.2" "uvicorn[standard]==0.22.0"' -ForegroundColor Yellow
        Write-Host '  pip install -r backend/requirements.txt' -ForegroundColor Yellow
        exit 1
    }
}
Write-Ok "Backend dependencies installed."

# -----------------------------------------------------------------------
# 4) Install frontend deps
# -----------------------------------------------------------------------
Write-Step "Installing frontend dependencies..."
Push-Location $frontendPath

if ($CleanFrontend) {
    Write-Warn "Removing node_modules and package-lock.json (-CleanFrontend)..."
    Remove-Item -Recurse -Force node_modules,package-lock.json -ErrorAction SilentlyContinue
}

npm install
if ($LASTEXITCODE -ne 0) {
    Write-Err "npm install failed. Try re-running with -CleanFrontend to wipe node_modules."
    Pop-Location
    exit 1
}
Pop-Location
Write-Ok "Frontend dependencies installed."

# -----------------------------------------------------------------------
# 5) Determine backend import path (handles 'No module named app' case)
# -----------------------------------------------------------------------
# execute.md notes two valid layouts:
#   - run from project root:  backend.app.main:app
#   - run from backend/ dir:  app.main:app
$backendAppFile = Join-Path $projRoot 'backend\app\main.py'
if (-Not (Test-Path $backendAppFile)) {
    Write-Err "Could not find backend\app\main.py - check your project layout."
    exit 1
}
$uvicornTarget = "backend.app.main:app"
$uvicornCwd    = $projRoot

# -----------------------------------------------------------------------
# 6) Start backend in a new window
# -----------------------------------------------------------------------
Write-Step "Starting backend on http://127.0.0.1:8000 ..."
$backendScript = @"
Set-Location -LiteralPath '$uvicornCwd'
. '$activate'
Write-Host 'Starting uvicorn ($uvicornTarget)...' -ForegroundColor Cyan
python -m uvicorn $uvicornTarget --host 127.0.0.1 --port 8000 --reload
if (`$LASTEXITCODE -ne 0) {
    Write-Host 'Primary import path failed, retrying from backend/ as app.main:app...' -ForegroundColor Yellow
    Set-Location -LiteralPath '$projRoot\backend'
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
}
Read-Host 'Backend process exited. Press Enter to close this window'
"@
$backendEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($backendScript))
Start-Process powershell -ArgumentList @('-NoProfile', '-EncodedCommand', $backendEncoded)

# Give backend a moment to bind the port
Start-Sleep -Seconds 3

# -----------------------------------------------------------------------
# 7) Start frontend (Vite) in a new window
# -----------------------------------------------------------------------
Write-Step "Starting frontend dev server..."
$frontendScript = @"
Set-Location -LiteralPath '$frontendPath'
Write-Host 'Running npm run dev...' -ForegroundColor Cyan
npm run dev
if (`$LASTEXITCODE -ne 0) {
    Write-Host 'npm run dev failed, falling back to npx vite...' -ForegroundColor Yellow
    npx vite
}
if (`$LASTEXITCODE -ne 0) {
    Write-Host 'npx vite failed too - falling back to direct node invocation (works around & in path)...' -ForegroundColor Yellow
    `$viteJs = Join-Path '$frontendPath' 'node_modules\vite\bin\vite.js'
    if (Test-Path `$viteJs) {
        node `$viteJs
    } else {
        Write-Host "Could not find `$viteJs - is node_modules installed correctly?" -ForegroundColor Red
    }
}
Read-Host 'Frontend process exited. Press Enter to close this window'
"@
$frontendEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($frontendScript))
Start-Process powershell -ArgumentList @('-NoProfile', '-EncodedCommand', $frontendEncoded)

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------
Write-Host ""
Write-Ok "Backend launching:  http://127.0.0.1:8000"
Write-Ok "Frontend launching: check its PowerShell window for the actual URL (default http://127.0.0.1:5173)"
Write-Warn "Two new PowerShell windows were opened for backend and frontend."
Write-Warn "Press Ctrl+C in each of those windows to stop the respective server."