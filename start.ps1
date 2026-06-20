# =============================================================================
# Packet-Intel Safe Start Script (FIXED VERSION)
# =============================================================================

param(
    [switch]$CleanAll
)

$ErrorActionPreference = "Contiinue"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }

# ---------------------------------------------------------------------
# 0) Paths
# ---------------------------------------------------------------------
$projRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projRoot

$venvPath     = Join-Path $projRoot ".venv"
$activatePath = Join-Path $venvPath "Scripts\Activate.ps1"
$backendReq   = Join-Path $projRoot "backend\requirements.txt"
$frontendPath = Join-Path $projRoot "frontend"

Write-Host "`nProject: $projRoot" -ForegroundColor Green

# ---------------------------------------------------------------------
# 1) Kill stuck processes (VERY IMPORTANT)
# ---------------------------------------------------------------------
Write-Step "Stopping running Python/Node processes..."
taskkill /F /IM python.exe 2>$null | Out-Null
taskkill /F /IM node.exe 2>$null | Out-Null
taskkill /F /IM npm.exe 2>$null | Out-Null
Write-Ok "Processes cleared"

# ---------------------------------------------------------------------
# 2) Delete broken venv if requested or detected
# ---------------------------------------------------------------------
if ($CleanAll -and (Test-Path $venvPath)) {
    Write-Step "Removing existing venv (-CleanAll)..."
    Remove-Item -Recurse -Force $venvPath -ErrorAction SilentlyContinue
}

if (Test-Path $activatePath) {
    # sanity check: if venv is broken, rebuild it
    Write-Warn "Existing venv detected - keeping unless broken"
} else {
    Write-Step "Creating fresh virtual environment..."
    python -m venv .venv
}

# If venv still doesn't exist → hard fail
if (-not (Test-Path $activatePath)) {
    Write-Err "Virtual environment creation failed"
    exit 1
}

# ---------------------------------------------------------------------
# 3) Activate venv
# ---------------------------------------------------------------------
Write-Step "Activating virtual environment..."
. $activatePath

# ---------------------------------------------------------------------
# 4) Upgrade pip safely (NO pip.exe usage)
# ---------------------------------------------------------------------
Write-Step "Upgrading pip tooling..."
python -m ensurepip --upgrade | Out-Null
python -m pip install --upgrade pip setuptools wheel

# ---------------------------------------------------------------------
# 5) FIXED dependency strategy (prevents your FastAPI crash)
# ---------------------------------------------------------------------
Write-Step "Installing backend dependencies (safe mode)..."

# Force known compatible versions FIRST (prevents crashes)
python -m pip install "fastapi==0.95.2" "uvicorn[standard]==0.22.0" "pydantic<2"

if ($LASTEXITCODE -ne 0) {
    Write-Err "Core dependency install failed"
    exit 1
}

# Then install project requirements
python -m pip install -r backend/requirements.txt

Write-Ok "Backend dependencies installed"

# ---------------------------------------------------------------------
# 6) Install frontend
# ---------------------------------------------------------------------
Write-Step "Installing frontend dependencies..."
Set-Location $frontendPath
npm install

if ($LASTEXITCODE -ne 0) {
    Write-Err "Frontend install failed"
    exit 1
}

Set-Location $projRoot
Write-Ok "Frontend ready"

# ---------------------------------------------------------------------
# 7) Start backend
# ---------------------------------------------------------------------
Write-Step "Starting backend..."

$backendCmd = @"
Set-Location '$projRoot'
. '$activatePath'
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
Read-Host 'Backend stopped. Press Enter to close.'
"@

$backendEncoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($backendCmd)
)

Start-Process powershell -ArgumentList "-NoExit","-EncodedCommand",$backendEncoded

Start-Sleep 3

# ---------------------------------------------------------------------
# 8) Start frontend
# ---------------------------------------------------------------------
Write-Step "Starting frontend..."

$frontendCmd = @"
Set-Location '$frontendPath'
npm run dev
Read-Host 'Frontend stopped. Press Enter to close.'
"@

$frontendEncoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($frontendCmd)
)

Start-Process powershell -ArgumentList "-NoExit","-EncodedCommand",$frontendEncoded

# ---------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------
Write-Host "`n====================================" -ForegroundColor Green
Write-Ok "Backend:  http://127.0.0.1:8000"
Write-Ok "Frontend: http://127.0.0.1:5173"
Write-Host "====================================`n" -ForegroundColor Green