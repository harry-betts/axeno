#Requires -Version 5.1
<#
.SYNOPSIS
    Axeno local two-client test harness (Windows).

.DESCRIPTION
    Run from the repo root that contains .\axeno-client and .\axeno-server.
    It will:
      1. Delete the two local test app-data folders in %APPDATA%
      2. Recreate .\axeno-client2 from .\axeno-client
      3. Patch client2 to use Vite port 1421 and identifier com.hbz.axeno-client2
      4. Run npm install in both clients
      5. Start the relay server and both Tauri dev clients in separate terminals

.NOTES
    Requires: npm, cargo, and Windows Terminal (wt) or a fallback terminal.
    Run with: powershell -ExecutionPolicy Bypass -File run-test.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
$RootDir  = $PSScriptRoot
$ClientA  = Join-Path $RootDir 'axeno-client'
$ClientB  = Join-Path $RootDir 'axeno-client2'
$ServerDir = Join-Path $RootDir 'axeno-server'

$AppIdA   = 'com.hbz.axeno-client'
$AppIdB   = 'com.hbz.axeno-client2'
$PortA    = '1420'
$PortB    = '1421'
$RelayPort = '8787'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Log  { param([string]$Msg) Write-Host "[axeno-test] $Msg" -ForegroundColor Cyan }
function Warn { param([string]$Msg) Write-Host "[axeno-test warning] $Msg" -ForegroundColor Yellow }
function Fail { param([string]$Msg) Write-Host "[axeno-test error] $Msg" -ForegroundColor Red; exit 1 }

function Require-Dir {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Container)) { Fail "Missing directory: $Path" }
}

function Require-Cmd {
    param([string]$Cmd)
    if (-not (Get-Command $Cmd -ErrorAction SilentlyContinue)) { Fail "Missing command: $Cmd" }
}

function Is-PortInUse {
    param([string]$Port)
    $conns = netstat -an 2>$null | Select-String ":$Port\s"
    return ($null -ne $conns)
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
Require-Dir $ClientA
Require-Dir $ServerDir
Require-Cmd 'npm'
Require-Cmd 'cargo'

# ---------------------------------------------------------------------------
# 1. Clean app-data
# ---------------------------------------------------------------------------
Log "Deleting local Axeno test app data in %APPDATA%"
# $AppDataA = Join-Path $env:APPDATA $AppIdA
# $AppDataB = Join-Path $env:APPDATA $AppIdB
# Remove-Item -Recurse -Force $AppDataA -ErrorAction SilentlyContinue
# Remove-Item -Recurse -Force $AppDataB -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 2. Sync axeno-client -> axeno-client2
# ---------------------------------------------------------------------------
Log "Syncing axeno-client -> axeno-client2 (preserving compiled output)"

# Directories to skip when mirroring (we never want to wipe these in client2)
$ExcludeDirs = @('node_modules', 'dist', 'target', '.git')

if (-not (Test-Path $ClientB -PathType Container)) {
    New-Item -ItemType Directory -Path $ClientB | Out-Null
}

# Mirror everything except the excluded dirs.
# We use robocopy in "mirror" mode but with per-dir exclusions.
$RobocopyArgs = @(
    $ClientA, $ClientB,
    '/MIR',          # mirror (delete files in dest that are gone from src)
    '/NFL', '/NDL', '/NJH', '/NJS', '/NC', '/NS',  # suppress most output
    '/XD'            # exclude directories (must be last before the dir names)
) + $ExcludeDirs

$rc = (Start-Process robocopy -ArgumentList $RobocopyArgs -Wait -PassThru -NoNewWindow).ExitCode
# robocopy exit codes 0-7 are success/informational; 8+ are errors
if ($rc -ge 8) { Fail "robocopy failed with exit code $rc" }

# ---------------------------------------------------------------------------
# 3. Patch client2's package.json and tauri.conf.json
# ---------------------------------------------------------------------------
Log "Patching client2 package.json and tauri.conf.json"

# --- package.json ---
$PkgPath = Join-Path $ClientB 'package.json'
$pkg = Get-Content $PkgPath -Raw | ConvertFrom-Json

if (-not ($pkg.PSObject.Properties.Name -contains 'scripts')) {
    $pkg | Add-Member -MemberType NoteProperty -Name 'scripts' -Value ([PSCustomObject]@{})
}
# Set (or overwrite) the dev script
if ($pkg.scripts.PSObject.Properties.Name -contains 'dev') {
    $pkg.scripts.dev = "vite --port $PortB"
} else {
    $pkg.scripts | Add-Member -MemberType NoteProperty -Name 'dev' -Value "vite --port $PortB"
}
$pkg | ConvertTo-Json -Depth 20 | Set-Content $PkgPath -Encoding UTF8

# --- tauri.conf.json ---
$TauriConfPath = Join-Path $ClientB 'src-tauri' 'tauri.conf.json'
$conf = Get-Content $TauriConfPath -Raw | ConvertFrom-Json

$conf.productName = 'Axeno 2'
$conf.identifier  = $AppIdB

# build.devUrl
if (-not ($conf.PSObject.Properties.Name -contains 'build')) {
    $conf | Add-Member -MemberType NoteProperty -Name 'build' -Value ([PSCustomObject]@{})
}
if ($conf.build.PSObject.Properties.Name -contains 'devUrl') {
    $conf.build.devUrl = "http://localhost:$PortB"
} else {
    $conf.build | Add-Member -MemberType NoteProperty -Name 'devUrl' -Value "http://localhost:$PortB"
}

# app.windows[0].title
if (-not ($conf.PSObject.Properties.Name -contains 'app')) {
    $conf | Add-Member -MemberType NoteProperty -Name 'app' -Value ([PSCustomObject]@{})
}
if ($conf.app.PSObject.Properties.Name -contains 'windows' -and $conf.app.windows.Count -gt 0) {
    $conf.app.windows[0].title = 'Axeno 2'
}

# app.security.csp connect-src
if (-not ($conf.app.PSObject.Properties.Name -contains 'security')) {
    $conf.app | Add-Member -MemberType NoteProperty -Name 'security' -Value ([PSCustomObject]@{})
}
$security = $conf.app.security
if ($security.PSObject.Properties.Name -contains 'csp') {
    $csp = $security.csp
    if ($csp -is [PSCustomObject] -and ($csp.PSObject.Properties.Name -contains 'connect-src')) {
        $connectSrc = $csp.'connect-src'
        foreach ($item in @("http://localhost:$PortB", "http://127.0.0.1:$PortB")) {
            if ($connectSrc -notmatch [regex]::Escape($item)) {
                $connectSrc = "$connectSrc $item".Trim()
            }
        }
        $csp.'connect-src' = $connectSrc
    }
}

$conf | ConvertTo-Json -Depth 20 | Set-Content $TauriConfPath -Encoding UTF8

# ---------------------------------------------------------------------------
# 4. npm install
# ---------------------------------------------------------------------------
Log "Installing npm dependencies in client A"
Push-Location $ClientA
npm install
Pop-Location

Log "Installing npm dependencies in client B"
Push-Location $ClientB
npm install
Pop-Location

# ---------------------------------------------------------------------------
# 5. Port-in-use warnings
# ---------------------------------------------------------------------------
if (Is-PortInUse $RelayPort) {
    Warn "Port $RelayPort already appears to be in use. If the relay fails, kill the process with: netstat -ano | findstr :$RelayPort  then: taskkill /PID <pid> /F"
}
if (Is-PortInUse $PortA) {
    Warn "Port $PortA already in use. Client A may fail if another Vite server is running."
}
if (Is-PortInUse $PortB) {
    Warn "Port $PortB already in use. Client B may fail if another Vite server is running."
}

# ---------------------------------------------------------------------------
# Terminal launcher
# ---------------------------------------------------------------------------
function Run-InTerminal {
    param(
        [string]$Title,
        [string]$Dir,
        [string]$Cmd
    )

    # The command string we'll run inside the new terminal.
    # We cd into the dir, run the command, then pause so the window stays open.
    $Inner = "cd /d `"$Dir`" && ($Cmd) & pause"

    if (Get-Command 'wt' -ErrorAction SilentlyContinue) {
        # Windows Terminal — opens a new tab
        Start-Process wt -ArgumentList "new-tab --title `"$Title`" cmd /k `"$Inner`""
    } elseif (Get-Command 'pwsh' -ErrorAction SilentlyContinue) {
        Start-Process pwsh -ArgumentList "-NoExit", "-Command", "Set-Location '$Dir'; $Cmd"
    } else {
        # Plain cmd fallback
        Start-Process cmd -ArgumentList "/k", $Inner
    }
}

# ---------------------------------------------------------------------------
# 6. Launch processes
# ---------------------------------------------------------------------------
Log "Starting Axeno relay server"
Run-InTerminal -Title 'Axeno Server' -Dir $ServerDir `
    -Cmd 'set RUST_LOG=axeno_server=debug,tower_http=info && cargo run'
Start-Sleep -Seconds 2

Log "Starting client A on Vite port $PortA"
Run-InTerminal -Title 'Axeno Client A' -Dir $ClientA `
    -Cmd 'npm run tauri dev'
Start-Sleep -Seconds 2

Log "Starting client B on Vite port $PortB"
Run-InTerminal -Title 'Axeno Client B' -Dir $ClientB `
    -Cmd 'npm run tauri dev'

Log "Done. Both clients should connect to ws://127.0.0.1:${RelayPort}/ws"
Log "Client A app data: $env:APPDATA\$AppIdA"
Log "Client B app data: $env:APPDATA\$AppIdB"