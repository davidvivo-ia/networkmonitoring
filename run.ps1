# Lanzador de ipmonitor para Windows con auto-elevación UAC.
# Uso:  .\run.ps1                    (lanza con dashboard)
#       .\run.ps1 -i "Wi-Fi"
#       .\run.ps1 --no-ui --duration 30 --export-json sesion.json

[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Args
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $Here

# 1. Asegura un venv con las dependencias instaladas.
if (-not (Test-Path .\.venv)) {
    Write-Host "[ipmonitor] Creando entorno virtual ..." -ForegroundColor Cyan
    python -m venv .venv
    & .\.venv\Scripts\python -m pip install -U pip wheel
    & .\.venv\Scripts\python -m pip install -r requirements.txt
}

# 2. Auto-elevación: si no somos admin, relanzamos pidiendo UAC.
$Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdmin   = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ipmonitor] Solicitando elevación UAC ..." -ForegroundColor Yellow
    $argLine = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
                 '-File', $MyInvocation.MyCommand.Path) + $Args
    Start-Process -FilePath "powershell.exe" -ArgumentList $argLine -Verb RunAs
    exit
}

# 3. Aviso si Npcap no parece instalado.
$npcap = Test-Path "$env:WINDIR\System32\Npcap\wpcap.dll"
if (-not $npcap) {
    Write-Host "[ipmonitor] AVISO: no se detectó Npcap. Descarga e instala desde https://npcap.com (en modo 'WinPcap API-compatible')." -ForegroundColor Yellow
}

& .\.venv\Scripts\python -m ipmonitor @Args
