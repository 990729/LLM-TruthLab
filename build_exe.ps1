$ErrorActionPreference = "Stop"
$ProjRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjRoot

$Py = Join-Path $ProjRoot ".venv\Scripts\python.exe"
$PyInstaller = Join-Path $ProjRoot ".venv\Scripts\pyinstaller.exe"

Write-Host "[1/3] Generating application icon..." -ForegroundColor Cyan
& $Py make_icon.py
if ($LASTEXITCODE -ne 0) { throw "Icon generation failed with exit code $LASTEXITCODE" }

Write-Host "[2/3] Running test suite before packaging..." -ForegroundColor Cyan
& $Py -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Pytest failed with exit code $LASTEXITCODE" }

Write-Host "[3/3] Packaging standalone Windows EXE (LLM-TruthLab.exe)..." -ForegroundColor Cyan
& $PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name "LLM-TruthLab" `
  --icon "assets\app.ico" `
  --add-data "web\index.html;web" `
  --collect-data certifi `
  --hidden-import "audit_engine" `
  app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$ExePath = Join-Path $ProjRoot "dist\LLM-TruthLab.exe"
if (Test-Path $ExePath) {
    $SizeMB = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
    Write-Host "`nSUCCESS! Built: $ExePath ($SizeMB MB)" -ForegroundColor Green
} else {
    throw "Build failed: $ExePath not found."
}
