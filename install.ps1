# Octane Accelerator installer for Windows
# Usage: powershell -c "irm https://octane-fast.github.io/octane-accelerator/install.ps1 | iex"

$ErrorActionPreference = "Stop"

Write-Host "⚡ Octane Accelerator Installer" -ForegroundColor Cyan
Write-Host ""

$Repo = "octane-fast/octane-accelerator"
$InstallDir = "$env:LOCALAPPDATA\OctaneAccelerator"
$Bin = "$InstallDir\octane-accelerator.exe"
$Url = "https://github.com/$Repo/releases/latest/download/octane-accelerator-windows-x64.zip"

Write-Host "  Install to: $InstallDir"
Write-Host ""

# Create install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Download
Write-Host "Downloading..."
$ZipPath = "$env:TEMP\octane-accelerator.zip"
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

# Extract
Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
Remove-Item $ZipPath -Force
Write-Host "  ✓ Binary installed" -ForegroundColor Green

# Create startup shortcut (runs on login)
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$ShortcutPath = "$StartupDir\OctaneAccelerator.lnk"
$WScript = New-Object -ComObject WScript.Shell
$Shortcut = $WScript.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $Bin
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.WindowStyle = 7  # Minimized
$Shortcut.Description = "Octane Accelerator"
$Shortcut.Save()
Write-Host "  ✓ Auto-start configured (Startup folder)" -ForegroundColor Green

# Start now
Start-Process -FilePath $Bin -WindowStyle Hidden
Write-Host "  ✓ Service started" -ForegroundColor Green

Write-Host ""
Write-Host "✅ Octane Accelerator installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  The accelerator is now running in the background."
Write-Host "  Your Octane wallet will automatically use it for faster proofs."
Write-Host ""
Write-Host "  To check status:  curl http://127.0.0.1:19876/health"
Write-Host "  To uninstall:     & '$InstallDir\uninstall.ps1'"
Write-Host ""

# Create uninstall script
@"
# Octane Accelerator Uninstaller
Write-Host "Uninstalling Octane Accelerator..."
Stop-Process -Name "octane-accelerator" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\OctaneAccelerator.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:LOCALAPPDATA\OctaneAccelerator" -Recurse -Force
Write-Host "✓ Uninstalled" -ForegroundColor Green
"@ | Out-File -FilePath "$InstallDir\uninstall.ps1" -Encoding UTF8
