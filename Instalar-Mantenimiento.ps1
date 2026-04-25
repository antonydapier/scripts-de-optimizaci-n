# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Comando directo y simple, como el de Chris Titus
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command ""iex (irm https://bit.ly/pc-mantenimiento-diario)"""

$Shortcut.IconLocation = "imageres.dll,109" # Icono de herramientas de Windows
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

[System.Windows.Forms.MessageBox]::Show("¡Icono creado!`n`nUsa el acceso directo del escritorio para empezar.", "Antony Dapier")
