# Script para crear el acceso directo al mantenimiento remoto
$Desktop = [System.Environment]::GetFolderPath('Desktop')
$ShortcutPath = Join-Path $Desktop "Optimizar PC - Antony Dapier.lnk" # Nombre del acceso directo
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)

# Este es el comando que se ejecutará al dar doble clic
# -WindowStyle Hidden hace que la consola no sea visible
$Command = "iex (irm https://bit.ly/pc-mantenimiento-diario)" # Tu enlace Bitly
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$Command`""
$Shortcut.IconLocation = "imageres.dll,109" # Icono de mantenimiento más moderno (puedes cambiarlo)
$Shortcut.Description = "Mantenimiento y Optimización Antony Dapier"
$Shortcut.Save()

# Forzar que el acceso directo pida privilegios de administrador
$bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20 # Activa el bit de "Ejecutar como administrador"
[System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)

Write-Host "¡Acceso directo creado en el escritorio con éxito!" -ForegroundColor Green
