# Mantenimiento-Diario.ps1 - Versión con opción de automatizar

Write-Host "=== MANTENIMIENTO DIARIO DE WINDOWS PARA DISEÑADORES ===" -ForegroundColor Cyan

# Validar privilegios de administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Ejecuta PowerShell como Administrador." -ForegroundColor Red
    exit
}

# 1. Preguntar si desea vaciar la papelera
$limpiarPapelera = Read-Host "¿Deseas vaciar la Papelera? (S/N)"
if ($limpiarPapelera -match "^[Ss]$") {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Papelera vaciada." -ForegroundColor Green
} else {
    Write-Host "❌ Papelera no fue modificada." -ForegroundColor Yellow
}

# 2. Preguntar si desea limpiar la carpeta Descargas
$limpiarDescargas = Read-Host "¿Deseas eliminar archivos de la carpeta Descargas? (S/N)"
if ($limpiarDescargas -match "^[Ss]$") {
    Remove-Item -Path "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Archivos en Descargas eliminados." -ForegroundColor Green
} else {
    Write-Host "❌ Descargas no fue modificada." -ForegroundColor Yellow
}

# 3. Limpiar temporales
Write-Host "🧹 Limpiando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "✅ Temporales eliminados." -ForegroundColor Green

# 4. Limpiar caché DNS
Write-Host "🌐 Limpiando caché DNS y reiniciando Windows Update..." -ForegroundColor Yellow
ipconfig /flushdns
net stop wuauserv /y
net start wuauserv
Write-Host "✅ Caché limpiada y servicios reiniciados." -ForegroundColor Green

# 5. Reparar sistema
Write-Host "🛠️ Verificando archivos del sistema..." -ForegroundColor Yellow
sfc /scannow

# 6. Reiniciar servicios clave
$servicios = @("Spooler", "wuauserv", "bits", "SysMain")
foreach ($s in $servicios) {
    Restart-Service -Name $s -Force -ErrorAction SilentlyContinue
}
Write-Host "✅ Servicios importantes reiniciados." -ForegroundColor Green

# 7. Ofrecer programar mantenimiento semanal automático
$programar = Read-Host "¿Deseas programar esta limpieza para que se ejecute cada lunes al iniciar? (S/N)"
if ($programar -match "^[Ss]$") {
    $TareaName = "Mantenimiento-Antony"
    $Accion = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command iex (iwr https://bit.ly/pc-mantenimiento-diario)"
    $Trigger = New-ScheduledTaskTrigger -AtStartup -DaysOfWeek Monday
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
    Register-ScheduledTask -Action $Accion -Trigger $Trigger -TaskName $TareaName -Principal $Principal -Force
    Write-Host "✅ Mantenimiento automático programado correctamente." -ForegroundColor Cyan
} else {
    Write-Host "📝 Mantenimiento quedará como ejecución manual." -ForegroundColor Yellow
}

Write-Host "`n🖥️ Mantenimiento finalizado. ¡Tu equipo está listo para trabajar esta semana!" -ForegroundColor Cyan
