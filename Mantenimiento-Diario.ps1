# Mantenimiento-Diario.ps1
Write-Host "Iniciando la optimización de la PC..."
# Ejecutar como Administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Ejecuta PowerShell como Administrador." -ForegroundColor Red
    exit
}

Write-Host "=== MANTENIMIENTO DIARIO DE WINDOWS PARA DISEÑADORES ===" -ForegroundColor Cyan

# -------------- 1. PREGUNTAR SI QUIERE LIMPIAR PAPELERA --------------
$limpiarPapelera = Read-Host "¿Deseas vaciar la Papelera? (S/N)"
if ($limpiarPapelera -eq "S" -or $limpiarPapelera -eq "s") {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "Se ha vaciado la Papelera." -ForegroundColor Green
} else {
    Write-Host "No se eliminó nada de la Papelera." -ForegroundColor Yellow
}

# -------------- 2. PREGUNTAR SI QUIERE LIMPIAR DESCARGAS --------------
$limpiarDescargas = Read-Host "¿Deseas eliminar archivos de la carpeta Descargas? (S/N)"
if ($limpiarDescargas -eq "S" -or $limpiarDescargas -eq "s") {
    Remove-Item -Path "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Se han eliminado archivos de la carpeta Descargas." -ForegroundColor Green
} else {
    Write-Host "No se eliminó nada de la carpeta Descargas." -ForegroundColor Yellow
}

# -------------- 3. LIMPIAR ARCHIVOS TEMPORALES --------------
Write-Host "Limpiando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Archivos temporales eliminados." -ForegroundColor Green

# -------------- 4. VACÍO DE CACHÉ Y DNS --------------
Write-Host "Limpiando caché del sistema..." -ForegroundColor Yellow
ipconfig /flushdns
net stop wuauserv /y
net start wuauserv
Write-Host "Caché limpiada correctamente." -ForegroundColor Green

# -------------- 5. REPARACIÓN AUTOMÁTICA DEL SISTEMA --------------
Write-Host "Verificando y reparando archivos del sistema..." -ForegroundColor Yellow
sfc /scannow

# -------------- 6. REINICIAR SERVICIOS CLAVE --------------
$serviciosReiniciar = @("Spooler", "wuauserv", "bits", "SysMain")
foreach ($servicio in $serviciosReiniciar) {
    Restart-Service -Name $servicio -Force -ErrorAction SilentlyContinue
}
Write-Host "Servicios de rendimiento reiniciados." -ForegroundColor Green

# -------------- 7. FINALIZAR --------------
Write-Host "Mantenimiento completado. ¡Tu PC está lista para trabajar!" -ForegroundColor Cyan
