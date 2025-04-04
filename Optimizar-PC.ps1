# Optimizar-PC.ps1
Write-Host "Iniciando la optimización de la PC..."
# Ejecutar como Administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Ejecuta PowerShell como Administrador." -ForegroundColor Red
    exit
}

Write-Host "Optimizando Windows para Diseñadores..." -ForegroundColor Cyan

# -------------- 1. ELIMINAR BLOATWARE SIN AFECTAR PROGRAMAS NECESARIOS --------------
$appsEliminar = @(
    "*xbox*", "*solitaire*", "*skype*", "*yourphone*", "*bing*", "*people*", "*zune*",
    "*feedbackhub*", "*getstarted*", "*cortana*", "*3d*", "*mixedreality*", "*officehub*"
)

foreach ($app in $appsEliminar) {
    Get-AppxPackage $app | Remove-AppxPackage -ErrorAction SilentlyContinue
}

Write-Host "Bloatware eliminado correctamente." -ForegroundColor Green

# -------------- 2. DESHABILITAR SERVICIOS INNECESARIOS (PERO RESPETANDO RED, ADOBE Y ANYDESK) --------------
$serviciosDeshabilitar = @(
    "DiagTrack",  # Telemetría de Windows
    "dmwappushservice",  # Envío de datos innecesarios a Microsoft
    "RetailDemo",  # Modo demo para tiendas
    "SysMain",  # Superfetch (si usas SSD, mejor desactivarlo)
    "WbioSrvc",  # Reconocimiento biométrico (innecesario si no usas huella digital)
    "lfsvc",  # Servicio de geolocalización (innecesario en PCs de trabajo)
    "RemoteRegistry",  # Registro remoto (potencial riesgo de seguridad)
    "stisvc",  # Adquisición de imágenes de Windows (innecesario si no usas escáner)
    "WdNisSvc",  # Protección avanzada de Windows Defender (ya tienes antivirus?)
    "OneSyncSvc",  # Sincronización de cuentas innecesaria
    "PcaSvc",  # Asistencia de compatibilidad de programas
    "CdpSvc",  # Servicio de conexión de dispositivos (Bluetooth, no siempre necesario)
    "TabletInputService" # Servicios de lápiz y entrada táctil (innecesario en PCs sin touchscreen)
)

foreach ($servicio in $serviciosDeshabilitar) {
    Get-Service -Name $servicio -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}

Write-Host "Servicios innecesarios deshabilitados." -ForegroundColor Green

# -------------- 3. MANTENER SERVICIOS ESENCIALES PARA DISEÑO --------------
$serviciosMantener = @(
    "Spooler",  # Servicio de impresión
    "PrintWorkflowUserSvc",  # Manejo de trabajos de impresión
    "AdobeARMservice",  # Actualizaciones de Adobe
    "AdobeUpdateService",  # Mantenimiento de Adobe
    "AnyDesk",  # Soporte remoto
    "ResilioSyncService"  # Transferencia de archivos P2P
)

foreach ($servicio in $serviciosMantener) {
    Get-Service -Name $servicio -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic
}

Write-Host "Servicios esenciales protegidos." -ForegroundColor Green

# -------------- 4. OPTIMIZACIÓN DE RENDIMIENTO --------------
# Configurar opciones de energía en Alto Rendimiento
powercfg /S SCHEME_MIN

# Ajustar efectos visuales para rendimiento
Write-Host "Optimizando efectos visuales..." -ForegroundColor Yellow
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
If (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force }
Set-ItemProperty -Path $RegPath -Name "VisualFXSetting" -Value 2
Write-Host "Efectos visuales optimizados." -ForegroundColor Green

# -------------- 5. MEJORAR RENDIMIENTO DE ADOBE SUITE --------------
Write-Host "Ajustando rendimiento para Adobe..." -ForegroundColor Yellow
$RegPathAdobe = "HKCU:\Software\Adobe\Photoshop"
If (!(Test-Path $RegPathAdobe)) { New-Item -Path $RegPathAdobe -Force }
Set-ItemProperty -Path $RegPathAdobe -Name "GPUPerformance" -Value 1
Set-ItemProperty -Path $RegPathAdobe -Name "MemoryUsage" -Value 75
Write-Host "Adobe Suite configurado para mejor rendimiento." -ForegroundColor Green

# -------------- 6. LIMPIAR ARCHIVOS TEMPORALES --------------
Write-Host "Limpiando archivos temporales..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Limpieza de archivos temporales completada." -ForegroundColor Green

# -------------- 7. FINALIZAR --------------
Write-Host "Optimización completada. Reinicia la PC para aplicar cambios." -ForegroundColor Cyan
