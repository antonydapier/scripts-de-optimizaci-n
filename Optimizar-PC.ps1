# Optimizar-PC-Avanzado.ps1

Write-Host "Iniciando optimización avanzada de la PC para diseñadores..." -ForegroundColor Cyan

# 1. Eliminar Bloatware (AppX innecesarias)
Write-Host "Eliminando bloatware..."
Get-AppxPackage *xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *bing* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *zune* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *solitaire* | Remove-AppxPackage -ErrorAction SilentlyContinue

# 2. Desactivar servicios innecesarios (seguros para diseñadores)
Write-Host "Desactivando servicios innecesarios..."
$servicesToDisable = @(
    'DiagTrack',              # Telemetría
    'MapsBroker',            # Mapas offline
    'WMPNetworkSvc',         # Compartir multimedia
    'WerSvc',                # Informe de errores
    'RetailDemo',            # Modo demo de tiendas
    'Fax',                   # Servicio de fax
    'PimIndexMaintenanceSvc', # Indexación de contactos
    'SensorService',         # Sensores (no usados)
    'TabletInputService'     # Teclado táctil en PCs
)
foreach ($svc in $servicesToDisable) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}

# 3. Optimizar efectos visuales
Write-Host "Optimización visual..."
$visualSettings = @"
Windows Registry Editor Version 5.00
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=dword:00000002
"@
$regPath = "$env:TEMP\visual.reg"
$visualSettings | Out-File -Encoding ASCII $regPath
reg import $regPath
Remove-Item $regPath -Force

# 4. Mejor rendimiento en Adobe
Write-Host "Configurando Adobe para alto rendimiento..."
reg add "HKCU\Software\Adobe\Photoshop\120.0" /v "Performance" /t REG_DWORD /d 1 /f 2>$null

# 5. Eliminar tareas programadas innecesarias
Write-Host "Eliminando tareas innecesarias..."
$tasksToDisable = @(
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater'
)
foreach ($task in $tasksToDisable) {
    schtasks /Change /TN $task /Disable 2>$null
}

# 6. Limpieza de archivos temporales
Write-Host "Limpiando archivos temporales..."
Get-ChildItem "$env:TEMP" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

# 7. Verificación rápida de integridad del sistema
Write-Host "Verificando archivos del sistema (rápido)..."
dism /Online /Cleanup-Image /ScanHealth | Out-Null

Write-Host "\nOptimización avanzada completada. Reinicia tu PC para aplicar todos los cambios." -ForegroundColor Green
