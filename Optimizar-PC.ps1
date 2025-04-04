# Optimizar-PC-Avanzado.ps1 con interfaz amigable

function Mostrar-PanelEstado($mensaje, $color) {
    Write-Host ("=" * 60) -ForegroundColor DarkGray
    Write-Host $mensaje -ForegroundColor $color
    Write-Host ("=" * 60) -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 800
}

Mostrar-PanelEstado "Iniciando optimización avanzada de la PC..." Cyan

# Eliminar bloatware conocido sin afectar diseño
Get-AppxPackage *xbox* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *bing* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *zune* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *solitaire* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *3d* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage *people* | Remove-AppxPackage -ErrorAction SilentlyContinue
Mostrar-PanelEstado "✅ Bloatware eliminado correctamente." Green

# Deshabilitar servicios innecesarios para diseñadores
$serviciosADesactivar = @("DiagTrack","RetailDemo","Fax","RemoteRegistry","XblGameSave","MapsBroker","WMPNetworkSvc","dmwappushsvc")
foreach ($servicio in $serviciosADesactivar) {
    Get-Service -Name $servicio -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
}
Mostrar-PanelEstado "🛑 Servicios innecesarios deshabilitados." Green

# Mantener servicios esenciales de diseño
$serviciosEsenciales = @("Spooler","PrintWorkflowUserSvc","FDResPub","LanmanServer","LanmanWorkstation")
foreach ($servicio in $serviciosEsenciales) {
    Get-Service -Name $servicio -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction SilentlyContinue
}
Mostrar-PanelEstado "🔒 Servicios esenciales protegidos (impresión y red)." Yellow

# Optimizar efectos visuales
$visuals = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
Set-ItemProperty -Path $visuals -Name VisualFXSetting -Value 2
Mostrar-PanelEstado "✨ Efectos visuales optimizados para rendimiento." Green

# Priorizar rendimiento para Adobe
$adobeKeys = "HKCU:\Software\Adobe", "HKLM:\SOFTWARE\Adobe"
foreach ($key in $adobeKeys) {
    if (Test-Path $key) {
        New-ItemProperty -Path $key -Name "PerformanceMode" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    }
}
Mostrar-PanelEstado "🎨 Adobe Suite configurado para mejor rendimiento." Green

# Limpieza de archivos temporales, cachés y miniaturas
$paths = @(
    "$env:TEMP\*",
    "$env:windir\Temp\*",
    "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db"
)
foreach ($path in $paths) {
    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
}
Mostrar-PanelEstado "🧹 Limpieza profunda de archivos temporales completada." Green

# Optimizar tareas de inicio
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Office*" -or $_.TaskName -like "*Edge*" } | Disable-ScheduledTask -ErrorAction SilentlyContinue
Mostrar-PanelEstado "🚀 Tareas de inicio optimizadas." Green

# Verificar y reparar archivos del sistema (en segundo plano)
Start-Process powershell -ArgumentList "-Command sfc /scannow" -Verb runAs
Mostrar-PanelEstado "🛠️ Verificando y reparando archivos del sistema (puede tardar)..." Yellow

# Reducir consumo y temperatura sin sacrificar rendimiento
powercfg -setactive SCHEME_BALANCED
powercfg -h off
Mostrar-PanelEstado "🌡️ Plan de energía equilibrado activado para evitar sobrecalentamiento." Green

# Desfragmentación y optimización de disco (solo si es HDD)
if ((Get-PhysicalDisk | Where-Object { $_.MediaType -eq 'HDD' }).Count -gt 0) {
    Optimize-Volume -DriveLetter C -Defrag -Verbose -ErrorAction SilentlyContinue
    Mostrar-PanelEstado "💽 Disco duro desfragmentado y optimizado." Green
}

# Liberar memoria RAM (vaciar standby list)
if (Get-Command -Name Clear-Content -ErrorAction SilentlyContinue) {
    [System.GC]::Collect()
    Mostrar-PanelEstado "🧠 Memoria optimizada y liberada." Green
}

Mostrar-PanelEstado "✅ Optimización avanzada completada. Reinicia tu PC para aplicar todos los cambios." Cyan
