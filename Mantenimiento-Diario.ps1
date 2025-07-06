# ================================================================
# Script de Mantenimiento y Optimización de Windows
# Autor: Antony Dapier
# Versión: 7.0
# ================================================================

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    # Fuerza el reinicio automático al finalizar sin preguntar.
    [switch]$ForzarReinicio
)

# --- INICIO DE LA CONFIGURACIÓN DEL INFORME ---
$informePath = "$env:USERPROFILE\Desktop\Informe_Optimizacion_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
try {
    Start-Transcript -Path $informePath -ErrorAction Stop
} catch {
    Write-Host "No se pudo crear el archivo de informe en el Escritorio. Verifique los permisos." -ForegroundColor Red
    exit
}

# ==============================
# FUNCIONES DE AYUDA
# ==============================

function Log-Error {
    param ([string]$message)
    Write-Host "ERROR: $message" -ForegroundColor Red
}

function Write-TaskStatus {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TaskName,

        [Parameter(Mandatory=$true)]
        [scriptblock]$Action
    )
    Write-Host -NoNewline "  -> $TaskName..."
    try {
        & $Action
        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FALLÓ]" -ForegroundColor Red
        Log-Error "Error en la tarea '$TaskName': $($_.Exception.Message)"
    }
}

# ==============================
# FUNCIONES DE TAREA (SILENCIOSAS)
# ==============================

function Confirm-IsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        $params = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$($MyInvocation.MyCommand.Path)`"")
        Start-Process powershell -ArgumentList $params -Verb RunAs
        exit
    }
}

function Test-InternetConnection {
    if (-not (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet)) {
        throw "No hay conexión a Internet."
    }
}

function Clear-TemporaryFiles {
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\Windows\Temp", "$env:TEMP") | Select-Object -Unique
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Clear-DownloadsFolder {
    $downloadsPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $downloadsPath) {
        Get-ChildItem -Path $downloadsPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Clear-RecycleBinAllDrives {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

function Get-DiskSpace {
    Write-Host "`nEspacio en disco disponible:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "Unidad $($_.Name): $([math]::Round($_.Free/1GB,2)) GB libres de $([math]::Round($_.Used/1GB + $_.Free/1GB,2)) GB" -ForegroundColor Green
    }
}

function Flush-DnsCache {
    ipconfig /flushdns | Out-Null
}

function Set-NetworkOptimization {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10 -Force
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10 -Force
}

function Disable-VisualEffects {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFxSetting" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force
}

function Remove-Bloatware {
    Write-Host "`n  -> Creando punto de restauración..." -NoNewline
    try {
        Checkpoint-Computer -Description "Antes de eliminar Bloatware con Script de Optimización" -ErrorAction Stop
        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FALLÓ]" -ForegroundColor Red
        Log-Error ("No se pudo crear el punto de restauración. Saltando eliminación de bloatware por seguridad.")
        Write-Host "     SUGERENCIA: Asegúrate de que la 'Protección del sistema' esté activada para tu unidad C:." -ForegroundColor Cyan
        return
    }

    Write-Host "  -> Eliminando aplicaciones preinstaladas (Bloatware)..."
    $bloatware = @(
        "*3DBuilder*", "*3DViewer*", "*BingFinance*", "*BingNews*", "*BingSports*", 
        "*BingWeather*", "*CandyCrush*", "*king.com*", "*EclipseManager*", "*Facebook*",
        "*HiddenCity*", "*Minecraft*", "*OneConnect*", "*OneNote*", 
        "*Microsoft.People*", "*Photos*", "*SkypeApp*", "*Twitter*", 
        "*Wallet*", "*YourPhone*", "*ZuneMusic*", "*ZuneVideo*", 
        "*XboxApp*", "*XboxGamingOverlay*", "*XboxSpeechToTextOverlay*",
        "*MixedReality.Portal*"
    )
    foreach ($app in $bloatware) {
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
    Write-Host "     Limpieza de Bloatware completada." -ForegroundColor Green
}

function Disable-StartupApps {
    $startupExclusions = @("security", "antivirus", "defender", "nvidia", "amd", "intel", "audio", "realtek", "synaptics", "onedrive", "dropbox")
    $runKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")

    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $backupKey = "${key}_DisabledByScript"
            if (-not (Test-Path $backupKey)) { New-Item -Path $backupKey -Force | Out-Null }

            $properties = Get-ItemProperty -Path $key
            $appNames = $properties.PSObject.Properties.Name | Where-Object { $_ -notlike "PS*" -and $_ -ne "(default)" }

            foreach ($appName in $appNames) {
                if (-not ($startupExclusions | Where-Object { $appName -ilike "*$_*" -or $properties.$appName -ilike "*$_*"})) {
                    try {
                        Move-ItemProperty -Path $key -Destination $backupKey -Name $appName -Force -ErrorAction Stop
                    } catch {
                        # Silently ignore if it fails, as it's not critical
                    }
                }
            }
        }
    }
}

function Disable-GamingFeatures {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseGameBarOnlyInFullscreen" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Force
    $xboxServices = @("XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")
    foreach ($service in $xboxServices) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) { Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue }
    }
}

function Optimize-BackgroundProcesses {
    $serviciosADeshabilitar = @( "DiagTrack", "dmwappushsvc", "WMPNetworkSvc", "RemoteRegistry", "RetailDemo", "diagnosticshub.standardcollector.service", "MapsBroker", "Fax" )
    foreach ($s in $serviciosADeshabilitar) {
        $servicio = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($null -ne $servicio -and $servicio.Status -ne 'Stopped') {
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    $tareasTelemetria = @( "\Microsoft\Windows\Application Experience\ProgramDataUpdater", "\Microsoft\Windows\Autochk\Proxy", "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator", "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask", "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" )
    foreach ($t in $tareasTelemetria) {
        $task = Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue
        if ($null -ne $task -and $task.State -ne 'Disabled') {
            $task | Disable-ScheduledTask -ErrorAction SilentlyContinue
        }
    }
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Force
}

function Repair-SystemFiles {
    Write-Progress -Activity "Reparando Sistema" -Status "Paso 1/2: Ejecutando SFC /scannow (esto puede tardar)..." -PercentComplete 0
    Start-Process sfc.exe -ArgumentList "/scannow" -Wait -NoNewWindow
    
    Write-Progress -Activity "Reparando Sistema" -Status "Paso 2/2: Ejecutando DISM (esto puede tardar aún más)..." -PercentComplete 50
    Start-Process Dism.exe -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -NoNewWindow
    
    Write-Progress -Activity "Reparando Sistema" -Status "Completado." -Completed
}

function Optimize-Drives {
    Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -ne 'RAW' } | ForEach-Object {
        Optimize-Volume -DriveLetter $_.DriveLetter
    }
}

function Handle-SmartRestart {
    $respuesta = "n"
    if (-not $ForzarReinicio.IsPresent) {
        Write-Host "`n"
        $respuesta = Read-Host -Prompt "El mantenimiento ha finalizado. ¿Deseas reiniciar ahora para aplicar todos los cambios? (s/n)"
    }

    if ($ForzarReinicio.IsPresent -or $respuesta -eq 's') {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "REINICIO PROGRAMADO" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "El equipo se reiniciará para aplicar todos los cambios." -ForegroundColor Green
        
        try {
            for ($i = 10; $i -ge 1; $i--) {
                Write-Host -NoNewline "`rReiniciando en $i segundos... Presiona CTRL+C para cancelar. "
                Start-Sleep -Seconds 1
            }
            Write-Host "`n¡Reiniciando ahora!" -ForegroundColor Green
            Shutdown.exe /r /f /t 0
        } catch {
            Write-Host "`nReinicio cancelado por el usuario." -ForegroundColor Red
        }
    } else {
        Write-Host "`nReinicio omitido. Recuerda reiniciar manualmente para aplicar todos los cambios." -ForegroundColor Cyan
    }
}

# ==============================
# EJECUCIÓN PRINCIPAL
# ==============================

Confirm-IsAdmin

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "=== INICIANDO SCRIPT DE OPTIMIZACIÓN ===" -ForegroundColor Cyan
Write-Host "=========================================="

Write-Host "`n[Paso 1: Preparación y Verificaciones]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Verificando conexión a Internet" -Action { Test-InternetConnection }

Write-Host "`n[Paso 2: Limpieza del Sistema]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Limpiando archivos temporales" -Action { Clear-TemporaryFiles }
Write-TaskStatus -TaskName "Vaciando la Papelera de Reciclaje" -Action { Clear-RecycleBinAllDrives }
Write-TaskStatus -TaskName "Limpiando carpeta de Descargas (¡PRECAUCIÓN!)" -Action { Clear-DownloadsFolder }

Write-Host "`n[Paso 3: Optimización de Rendimiento]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Optimizando configuración de red" -Action { Set-NetworkOptimization }
Write-TaskStatus -TaskName "Limpiando caché de DNS" -Action { Flush-DnsCache }
Write-TaskStatus -TaskName "Deshabilitando aplicaciones de inicio" -Action { Disable-StartupApps }
Write-TaskStatus -TaskName "Desactivando telemetría y servicios en segundo plano" -Action { Optimize-BackgroundProcesses }
Write-TaskStatus -TaskName "Desactivando características de juego de Xbox" -Action { Disable-GamingFeatures }
Write-TaskStatus -TaskName "Ajustando efectos visuales para rendimiento" -Action { Disable-VisualEffects }
Write-TaskStatus -TaskName "Optimizando unidades de disco (Defrag/TRIM)" -Action { Optimize-Drives }

Write-Host "`n[Paso 4: Mantenimiento Profundo]" -ForegroundColor Yellow
Remove-Bloatware
Write-TaskStatus -TaskName "Reparando archivos de sistema (SFC y DISM)" -Action { Repair-SystemFiles }

Get-DiskSpace

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "MANTENIMIENTO FINALIZADO CORRECTAMENTE." -ForegroundColor Green
Write-Host "=========================================="

# Detener la transcripción ANTES de preguntar por el reinicio.
Stop-Transcript
Write-Host "`nUn informe detallado de esta sesión se ha guardado en: $informePath" -ForegroundColor Cyan

Handle-SmartRestart
