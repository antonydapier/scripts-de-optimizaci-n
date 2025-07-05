# ================================================================
# Script de Mantenimiento y Optimización de Windows
# Autor: Antony Dapier
# Versión: 1.5
# ================================================================

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    # Incluir la carpeta de Descargas en el proceso de limpieza. ¡USAR CON PRECAUCIÓN!
    [switch]$LimpiarDescargas,

    # Realiza la reparación profunda del sistema con SFC y DISM (tarda mucho tiempo).
    [switch]$RepararSistema,

    # Elimina aplicaciones preinstaladas de Windows (Bloatware) como Candy Crush, etc.
    [switch]$QuitarBloatware,

    # Aplica ajustes visuales para máximo rendimiento, desactivando animaciones y transparencias.
    [switch]$AjustesVisuales,

    # Forzar el reinicio del equipo automáticamente al finalizar el script.
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
# FUNCIONES
# ==============================

function Confirm-IsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        $params = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$($MyInvocation.MyCommand.Path)`"")
        if ($LimpiarDescargas.IsPresent) { $params += "-LimpiarDescargas" }
        if ($QuitarBloatware.IsPresent) { $params += "-QuitarBloatware" }
        if ($AjustesVisuales.IsPresent) { $params += "-AjustesVisuales" }
        if ($RepararSistema.IsPresent) { $params += "-RepararSistema" }
        if ($ForzarReinicio.IsPresent) { $params += "-ForzarReinicio" }
        Start-Process powershell -ArgumentList $params -Verb RunAs
        exit
    }
}

function Test-InternetConnection {
    Write-Host "Verificando conexión a Internet..." -ForegroundColor Yellow
    if (-not (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet)) {
        Write-Host "No hay conexión. Algunas funciones pueden fallar." -ForegroundColor Red
        return $false
    }
    Write-Host "Conexión a Internet verificada." -ForegroundColor Green
    return $true
}

function Log-Error {
    param ([string]$message)
    Write-Host "ERROR: $message" -ForegroundColor Red
}

function Clear-TemporaryFiles {
    Write-Host "`nEliminando archivos temporales..." -ForegroundColor Yellow
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\Windows\Temp", "$env:TEMP") | Select-Object -Unique
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Limpiado: $path" -ForegroundColor Green
            } catch {
                Log-Error ("Error al limpiar ${path}: " + $_.Exception.Message)
            }
        }
    }
    if ($LimpiarDescargas.IsPresent) {
        Write-Host "`nLimpiando carpeta de Descargas (según solicitado)..." -ForegroundColor Yellow
        $downloadsPath = "$env:USERPROFILE\Downloads"
        if (Test-Path $downloadsPath) {
            try {
                Get-ChildItem -Path $downloadsPath -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Carpeta de Descargas limpiada." -ForegroundColor Green
            } catch {
                Log-Error ("Error al limpiar la carpeta de Descargas: " + $_.Exception.Message)
            }
        }
    }
}

function Clear-RecycleBinAllDrives {
    Write-Host "`nVaciando la Papelera de reciclaje..." -ForegroundColor Yellow
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Host "Papelera vaciada correctamente." -ForegroundColor Green
    } catch {
        Log-Error ("No se pudo vaciar la papelera: " + $_.Exception.Message)
    }
}

function Get-DiskSpace {
    Write-Host "`nEspacio en disco disponible:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "Unidad $($_.Name): $([math]::Round($_.Free/1GB,2)) GB libres de $([math]::Round($_.Used/1GB + $_.Free/1GB,2)) GB" -ForegroundColor Green
    }
}

function Set-NetworkOptimization {
    Write-Host "`nOptimizando red..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10 -Force
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10 -Force
        Write-Host "Red optimizada." -ForegroundColor Green
    } catch {
        Log-Error ("Error al optimizar red: " + $_.Exception.Message)
    }
}

function Set-UltimatePerformancePlan {
    Write-Host "`nConfigurando plan de energía para 'Máximo Rendimiento'..." -ForegroundColor Yellow
    $ultimatePlanGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    # Se suprime la salida de este comando para evitar el mensaje "No se admite" si el plan ya existe.
    powercfg -duplicatescheme $ultimatePlanGuid | Out-Null
    powercfg -setactive $ultimatePlanGuid
    Write-Host "Plan de energía 'Máximo Rendimiento' activado." -ForegroundColor Green
}

function Disable-VisualEffects {
    Write-Host "`nDesactivando efectos visuales para mejorar la agilidad del sistema..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFxSetting" -Value 2 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Force
        Write-Host "Efectos visuales desactivados." -ForegroundColor Green
    } catch {
        Log-Error ("Error al desactivar efectos visuales: " + $_.Exception.Message)
    }
}

function Remove-Bloatware {
    Write-Host "`nCreando punto de restauración del sistema antes de eliminar aplicaciones..." -ForegroundColor Cyan
    try {
        Checkpoint-Computer -Description "Antes de eliminar Bloatware con Script de Optimización" -ErrorAction Stop
        Write-Host "Punto de restauración creado con éxito." -ForegroundColor Green
    } catch {
        Log-Error ("No se pudo crear el punto de restauración. Saltando eliminación de bloatware por seguridad.")
        return
    }
    Write-Host "`nEliminando aplicaciones preinstaladas (Bloatware)..." -ForegroundColor Yellow
    $bloatware = @( "*3DBuilder*", "*3DViewer*", "*BingFinance*", "*BingNews*", "*BingSports*", "*BingWeather*", "*CandyCrush*", "*king.com*", "*EclipseManager*", "*Facebook*", "*HiddenCity*", "*Minecraft*", "*Netflix*", "*OneConnect*", "*OneNote*", "*People*", "*Photos*", "*SkypeApp*", "*SolitaireCollection*", "*Spotify*", "*Twitter*", "*Wallet*", "*YourPhone*", "*ZuneMusic*", "*ZuneVideo*", "*Xbox*", "*MixedReality.Portal*" )
    foreach ($app in $bloatware) {
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "Intentando eliminar (si existía): $app" -ForegroundColor Gray
    }
    Write-Host "Limpieza de Bloatware completada." -ForegroundColor Green
}

function Disable-GamingFeatures {
    Write-Host "`nDesactivando características de juego (Xbox Game Bar)..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseGameBarOnlyInFullscreen" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Force
        $xboxServices = @("XblAuthManager", "XblGameSave", "XboxGipSvc", "XboxNetApiSvc")
        foreach ($service in $xboxServices) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) { Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue }
        }
        Write-Host "Características de juego de Xbox desactivadas." -ForegroundColor Green
    } catch {
        Log-Error ("Error al desactivar las características de juego: " + $_.Exception.Message)
    }
}

function Disable-Telemetry {
    Write-Host "`nDeshabilitando servicios y tareas de telemetría..." -ForegroundColor Yellow
    $serviciosTelemetria = @( "DiagTrack", "dmwappushsvc", "WMPNetworkSvc", "RemoteRegistry", "RetailDemo", "diagnosticshub.standardcollector.service" )
    foreach ($s in $serviciosTelemetria) {
        $servicio = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($null -ne $servicio -and $servicio.Status -ne 'Stopped') {
            try {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "Servicio deshabilitado: $s" -ForegroundColor Gray
            } catch {
                Log-Error ("Error al desactivar servicio ${s}: " + $_.Exception.Message)
            }
        }
    }
    $tareasTelemetria = @( "\Microsoft\Windows\Application Experience\ProgramDataUpdater", "\Microsoft\Windows\Autochk\Proxy", "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator", "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask", "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector", "\Microsoft\Windows\Feedback\Siuf\DmClient", "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload", "\Microsoft\Windows\Windows Error Reporting\QueueReporting" )
    foreach ($t in $tareasTelemetria) {
        $task = Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue
        if ($null -ne $task -and $task.State -ne 'Disabled') {
            try {
                $task | Disable-ScheduledTask
                Write-Host "Tarea deshabilitada: $t" -ForegroundColor DarkGray
            } catch {
                Log-Error ("Error al desactivar tarea ${t}: " + $_.Exception.Message)
            }
        }
    }
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Force
        Write-Host "Telemetría bloqueada desde el registro." -ForegroundColor Green
    } catch {
        Log-Error ("Error al modificar el registro de telemetría: " + $_.Exception.Message)
    }
}

function Repair-SystemFiles {
    Write-Host "`nEjecutando reparación de archivos del sistema (puede tardar varios minutos)..." -ForegroundColor Yellow
    try {
        Write-Host "Paso 1/2: Ejecutando 'sfc /scannow'..." -ForegroundColor Gray
        sfc.exe /scannow | Out-Null
        Write-Host "SFC completado." -ForegroundColor Green
        Write-Host "Paso 2/2: Ejecutando 'Dism /Online /Cleanup-Image /RestoreHealth'..." -ForegroundColor Gray
        Dism.exe /Online /Cleanup-Image /RestoreHealth | Out-Null
        Write-Host "DISM completado." -ForegroundColor Green
    } catch {
        Log-Error ("Ocurrió un error durante la reparación del sistema (SFC/DISM): " + $_.Exception.Message)
    }
}

function Optimize-Drives {
    Write-Host "`nOptimizando unidades de disco (Defrag/TRIM)..." -ForegroundColor Yellow
    try {
        Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.FileSystem -ne 'RAW' } | ForEach-Object {
            Write-Host "Optimizando unidad $($_.DriveLetter):..." -ForegroundColor Gray
            Optimize-Volume -DriveLetter $_.DriveLetter -Verbose
        }
        Write-Host "Optimización de unidades completada." -ForegroundColor Green
    } catch {
        Log-Error ("Ocurrió un error durante la optimización de unidades: " + $_.Exception.Message)
    }
}

function Show-ExecutionPlan {
    Write-Host "`n========= PLAN DE EJECUCIÓN =========" -ForegroundColor Cyan
    Write-Host "Se realizarán las siguientes tareas:"
    Write-Host "-------------------------------------"
    
    Write-Host "[TAREAS ESTÁNDAR]" -ForegroundColor Yellow
    Write-Host " - Configurar plan de 'Máximo Rendimiento'"
    Write-Host " - Desactivar características de juego (Xbox)"
    Write-Host " - Optimizar configuración de red"
    Write-Host " - Deshabilitar telemetría de Windows"
    Write-Host " - Limpieza de archivos temporales y Papelera"
    Write-Host " - Optimización de unidades de disco (Defrag/TRIM)"
    Write-Host " - Revisión del espacio en disco"
    Write-Host ""

    if ($QuitarBloatware.IsPresent -or $AjustesVisuales.IsPresent -or $RepararSistema.IsPresent -or $LimpiarDescargas.IsPresent) {
        Write-Host "[TAREAS OPCIONALES (Activadas por parámetro)]" -ForegroundColor Yellow
        if ($QuitarBloatware.IsPresent) { Write-Host " - Eliminar Bloatware (con punto de restauración)" -ForegroundColor Green }
        if ($AjustesVisuales.IsPresent) { Write-Host " - Aplicar ajustes visuales para rendimiento" -ForegroundColor Green }
        if ($RepararSistema.IsPresent) { Write-Host " - Reparación profunda del sistema (SFC/DISM)" -ForegroundColor Green }
        if ($LimpiarDescargas.IsPresent) { Write-Host " - Limpiar carpeta de Descargas ¡CON PRECAUCIÓN!" -ForegroundColor Red }
    }
    Write-Host "-------------------------------------"
}

# ==============================
# EJECUCIÓN PRINCIPAL
# ==============================

Confirm-IsAdmin
if (-not (Test-InternetConnection)) { Stop-Transcript; exit }

# Mostrar el plan de ejecución al inicio para que el informe sea coherente.
Show-ExecutionPlan

Write-Host "`n============================="
Write-Host "=== MANTENIMIENTO INICIADO ===" -ForegroundColor Cyan

# Tareas estándar
Set-UltimatePerformancePlan
Disable-GamingFeatures
Set-NetworkOptimization
Disable-Telemetry
Clear-TemporaryFiles
Clear-RecycleBinAllDrives
Optimize-Drives
Get-DiskSpace

# Tareas opcionales
if ($QuitarBloatware.IsPresent) { Remove-Bloatware }
if ($AjustesVisuales.IsPresent) { Disable-VisualEffects }
if ($RepararSistema.IsPresent) { Repair-SystemFiles }

Write-Host "`n============================="
Write-Host "MANTENIMIENTO FINALIZADO CORRECTAMENTE." -ForegroundColor Green

# --- FINALIZACIÓN Y REINICIO ---
Stop-Transcript
Write-Host "`nUn informe detallado de esta sesión se ha guardado en: $informePath" -ForegroundColor Cyan

if ($ForzarReinicio.IsPresent) {
    Write-Host "`nATENCIÓN: El sistema se reiniciará en 20 segundos (parámetro -ForzarReinicio detectado)." -ForegroundColor Yellow
    Start-Sleep -Seconds 20
    Restart-Computer -Force
} else {
    try {
        $respuesta = Read-Host -Prompt 'Se recomienda reiniciar para aplicar todos los cambios. ¿Deseas reiniciar ahora? (S/N)'
        if ($respuesta -match '^[sS]$') {
            Write-Host 'Reiniciando el equipo...' -ForegroundColor Green
            Restart-Computer
        } else {
            Write-Host 'Reinicio cancelado. Recuerda reiniciar manualmente más tarde.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host 'No se pudo leer la entrada. Por favor, reinicia manualmente.' -ForegroundColor Yellow
    }
}
