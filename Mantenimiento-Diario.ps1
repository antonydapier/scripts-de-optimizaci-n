# ================================================================
# Script de Mantenimiento y Optimización de Windows 10 y Windows 11
# Autor: Antony Dapier
# Versión: 9.0
# ================================================================

# Requiere PowerShell 5.1 (incluido por defecto en Windows 10) para máxima compatibilidad.
#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    # Fuerza el reinicio automático al finalizar sin preguntar.
    [switch]$ForzarReinicio
)

# --- INICIO DE LA CONFIGURACIÓN DEL INFORME ---
# Usar un método más robusto para encontrar el Escritorio, compatible con OneDrive.
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$informePath = Join-Path -Path $desktopPath -ChildPath "Informe de Optimización by Antony Dapier ($(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')).txt"
try {
    Start-Transcript -Path $informePath -ErrorAction Stop
    # Escribir la cabecera personalizada en el informe
    Write-Output "Gracias por usar mi script, si llegas a tener algun problema puedes enviarme este mismo archivo. Saludos Antony Dapier`n"
} catch {
    Write-Host "No se pudo crear el archivo de informe en '$($informePath)'. Verifique los permisos." -ForegroundColor Red
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

function Clear-RecycleBinAllDrives {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

function Clear-SoftwareDistribution {
    # Detener el servicio de Windows Update para liberar los archivos
    $wasRunning = $false
    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $wasRunning = $true
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        # Esperar de forma fiable a que el servicio se detenga (hasta 30 segundos)
        $service.WaitForStatus('Stopped', [System.TimeSpan]::FromSeconds(30))
    }

    $path = "C:\Windows\SoftwareDistribution\Download"
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Reiniciar el servicio de Windows Update solo si estaba en ejecución previamente
    if ($wasRunning) {
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    }
}

function Clear-EventLogs {
    $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
    foreach ($log in $logs) {
        # Se redirige la salida de error a $null para evitar que un fallo en un solo log (p. ej. por permisos de "Acceso denegado")
        # haga que toda la tarea de "Write-TaskStatus" se marque como fallida.
        wevtutil.exe cl $log.LogName 2>$null
    }
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

function Set-GoogleDns {
    $googleDns = "8.8.8.8", "8.8.4.4"
    # Obtener los adaptadores de red activos (Ethernet, Wi-Fi) que usan IPv4
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.MediaType -eq '802.3' -or $_.MediaType -eq 'Native 802.11') }
    
    if (-not $networkAdapters) {
        throw "No se encontraron adaptadores de red activos (Ethernet o Wi-Fi)."
    }

    foreach ($adapter in $networkAdapters) {
        Write-Host "`n     -> Configurando DNS para $($adapter.Name)..." -ForegroundColor Gray
        # Solo modificar adaptadores que tienen una configuración IP
        $ipconfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
        if ($ipconfig.IPv4Address.IPAddress) {
            # El comando Set-DnsClientServerAddress ya muestra un output, no necesitamos más confirmación.
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $googleDns
        }
    }
}

function Set-NetworkOptimization {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10 -Force
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10 -Force
}

function Disable-VisualEffects {
    # Ajusta para mejor rendimiento (desactiva todo)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFxSetting" -Value 2 -Force

    # Reactiva específicamente el suavizado de fuentes y las miniaturas para un mejor balance
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 0 -Type DWord -Force

    # Desactiva la transparencia (efecto adicional para rendimiento)
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

    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    Write-Host "  -> Eliminando aplicaciones preinstaladas (Bloatware) de $osVersion..."

    if ($osVersion -like "*Windows 11*") {
        $bloatware = @(
            "*BingFinance*", "*BingNews*", "*BingSports*", "*BingWeather*", "*SolitaireCollection*",
            "*MicrosoftTeams*", "*Clipchamp*", "*Alarms*", # "*Calculator*", # "*Camera*",
            "*Family*", "*GetHelp*", "*GetStarted*", "*Maps*", "*MediaEngine*", "*ZuneMusic*", 
            "*ZuneVideo*", "*MixedReality*", "*YourPhone*", "*Windows.Photos*", "*XboxApp*"
        )
    } else {
        $bloatware = @(
            "*3DBuilder*", "*3DViewer*", "*BingFinance*", "*BingNews*", "*BingSports*", 
            "*BingWeather*", "*CandyCrush*", "*king.com*", "*EclipseManager*", "*Facebook*",
            "*HiddenCity*", "*Minecraft*", "*OneConnect*", "*OneNote*", 
            "*Microsoft.People*", "*Photos*", "*SkypeApp*", "*Twitter*", 
            "*Wallet*", "*YourPhone*", "*ZuneMusic*", "*ZuneVideo*", 
            "*XboxApp*", "*XboxGamingOverlay*", "*XboxSpeechToTextOverlay*",
            "*MixedReality.Portal*"
        )
    }
    
    # Optimización: Obtener las listas una sola vez
    $allPackages = Get-AppxPackage -AllUsers
    $allProvisionedPackages = Get-AppxProvisionedPackage -Online

    foreach ($pattern in $bloatware) {
        # Eliminar paquetes de usuario
        $allPackages | Where-Object { $_.Name -like $pattern } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

        # Eliminar paquetes provisionados para futuros usuarios
        $allProvisionedPackages | Where-Object { $_.DisplayName -like $pattern } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }

    Write-Host "     Limpieza de Bloatware completada." -ForegroundColor Green
}

function Disable-StartupApps {
    # NOTA: Esta función mueve las entradas de inicio a una clave de respaldo llamada "..._DisabledByScript".
    # Para revertir los cambios, se deben mover manualmente las entradas desde la clave de respaldo
    # de vuelta a la clave "Run" original usando el Editor del Registro (regedit.exe).
    $startupExclusions = @("security", "antivirus", "defender", "nvidia", "amd", "intel", "audio", "realtek", "synaptics", "onedrive", "dropbox", "bootcamp", "obs")
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
                        Write-Warning "No se pudo deshabilitar la app de inicio '$appName'. Es posible que se requieran permisos adicionales."
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
    Get-Service -Name $xboxServices -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
}

function Set-BandwidthLimit {
    # Habilita la política y establece el límite de ancho de banda reservable en 0%.
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
}

function Optimize-GoogleChrome {
    Write-Host "`n  -> Optimizando Google Chrome..."
    $chromeExePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    $chromeExePathX86 = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    if (-not (Test-Path $chromeExePath) -and -not (Test-Path $chromeExePathX86)) {
        Write-Host " [NO APLICA - Chrome no encontrado]" -ForegroundColor Yellow
        return
    }
    Write-Host # Newline para continuar con las subtareas

    # --- Configuración de Políticas (método recomendado y seguro) ---
    Write-Host -NoNewline "    -> Aplicando políticas de rendimiento..."
    try {
        $policyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force -ErrorAction Stop | Out-Null }

        # Desactivar "Seguir ejecutando aplicaciones en segundo plano"
        Set-ItemProperty -Path $policyPath -Name "BackgroundModeEnabled" -Value 0 -Type DWord -Force -ErrorAction Stop
        
        # Activar "Usar aceleración por hardware"
        Set-ItemProperty -Path $policyPath -Name "HardwareAccelerationModeEnabled" -Value 1 -Type DWord -Force -ErrorAction Stop

        # Activar "Ahorro de memoria"
        $perfPolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Performance"
        if (-not (Test-Path $perfPolicyPath)) { New-Item -Path $perfPolicyPath -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $perfPolicyPath -Name "MemorySaverModeEnabled" -Value 1 -Type DWord -Force -ErrorAction Stop

        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FALLÓ]" -ForegroundColor Red
        Log-Error "No se pudieron aplicar las políticas de registro para Chrome. Error: $($_.Exception.Message)"
    }

    # --- Limpieza de Datos de Navegación ---
    Write-Host -NoNewline "    -> Limpiando datos de navegación (cerrando Chrome)..."
    $chromeProcesses = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
    if ($chromeProcesses) {
        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
        # Esperar a que los procesos se cierren para evitar archivos bloqueados
        $chromeProcesses | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1 # Pequeña pausa adicional por si acaso
    }

    try {
        $chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        # Limpiar perfiles (Default y Profile *)
        $profiles = Get-ChildItem -Path "$chromeUserData\Default", "$chromeUserData\Profile *" -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $profiles) {
            # Lista ampliada de archivos y carpetas a eliminar para una limpieza más completa
            $itemsAndFoldersToRemove = @(
                # Archivos de historial y datos de navegación
                "$($profile.FullName)\History", "$($profile.FullName)\Top Sites", "$($profile.FullName)\Visited Links", "$($profile.FullName)\Web Data",
                # Carpetas de caché
                "$($profile.FullName)\Cache", "$($profile.FullName)\Code Cache", "$($profile.FullName)\GPUCache", "$($profile.FullName)\Media Cache"
            )
            foreach ($item in $itemsAndFoldersToRemove) {
                if (Test-Path $item) {
                    # -Recurse es para carpetas, pero no daña la eliminación de archivos individuales.
                    Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FALLÓ]" -ForegroundColor Red
        Log-Error "No se pudieron eliminar algunos archivos de datos de Chrome. Error: $($_.Exception.Message)"
    }
}

function Optimize-Adobe {
    Write-Host "`n  -> Optimizando aplicaciones de Adobe (limpieza de caché)..."
    $adobePath = "$env:ProgramFiles\Adobe"
    if (-not (Test-Path $adobePath)) {
        Write-Host " [NO APLICA - No se detectó instalación de Adobe]" -ForegroundColor Yellow
        return
    }

    Write-Host -NoNewline "    -> Cerrando procesos de Adobe..."
    $adobeApps = @("Photoshop", "Illustrator", "InDesign", "Premiere Pro", "AfterFX", "Audition", "Bridge")
    $processes = Get-Process -Name $adobeApps -ErrorAction SilentlyContinue
    if ($processes) {
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host " [OK]" -ForegroundColor Green
    } else {
        Write-Host " [No hay procesos activos]" -ForegroundColor Gray
    }

    Write-Host -NoNewline "    -> Limpiando caché de medios de Adobe..."
    try {
        $cachePaths = @("$env:APPDATA\Adobe\Common\Media Cache", "$env:APPDATA\Adobe\Common\Media Cache Files")
        foreach ($path in $cachePaths) {
            if (Test-Path $path) { Remove-Item -Path $path -Recurse -Force -ErrorAction Stop }
        }
        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FALLÓ]" -ForegroundColor Red
        Log-Error "No se pudo limpiar la caché de Adobe. Es posible que algunos archivos estuvieran en uso. Error: $($_.Exception.Message)"
    }
}

function Optimize-BackgroundProcesses {
    $serviciosADeshabilitar = @( "DiagTrack", "dmwappushsvc", "WMPNetworkSvc", "RemoteRegistry", "RetailDemo", "diagnosticshub.standardcollector.service", "MapsBroker", "Fax" )
    foreach ($s in $serviciosADeshabilitar) {
        $servicio = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($servicio) {
            if ($servicio.Status -ne 'Stopped') {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            }
            if ($servicio.StartType -ne 'Disabled') {
                Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
            }
        }
    }
    $tareasTelemetria = @( "\Microsoft\Windows\Application Experience\ProgramDataUpdater", "\Microsoft\Windows\Autochk\Proxy", "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator", "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask", "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" )
    foreach ($t in $tareasTelemetria) {
        $task = Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') {
            $task | Disable-ScheduledTask -ErrorAction SilentlyContinue
        }
    }
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Force
}

function Disable-SysMain {
    $servicio = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
    if ($servicio) { # Si el servicio existe
        # Lo detiene si está en ejecución y luego establece su tipo de inicio en Deshabilitado.
        $servicio | Stop-Service -Force -PassThru -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

function Clear-OldDrivers {
    # Esta utilidad elimina los paquetes de controladores que no están en uso.
    # El método es seguro: solo elimina drivers que no están asociados a ningún dispositivo.
    try {
        $oldDrivers = Get-CimInstance -ClassName Win32_PnPSignedDriver | Where-Object { -not $_.DeviceID }
        if (-not $oldDrivers) { return }

        foreach ($driver in $oldDrivers) {
            # Usamos pnputil para una desinstalación limpia del paquete de drivers.
            pnputil.exe /delete-driver $driver.InfName /uninstall /force | Out-Null
        }
    } catch {
        throw "Ocurrió un error al intentar limpiar los drivers antiguos. Error: $($_.Exception.Message)"
    }
}

function Repair-SystemFiles {
    Write-Host "`n     -> Paso 1/3: Limpiando componentes de Windows Update..." -ForegroundColor Gray
    Dism.exe /Online /Cleanup-Image /StartComponentCleanup

    Write-Host "`n     -> Paso 2/3: Ejecutando SFC /scannow (esto puede tardar)..." -ForegroundColor Gray
    sfc.exe /scannow

    Write-Host "`n     -> Paso 3/3: Ejecutando DISM /RestoreHealth (esto puede tardar aún más)..." -ForegroundColor Gray
    Dism.exe /Online /Cleanup-Image /RestoreHealth
}

function Optimize-Drives {
    $allFixedVolumes = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' }
    $volumesToOptimize = $allFixedVolumes | Where-Object { $_.FileSystem -ne 'RAW' -and $_.HealthStatus -eq 'Healthy' }

    if (-not $volumesToOptimize) {
        Write-Host "`n     -> No se encontraron unidades aptas para optimizar (Unidades fijas, con formato y en buen estado)." -ForegroundColor Yellow
        return
    }

    # Informar sobre unidades omitidas para mayor claridad
    $skippedVolumes = Compare-Object -ReferenceObject $allFixedVolumes -DifferenceObject $volumesToOptimize -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
    if ($skippedVolumes) {
        foreach ($skipped in $skippedVolumes) {
            $reason = if ($skipped.FileSystem -eq 'RAW') { "Sistema de archivos RAW" } elseif ($skipped.HealthStatus -ne 'Healthy') { "Estado no es 'Saludable' ($($skipped.HealthStatus))" } else { "Razón desconocida" }
            Write-Host "`n     -> Omitiendo Unidad $($skipped.DriveLetter): ($reason)." -ForegroundColor Gray
        }
    }

    foreach ($volume in $volumesToOptimize) {
        Write-Host "`n     -> Optimizando Unidad $($volume.DriveLetter):..." -ForegroundColor Gray -NoNewline
        # Optimize-Volume es inteligente: aplica TRIM en SSDs y Defrag en HDDs.
        # Usamos -Verbose para capturar la salida detallada.
        $result = Optimize-Volume -DriveLetter $volume.DriveLetter -Verbose 4>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $? -eq $true) {
            $optimizationType = if ($result -like "*TRIM*") { "TRIM" } elseif ($result -like "*defragment*") { "Defragmentación" } else { "Optimización" }
            Write-Host " [$optimizationType completada]" -ForegroundColor Green
        } else {
            throw "No se pudo optimizar la unidad $($volume.DriveLetter)."
        }
    }
}

function Handle-SmartRestart {
    $respuesta = "n"
    if (-not $ForzarReinicio.IsPresent) {
        Write-Host "`n"
        $respuesta = Read-Host -Prompt "El mantenimiento ha finalizado. ¿Deseas reiniciar ahora para aplicar todos los cambios? (s/n)"
    }

    if ($ForzarReinicio.IsPresent -or $respuesta -match '^(s|y|si|yes)$') {
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

# --- ADVERTENCIA INICIAL ---
Write-Host "`n=======================================================================" -ForegroundColor Yellow
Write-Host "  ADVERTENCIA: Este script cerrará programas y modificará el sistema." -ForegroundColor Yellow
Write-Host "  Por favor, GUARDE TODO SU TRABAJO y CIERRE TODAS LAS APLICACIONES." -ForegroundColor Yellow
Write-Host "=======================================================================" -ForegroundColor Yellow
try {
    for ($i = 10; $i -ge 1; $i--) {
        Write-Host -NoNewline "`rEl proceso comenzará automáticamente en $i segundos... (Presione CTRL+C para cancelar) "
        Start-Sleep -Seconds 1
    }
    Write-Host "`n" # Newline after countdown
} catch {
    Write-Host "`n`nOperación cancelada por el usuario." -ForegroundColor Red
    Stop-Transcript
    exit
}

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "=== INICIANDO SCRIPT DE OPTIMIZACIÓN ===" -ForegroundColor Cyan
Write-Host "=========================================="

Write-Host "`n[Paso 1: Preparación y Verificaciones]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Verificando conexión a Internet" -Action { Test-InternetConnection }

Write-Host "`n[Paso 2: Limpieza Profunda del Sistema]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Limpiando archivos temporales" -Action { Clear-TemporaryFiles }
Write-TaskStatus -TaskName "Vaciando la Papelera de Reciclaje" -Action { Clear-RecycleBinAllDrives }
Write-TaskStatus -TaskName "Limpiando registros de eventos de Windows" -Action { Clear-EventLogs }
Write-TaskStatus -TaskName "Limpiando caché de descargas de Windows Update" -Action { Clear-SoftwareDistribution }
Remove-Bloatware
Optimize-GoogleChrome
Optimize-Adobe
Write-TaskStatus -TaskName "Limpiando drivers antiguos del sistema (puede tardar)" -Action { Clear-OldDrivers }

Write-Host "`n[Paso 3: Optimización del Sistema y Red]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Configurando DNS de Google (8.8.8.8, 8.8.4.4)" -Action { Set-GoogleDns }
Write-TaskStatus -TaskName "Optimizando configuración de red" -Action { Set-NetworkOptimization }
Write-TaskStatus -TaskName "Eliminando límite de ancho de banda reservable" -Action { Set-BandwidthLimit }
Write-TaskStatus -TaskName "Limpiando caché de DNS" -Action { Flush-DnsCache }
Write-TaskStatus -TaskName "Deshabilitando aplicaciones de inicio" -Action { Disable-StartupApps }
Write-TaskStatus -TaskName "Desactivando telemetría y servicios en segundo plano" -Action { Optimize-BackgroundProcesses }
Write-TaskStatus -TaskName "Desactivando servicio de precarga (SysMain/Superfetch)" -Action { Disable-SysMain }
Write-TaskStatus -TaskName "Desactivando características de juego de Xbox" -Action { Disable-GamingFeatures }
Write-TaskStatus -TaskName "Ajustando efectos visuales para rendimiento" -Action { Disable-VisualEffects }

Write-Host "`n[Paso 4: Mantenimiento de Integridad y Discos]" -ForegroundColor Yellow
Write-TaskStatus -TaskName "Optimizando unidades de disco (TRIM/Defrag)" -Action { Optimize-Drives }
Write-TaskStatus -TaskName "Reparando archivos de sistema (SFC y DISM)" -Action { Repair-SystemFiles }

Write-Host "`n[Paso 5: Finalización e Informe]" -ForegroundColor Yellow
Get-DiskSpace

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "MANTENIMIENTO FINALIZADO CORRECTAMENTE." -ForegroundColor Green
Write-Host "=========================================="

# Detener la transcripción ANTES de preguntar por el reinicio.
Stop-Transcript
Write-Host "`nUn informe detallado de esta sesión se ha guardado en: $informePath" -ForegroundColor Cyan

Handle-SmartRestart
