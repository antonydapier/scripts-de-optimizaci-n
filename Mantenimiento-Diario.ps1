# ================================================================
# Script de Mantenimiento y Optimización de Windows 10 y Windows 11
# Autor: Antony Dapier (Versión 10.2 - Máxima Compatibilidad y Menú)
# Descripción: Versión segura que preserva los servicios críticos para
#              Notificaciones (WhatsApp), Herramienta de Recortes y Apps Modernas.
# ================================================================

# Requiere PowerShell 5.1 
#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    # Evita el reinicio automático al finalizar el script.
    [switch]$NoReiniciar,

    # Define el modo de ejecución del script.
    [Parameter(Mandatory=$false, HelpMessage="Elige 'Completo' para una optimización profunda inicial, o 'Rapido' para un mantenimiento periódico.")]
    [string]$Modo
)

# --- INICIO DE LA CONFIGURACIÓN DEL INFORME ---
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
$informePath = Join-Path -Path $desktopPath -ChildPath "Informe de Optimizacion_v10.2_($(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')).txt"
$customHeader = "Gracias por usar mi Script Enfocado a Optimizar Windows 10 y Windows 11. Antony Dapier (Versión 10.2 Segura con Menú)`n"

try {
    $customHeader | Out-File -FilePath $informePath -Encoding utf8 -ErrorAction Stop
    Start-Transcript -Path $informePath -Append -ErrorAction Stop
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
# FUNCIONES DE TAREA
# ==============================

function Confirm-IsAdmin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        $params = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$($MyInvocation.MyCommand.Path)`"")
        Start-Process powershell -ArgumentList $params -Verb RunAs
        exit
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

function Clear-RecycleBinAllDrives { Clear-RecycleBin -Force -ErrorAction SilentlyContinue }
function Clear-SoftwareDistribution {
    $wasRunning = $false
    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $wasRunning = $true
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        $service.WaitForStatus('Stopped', [System.TimeSpan]::FromSeconds(30))
    }
    $path = "C:\Windows\SoftwareDistribution\Download"
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if ($wasRunning) { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }
}
function Clear-EventLogs {
    $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue
    if (-not $logs) { return }
    foreach ($log in $logs) {
        try { wevtutil.exe cl $log.LogName 2>$null } catch {}
    }
}
function Flush-DnsCache { ipconfig /flushdns | Out-Null }
function Set-GoogleDns {
    $googleDns = "8.8.8.8", "8.8.4.4"
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.MediaType -eq '802.3' -or $_.MediaType -eq 'Native 802.11') }
    if (-not $networkAdapters) { throw "No se encontraron adaptadores de red activos (Ethernet o Wi-Fi)." }
    foreach ($adapter in $networkAdapters) {
        Write-Host "`n     -> Configurando DNS para $($adapter.Name)..." -ForegroundColor Gray
        $ipconfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
        $currentDns = $ipconfig.DNSServer.IPAddress
        if ($ipconfig.IPv4Address.IPAddress -and ($null -eq $currentDns -or -not ([System.Linq.Enumerable]::SequenceEqual($currentDns, $googleDns)))) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $googleDns -ErrorAction Stop
                Write-Host "        DNS de Google configurados." -ForegroundColor Green
            } catch {
                Write-Host "        No se pudieron configurar los DNS. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "        Ya está usando los DNS de Google o no tiene IP. Omitiendo." -ForegroundColor Gray
        }
    }
}
function Set-NetworkOptimization {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10 -Force
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10 -Force
}
function Disable-VisualEffects {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFxSetting" -Value 2 -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" -Type String -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 0 -Type DWord -Force
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
        $bloatware = @("*BingFinance*", "*BingNews*", "*BingSports*", "*BingWeather*", "*SolitaireCollection*", "*MicrosoftTeams*", "*Clipchamp*", "*Alarms*", "*Family*", "*GetHelp*", "*GetStarted*", "*Maps*", "*MediaEngine*", "*ZuneMusic*", "*ZuneVideo*", "*MixedReality*", "*YourPhone*", "*XboxApp*")
    } else {
        $bloatware = @("*3DBuilder*", "*3DViewer*", "*BingFinance*", "*BingNews*", "*BingSports*", "*BingWeather*", "*CandyCrush*", "*king.com*", "*EclipseManager*", "*Facebook*", "*HiddenCity*", "*Minecraft*", "*OneConnect*", "*OneNote*", "*Microsoft.People*", "*SkypeApp*", "*Twitter*", "*Wallet*", "*YourPhone*", "*ZuneMusic*", "*ZuneVideo*", "*XboxApp*", "*XboxGamingOverlay*", "*XboxSpeechToTextOverlay*", "*MixedReality.Portal*")
    }
    $allPackages = Get-AppxPackage -AllUsers
    $allProvisionedPackages = Get-AppxProvisionedPackage -Online
    foreach ($pattern in $bloatware) {
        $userPackages = $allPackages | Where-Object { $_.Name -like $pattern }
        if ($userPackages) { $userPackages | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
        $provisionedPackages = $allProvisionedPackages | Where-Object { $_.DisplayName -like $pattern }
        if ($provisionedPackages) { $provisionedPackages | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue }
    }
    Write-Host "     Limpieza de Bloatware completada." -ForegroundColor Green
}
function Disable-StartupApps {
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
                    try { Move-ItemProperty -Path $key -Destination $backupKey -Name $appName -Force -ErrorAction Stop } catch { Write-Warning "No se pudo deshabilitar la app de inicio '$appName'. Es posible que se requieran permisos adicionales." }
                }
            }
        }
    }
}
function Disable-GamingFeatures {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Force
}
function Set-BandwidthLimit {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
}

function Optimize-BackgroundProcesses {
    # LISTA MÁXIMA COMPATIBILIDAD: Se han ELIMINADO WpnService, WSearch, CDPUserSvc y dmwappushsvc.
    $serviciosADeshabilitar = @(
        "DiagTrack",                            # Connected User Experiences and Telemetry
        "WMPNetworkSvc",                        # Windows Media Player Network Sharing 
        "RemoteRegistry",                       # Registro Remoto
        "RetailDemo",                           # Servicio de demostración para tiendas
        "ShellHWDetection",                     # Detección de hardware de shell
        "CaptureService",                       # Servicio de captura de Game Bar
        "BcastDVRUserService",                  # Servicio de usuario de DVR de juegos
        "DPS",                                  # Servicio de directivas de diagnóstico
        "diagnosticshub.standardcollector.service", # Servicio de recolección estándar
        "MapsBroker",                           # Agente de mapas
        "Fax",                                  # Servicio de Fax
        "TabletInputService",                   # Servicio de teclado táctil
        "PhoneSvc",                             # Servicio de Teléfono
        "lfsvc"                                 # Servicio de geolocalización
    )
    foreach ($s in $serviciosADeshabilitar) {
        $servicio = Get-Service -Name "$($s)*" -ErrorAction SilentlyContinue
        if ($servicio) {
            if ($servicio.Status -ne 'Stopped') { Stop-Service -Name "$($s)*" -Force -ErrorAction SilentlyContinue }
            if ($servicio.StartType -ne 'Disabled') { Set-Service -Name "$($s)*" -StartupType Disabled -ErrorAction SilentlyContinue }
        }
    }

    # Tareas programadas de telemetría
    $tareasTelemetria = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\Speech\SpeechModelDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )
    foreach ($t in $tareasTelemetria) {
        $task = Get-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') { $task | Disable-ScheduledTask -ErrorAction SilentlyContinue }
    }
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Force
}

function Disable-WebSearch {
    # No se tocan las claves de Recortes ni Cortana.
    $regPathFeeds = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds\LockedScreen"
    if (-not (Test-Path $regPathFeeds)) { New-Item -Path $regPathFeeds -Force | Out-Null }
    Set-ItemProperty -Path $regPathFeeds -Name "LockedScreenExperienceEnabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 -Force
    $regPathLockScreen = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $regPathLockScreen -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Force
    Set-ItemProperty -Path $regPathLockScreen -Name "SubscribedContent-338387Enabled" -Value 0 -Force
}

function Disable-DeliveryOptimization {
    $regPathDO = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    if (-not (Test-Path $regPathDO)) { New-Item -Path $regPathDO -Force | Out-Null }
    Set-ItemProperty -Path $regPathDO -Name "DODownloadMode" -Value 100 -Type DWord -Force
    Set-ItemProperty -Path $regPathDO -Name "DOAllowUploads" -Value 0 -Type DWord -Force
    $regPathStore = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    if (-not (Test-Path $regPathStore)) { New-Item -Path $regPathStore -Force | Out-Null }
    Set-ItemProperty -Path $regPathStore -Name "AutoDownload" -Value 2 -Type DWord -Force
}

function Disable-Hibernation { powercfg.exe /hibernate off }
function Optimize-PowerPlan {
    $balancedGuid = "381b4222-f694-41f0-9685-ff5bb260df2e"
    powercfg /setactive $balancedGuid
    $powerSliderSettingExists = (powercfg /q $balancedGuid SUB_PowerThrottling) -match "Power Slider"
    if ($powerSliderSettingExists) {
        $powerSliderGuid = "{31f9f286-5084-42fe-b535-076635296c08}"
        $betterPerformanceValue = 1
        powercfg /setacvalueindex $balancedGuid SUB_PowerThrottling $powerSliderGuid $betterPerformanceValue | Out-Null
        powercfg /setdcvalueindex $balancedGuid SUB_PowerThrottling $powerSliderGuid $betterPerformanceValue | Out-Null
    }
}
function Disable-OneDriveIntegration {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $regPath -Name "HideFileOnDemandToolbar" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue
}
function Prioritize-ForegroundApps {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $regPath -Name "Win32PrioritySeparation" -Value 2 -Type DWord -Force
}
function Disable-8dot3Names { fsutil.exe behavior set disable8dot3 1 | Out-Null }
function Block-TelemetryHosts {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $telemetryDomains = @(
        "v10.vortex-win.data.microsoft.com", "v20.vortex-win.data.microsoft.com",
        "telemetry.microsoft.com", "watson.telemetry.microsoft.com",
        "oca.telemetry.microsoft.com", "settings-win.data.microsoft.com",
        "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
        "v10.data.microsoft.com", "v20.data.microsoft.com",
        "reports.wes.df.telemetry.microsoft.com", "df.telemetry.microsoft.com",
        "survey.watson.te"
    )
    try {
        $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop
        foreach ($domain in $telemetryDomains) {
            $entry = "127.0.0.1  $domain"
            $ipv6Entry = "::1      $domain"
            if (-not ($hostsContent -match [regex]::Escape($entry)) -and -not ($hostsContent -match [regex]::Escape($ipv6Entry))) {
                Add-Content -Path $hostsPath -Value "`r`n$entry" -ErrorAction Stop
                Add-Content -Path $hostsPath -Value "`r`n$ipv6Entry" -ErrorAction Stop
            }
        }
        Write-Host "     Dominios de Telemetría bloqueados en el archivo hosts." -ForegroundColor Green
    } catch {
        throw "No se pudo modificar el archivo hosts. Error: $($_.Exception.Message)"
    }
}

# ==============================
# EJECUCIÓN DEL SCRIPT
# ==============================

Confirm-IsAdmin

# --- LÓGICA DE MENÚ Y SELECCIÓN DE MODO ---
if (-not $Modo) {
    Write-Host "`n=================================================" -ForegroundColor Yellow
    Write-Host "     SELECCIÓN DE MODO DE EJECUCIÓN" -ForegroundColor Yellow
    Write-Host "=================================================" -ForegroundColor Yellow
    Write-Host "1) Rapido: Mantenimiento periódico (limpieza, DNS, procesos ligeros)." -ForegroundColor Green
    Write-Host "2) Completo: Optimización profunda (Rapido + Bloatware + Inicio)." -ForegroundColor Cyan
    
    $choice = Read-Host "Elija el modo (1/2) o escriba 'Completo'/'Rapido'"

    switch ($choice) {
        "1" {$Modo = "Rapido"}
        "2" {$Modo = "Completo"}
        "Rapido" {$Modo = "Rapido"}
        "Completo" {$Modo = "Completo"}
        default {
            Write-Host "Opción no válida. Se ejecutará el modo 'Rapido' por defecto." -ForegroundColor Red
            $Modo = "Rapido"
        }
    }
} else {
    $Modo = $Modo.Trim()
    if ($Modo -notmatch 'Completo|Rapido' -inotmatch 'Completo|Rapido') {
        Write-Host "El modo '$Modo' no es válido. Se ejecutará el modo 'Rapido' por defecto." -ForegroundColor Red
        $Modo = "Rapido"
    }
}
Write-Host "`nModo de ejecución seleccionado: $($Modo.ToUpper())" -ForegroundColor Yellow
Write-Host "-------------------------------------------------" -ForegroundColor Yellow
# -----------------------------------------------------------------

$tasks = @(
    @{ Name = "Limpieza de Archivos Temporales y Caché"; Action = { Clear-TemporaryFiles } },
    @{ Name = "Limpieza de Papelera de Reciclaje"; Action = { Clear-RecycleBinAllDrives } },
    @{ Name = "Limpieza de Caché de Windows Update"; Action = { Clear-SoftwareDistribution } },
    @{ Name = "Limpieza de Registros de Eventos"; Action = { Clear-EventLogs } },
    @{ Name = "Liberación de Caché DNS"; Action = { Flush-DnsCache } },
    @{ Name = "Configuración DNS de Google (Opcional)"; Action = { Set-GoogleDns } },
    @{ Name = "Optimización de Conexiones de Red"; Action = { Set-NetworkOptimization } },
    @{ Name = "Ajuste de Plan de Energía a Equilibrado/Rendimiento"; Action = { Optimize-PowerPlan } },
    @{ Name = "Optimización de Procesos en Segundo Plano (Segura)"; Action = { Optimize-BackgroundProcesses } },
    @{ Name = "Desactivación de Hibernación/Inicio Rápido"; Action = { Disable-Hibernation } },
    @{ Name = "Priorización de Aplicaciones en Primer Plano"; Action = { Prioritize-ForegroundApps } },
    @{ Name = "Desactivación de Nombres 8.3"; Action = { Disable-8dot3Names } },
    @{ Name = "Desactivación de Características de Gaming (Game Bar)"; Action = { Disable-GamingFeatures } },
    @{ Name = "Desactivación de OneDrive en el Explorador"; Action = { Disable-OneDriveIntegration } },
    @{ Name = "Desactivación de Optimización de Entrega y Store Updates"; Action = { Disable-DeliveryOptimization } },
    @{ Name = "Desactivación de Sugerencias y Anuncios (WebSearch)"; Action = { Disable-WebSearch } },
    @{ Name = "Bloqueo de Dominios de Telemetría (Hosts)"; Action = { Block-TelemetryHosts } }
)

# Ejecutar tareas (Estas son las tareas del Modo Rápido)
foreach ($task in $tasks) {
    Write-TaskStatus -TaskName $task.Name -Action $task.Action
}

# --- LÓGICA DE MODO COMPLETO ---

if ($Modo -ieq "Completo") {
    Write-Host "`n*** Ejecutando tareas adicionales de modo COMPLETO ***" -ForegroundColor Yellow
    Write-TaskStatus -TaskName "Eliminación de Bloatware (con Punto de Restauración)" -Action { Remove-Bloatware }
    Write-TaskStatus -TaskName "Desactivación de Aplicaciones de Inicio (Run Keys)" -Action { Disable-StartupApps }
}

# --- FIN DEL SCRIPT ---

Stop-Transcript
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "         OPTIMIZACIÓN COMPLETADA" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "El informe detallado se ha guardado en el Escritorio." -ForegroundColor Cyan

if (-not $NoReiniciar) {
    Write-Host "`nEl script finalizará en 10 segundos e intentará reiniciar el PC para aplicar los cambios." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "`nEl reinicio automático ha sido omitido. Por favor, reinicie manualmente." -ForegroundColor Green
}
