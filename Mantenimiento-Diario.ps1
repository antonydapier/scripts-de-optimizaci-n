# ================================================================
# Script de Mantenimiento y Optimización de Windows
# Autor: Antony Dapier
# Propósito: Mantener la PC rápida, limpia y sin procesos innecesarios
# ================================================================

Write-Host "`nIniciando el mantenimiento de la PC..." -ForegroundColor Cyan
Write-Host "Una mente clara empieza por una máquina limpia." -ForegroundColor Magenta

# ==============================
# FUNCIONES BÁSICAS
# ==============================

function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
        exit
    }
}

function Verificar-Conexion {
    Write-Host "Verificando conexión a Internet..." -ForegroundColor Yellow
    if (-not (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet)) {
        Write-Host "No hay conexión. Algunas funciones pueden fallar." -ForegroundColor Red
        return $false
    }
    return $true
}

function Log-Error {
    param ([string]$message)
    $logPath = "$env:USERPROFILE\MantenimientoErrorLog.txt"
    Add-Content -Path $logPath -Value "$(Get-Date): ERROR: ${message}"
    Write-Host "Error registrado: ${message}" -ForegroundColor Red
}

# ==============================
# LIMPIEZA DEL SISTEMA
# ==============================

function Limpiar-Temporales {
    Write-Host "`nEliminando archivos temporales..." -ForegroundColor Yellow
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\Windows\Temp", "$env:TEMP")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Limpiado: ${path}" -ForegroundColor Green
            } catch {
                Log-Error "Error al limpiar ${path}: $_"
            }
        }
    }

    try {
        Remove-Item "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Descargas limpiadas." -ForegroundColor Green
    } catch {
        Log-Error "Error al limpiar Descargas: $_"
    }

    Limpiar-Papelera
}

function Limpiar-Papelera {
    Write-Host "`nVaciando la Papelera de reciclaje..." -ForegroundColor Yellow
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)
        $items = $recycleBin.Items()

        if ($items.Count -eq 0) {
            Write-Host "La Papelera ya está vacía." -ForegroundColor Gray
            return
        }

        for ($i = $items.Count - 1; $i -ge 0; $i--) {
            try {
                Remove-Item -Path $items.Item($i).Path -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }

        Write-Host "Papelera vaciada correctamente." -ForegroundColor Green
    } catch {
        Log-Error "Error al vaciar la papelera: $_"
    }
}

# ==============================
# OPTIMIZACIÓN DEL SISTEMA
# ==============================

function Optimizar-RAM {
    Write-Host "`nLiberando RAM..." -ForegroundColor Yellow
    try {
        [System.GC]::Collect()
        Write-Host "RAM liberada." -ForegroundColor Green
    } catch {
        Log-Error "Error al liberar RAM: $_"
    }
}

function Reparar-ArchivosSistemas {
    Write-Host "`nEjecutando reparación de archivos SFC y DISM..." -ForegroundColor Yellow
    try {
        sfc /scannow
        Dism /Online /Cleanup-Image /RestoreHealth
        Write-Host "Sistema reparado." -ForegroundColor Green
    } catch {
        Log-Error "Error al ejecutar SFC/DISM: $_"
    }
}

function Revisar-EspacioDisco {
    Write-Host "`nEspacio en disco disponible:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "Unidad ${($_.Name)}: $([math]::Round($_.Free/1GB,2)) GB libres de $([math]::Round($_.Used/1GB + $_.Free/1GB,2)) GB" -ForegroundColor Green
    }
}

function Optimizar-Red {
    Write-Host "`nOptimizando red..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10
        Write-Host "Red optimizada." -ForegroundColor Green
    } catch {
        Log-Error "Error al optimizar red: $_"
    }
}

# ==============================
# BLOQUEO DE TELEMETRÍA
# ==============================

function Eliminar-Telemetria {
    Write-Host "`n🔒 Eliminando procesos y servicios de telemetría..." -ForegroundColor Yellow

    $serviciosTelemetria = @(
        "DiagTrack", "dmwappushsvc", "WMPNetworkSvc", 
        "RemoteRegistry", "RetailDemo", "diagnosticshub.standardcollector.service"
    )

    foreach ($s in $serviciosTelemetria) {
        try {
            Stop-Service -Name $s -ErrorAction SilentlyContinue
            Set-Service -Name $s -StartupType Disabled
            Write-Host "Desactivado servicio: $s" -ForegroundColor Gray
        } catch {
            Log-Error "Error al desactivar servicio $s: $_"
        }
    }

    $tareasTelemetria = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Maintenance\WinSAT",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    foreach ($t in $tareasTelemetria) {
        try {
            Disable-ScheduledTask -TaskPath $t -ErrorAction SilentlyContinue
            Write-Host "Tarea desactivada: $t" -ForegroundColor DarkGray
        } catch {
            Log-Error "Error al desactivar tarea $t: $_"
        }
    }

    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
        Write-Host "Telemetría bloqueada desde el registro." -ForegroundColor Green
    } catch {
        Log-Error "Error al modificar el registro de telemetría: $_"
    }

    Write-Host "Procesos de telemetría eliminados con éxito." -ForegroundColor Green
}

# ==============================
# EJECUCIÓN PRINCIPAL
# ==============================

Verificar-Administrador
if (-not (Verificar-Conexion)) { exit }

Write-Host "`n============================="
Write-Host "=== MANTENIMIENTO INICIADO ===" -ForegroundColor Cyan
Write-Host "Este proceso puede tardar entre 5 y 15 minutos..." -ForegroundColor Yellow
Write-Host "¡Comenzamos, Antony!" -ForegroundColor Green

Limpiar-Temporales
Reparar-ArchivosSistemas
Revisar-EspacioDisco
Optimizar-Red
Optimizar-RAM
Eliminar-Telemetria

Write-Host "`n✅ Mantenimiento finalizado correctamente." -ForegroundColor Green

# ==============================
# REINICIO AUTOMÁTICO EN 20 SEGUNDOS
# ==============================

for ($i = 20; $i -ge 1; $i--) {
    Write-Host "Reiniciando en $i segundos..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
}

Restart-Computer
