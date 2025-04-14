Write-Host "Iniciando la optimización de la PC..." -ForegroundColor Cyan

function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita ejecutarse como Administrador. Intentando elevar permisos..." -ForegroundColor Red
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `\"$scriptPath`\"" -Verb RunAs
        exit
    }
}

function Verificar-Conexion {
    Write-Host "Verificando conexión a Internet..." -ForegroundColor Yellow
    if (-not (Test-Connection -ComputerName cloudflare.com -Count 1 -Quiet)) {
        Write-Host "No hay conexión a Internet. Algunas acciones podrían no funcionar." -ForegroundColor Red
        return $false
    }
    return $true
}

function Log-Error {
    param ([string]$message)
    $logPath = "$env:USERPROFILE\MantenimientoErrorLog.txt"
    Add-Content -Path $logPath -Value "$(Get-Date): ERROR: $message"
    Write-Host "Error registrado: $message" -ForegroundColor Red
}

function Limpiar-Temporales {
    Write-Host "=============================\nEliminando archivos temporales..." -ForegroundColor Yellow
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\\Windows\\Temp", "$env:TEMP")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Archivos temporales eliminados en $path." -ForegroundColor Green
            } catch {
                Log-Error "Error al eliminar archivos en $path: $_"
            }
        }
    }
}

function Optimizar-RAM {
    Write-Host "=============================\nLiberando RAM..." -ForegroundColor Yellow
    try {
        [System.GC]::Collect()
        Write-Host "RAM optimizada." -ForegroundColor Green
    } catch {
        Log-Error "Error al liberar la RAM: $_"
    }
}

function Reparar-ArchivosSistemas {
    Write-Host "=============================\nEjecutando SFC..." -ForegroundColor Yellow
    try {
        sfc /scannow
        Write-Host "SFC finalizado." -ForegroundColor Green
    } catch {
        Log-Error "Error al ejecutar SFC: $_"
    }

    Write-Host "=============================\nEjecutando DISM..." -ForegroundColor Yellow
    try {
        Dism /Online /Cleanup-Image /RestoreHealth
        Write-Host "DISM finalizado." -ForegroundColor Green
    } catch {
        Log-Error "Error al ejecutar DISM: $_"
    }
}

function Revisar-EspacioDisco {
    Write-Host "=============================\nRevisando espacio en disco..." -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "Disco $($_.Name): $([math]::Round($_.Used/1GB,2)) GB usados de $([math]::Round(($_.Used + $_.Free)/1GB,2)) GB." -ForegroundColor Green
    }
}

function Optimizar-Red {
    Write-Host "=============================\nOptimizando red..." -ForegroundColor Yellow
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    try {
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10
        Write-Host "Red optimizada." -ForegroundColor Green
    } catch {
        Log-Error "Error al optimizar la red: $_"
    }
}

function Optimizar-Adobe {
    Write-Host "=============================\nOptimizando programas de Adobe..." -ForegroundColor Yellow
    $confirm = Read-Host "¿Deseas cerrar los programas de Adobe para limpiar la caché? (s/n)"
    if ($confirm -eq 's') {
        $apps = @("Photoshop", "Illustrator", "InDesign")
        foreach ($app in $apps) {
            $proceso = Get-Process -Name $app -ErrorAction SilentlyContinue
            if ($proceso) {
                Stop-Process -Name $app -Force
            }
        }
        $adobeCachePath = "$env:APPDATA\Adobe"
        if (Test-Path $adobeCachePath) {
            try {
                Remove-Item "$adobeCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Caché de Adobe limpiada." -ForegroundColor Green
            } catch {
                Log-Error "Error al limpiar caché de Adobe: $_"
            }
        }
    } else {
        Write-Host "Se omitió la limpieza de caché de Adobe." -ForegroundColor Yellow
    }
}

Verificar-Administrador
if (-not (Verificar-Conexion)) { exit }

Write-Host "=============================\n=== MANTENIMIENTO DE WINDOWS PARA DISEÑADORES ===" -ForegroundColor Cyan
Write-Host "Este proceso puede tardar entre 5 y 15 minutos." -ForegroundColor Yellow
Write-Host "¡Comenzamos!" -ForegroundColor Green

# Ejecución de las funciones de mantenimiento
Limpiar-Temporales
Reparar-ArchivosSistemas
Revisar-EspacioDisco
Optimizar-Red
Optimizar-RAM
Optimizar-Adobe

Write-Host "=============================\nMantenimiento completado con éxito." -ForegroundColor Green

# Espera de 10 segundos antes de continuar
for ($i = 10; $i -gt 0; $i--) {
    Write-Host "El script se cerrará en $i segundos..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

# Preguntar si desea programar el script para la próxima ejecución
$programar = Read-Host "¿Quieres programar este mantenimiento para ejecutarse cada lunes? (s/n)"
if ($programar -eq 's') {
    $fecha = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")
    $hora = Read-Host "¿A qué hora deseas programarlo? (HH:mm)"
    $programarCommand = "powershell.exe -File `"$scriptPath`""
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At $hora
    Register-ScheduledTask -Action $taskAction -Trigger $taskTrigger -TaskName "MantenimientoPC" -Description "Mantenimiento semanal para optimizar PC"
    Write-Host "Mantenimiento programado para el lunes a las $hora." -ForegroundColor Green
}

# Preguntar si desea reiniciar el equipo
$reiniciar = Read-Host "¿Quieres reiniciar el sistema ahora? (s/n)"
if ($reiniciar -eq 's') {
    Write-Host "Reiniciando el sistema..." -ForegroundColor Cyan
    Restart-Computer
} else {
    Write-Host "No se realizará el reinicio." -ForegroundColor Yellow
}

Read-Host -Prompt "Presiona ENTER para salir"
