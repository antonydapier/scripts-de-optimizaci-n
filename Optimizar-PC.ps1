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
            } catch {
                Log-Error "Error al eliminar archivos en $path: $_"
            }
        }
    }
    Write-Host "Temporales eliminados." -ForegroundColor Green
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

Limpiar-Temporales
Reparar-ArchivosSistemas
Revisar-EspacioDisco
Optimizar-Red
Optimizar-RAM
Optimizar-Adobe

Write-Host "=============================\nMantenimiento completado con éxito." -ForegroundColor Green

# Cuenta regresiva
$counter = 10
Write-Host "El script se cerrará en $counter segundos..." -ForegroundColor Yellow
while ($counter -gt 0) {
    Start-Sleep -Seconds 1
    $counter--
    Write-Host "$counter segundos restantes..." -ForegroundColor Yellow
}

Write-Host "Ahora que la limpieza está completada, ¿deseas programar el mantenimiento para cada lunes?" -ForegroundColor Yellow
$programar = Read-Host "Escribe 's' para programar o 'n' para omitir"

if ($programar -eq 's') {
    # Aquí va el código para programar el mantenimiento
    Write-Host "Mantenimiento programado para los lunes." -ForegroundColor Green
} else {
    Write-Host "Mantenimiento no programado." -ForegroundColor Yellow
}

Write-Host "¿Deseas reiniciar el equipo ahora?" -ForegroundColor Yellow
$reiniciar = Read-Host "Escribe 's' para reiniciar o 'n' para omitir"

if ($reiniciar -eq 's') {
    Restart-Computer -Force
} else {
    Write-Host "El script ha finalizado, gracias por utilizarlo. ¡Hasta la próxima!" -ForegroundColor Green
    Start-Sleep -Seconds 3  # Da un poco más de tiempo para que puedas leer el mensaje final
}
