Write-Host "`n🛠 Iniciando el mantenimiento de la PC de diseño..." -ForegroundColor Cyan

# ==============================
# FUNCIONES
# ==============================

function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "⚠️ Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
        exit
    }
}

function Verificar-Conexion {
    Write-Host "🌐 Verificando conexión a Internet..." -ForegroundColor Yellow
    if (-not (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet)) {
        Write-Host "❌ No hay conexión. Algunas funciones pueden fallar." -ForegroundColor Red
        return $false
    }
    return $true
}

function Log-Error {
    param ([string]$message)
    $logPath = "$env:USERPROFILE\MantenimientoErrorLog.txt"
    Add-Content -Path $logPath -Value "$(Get-Date): ERROR: ${message}"
    Write-Host "⚠️ Error registrado: ${message}" -ForegroundColor Red
}

function Limpiar-Temporales {
    Write-Host "`n🧹 Eliminando archivos temporales..." -ForegroundColor Yellow
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\Windows\Temp", "$env:TEMP")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "✔️ Limpiado: ${path}" -ForegroundColor Green
            } catch {
                Log-Error "Error al limpiar ${path}: $_"
            }
        }
    }

    $limpiarDescargas = Read-Host "¿Deseas limpiar la carpeta Descargas también? (s/n)"
    if ($limpiarDescargas -eq "s") {
        try {
            Remove-Item "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "✔️ Descargas limpiadas." -ForegroundColor Green
        } catch {
            Log-Error "Error al limpiar Descargas: $_"
        }
    }

    $limpiarPapelera = Read-Host "¿Deseas vaciar la Papelera de reciclaje? (s/n)"
    if ($limpiarPapelera -eq "s") {
        try {
            Clear-RecycleBin -Force
            Write-Host "🗑 Papelera vaciada." -ForegroundColor Green
        } catch {
            Log-Error "Error al vaciar la papelera: $_"
        }
    }
}

function Optimizar-RAM {
    Write-Host "`n💾 Liberando RAM..." -ForegroundColor Yellow
    try {
        [System.GC]::Collect()
        Write-Host "✔️ RAM liberada." -ForegroundColor Green
    } catch {
        Log-Error "Error al liberar RAM: $_"
    }
}

function Reparar-ArchivosSistemas {
    Write-Host "`n🩺 Ejecutando reparación de archivos SFC y DISM..." -ForegroundColor Yellow
    try {
        sfc /scannow
        Dism /Online /Cleanup-Image /RestoreHealth
        Write-Host "✔️ Sistema reparado." -ForegroundColor Green
    } catch {
        Log-Error "Error al ejecutar SFC/DISM: $_"
    }
}

function Revisar-EspacioDisco {
    Write-Host "`n💽 Espacio en disco disponible:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "🗂 Unidad ${($_.Name)}: $([math]::Round($_.Free/1GB,2)) GB libres de $([math]::Round($_.Used/1GB + $_.Free/1GB,2)) GB" -ForegroundColor Green
    }
}

function Optimizar-Red {
    Write-Host "`n🌐 Optimizando red (sin tocar configuraciones críticas)..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10
        Write-Host "✔️ Red optimizada." -ForegroundColor Green
    } catch {
        Log-Error "Error al optimizar red: $_"
    }
}

function Optimizar-Adobe {
    Write-Host "`n🎨 Optimizando Adobe (Photoshop, Illustrator, etc)..." -ForegroundColor Yellow
    $confirm = Read-Host "¿Cerrar programas Adobe para limpiar caché? (s/n)"
    if ($confirm -eq 's') {
        $apps = @("Photoshop", "Illustrator", "InDesign", "AfterFX")
        foreach ($app in $apps) {
            Stop-Process -Name $app -Force -ErrorAction SilentlyContinue
        }
        try {
            Remove-Item "$env:APPDATA\Adobe\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "✔️ Caché de Adobe eliminada." -ForegroundColor Green
        } catch {
            Log-Error "Error al limpiar Adobe: $_"
        }
    } else {
        Write-Host "⏭ Se omitió limpieza de Adobe." -ForegroundColor Yellow
    }
}

# ==============================
# EJECUCIÓN DEL MANTENIMIENTO
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
Optimizar-Adobe

Write-Host "`n✅ Mantenimiento finalizado correctamente." -ForegroundColor Green

# ==============================
# PROGRAMAR EJECUCIÓN AUTOMÁTICA
# ==============================

$programar = Read-Host "¿Deseas programar este mantenimiento para cada lunes? (s/n)"
if ($programar -eq 's') {
    try {
        $hora = Read-Host "¿A qué hora quieres programarlo? (ej. 09:00)"
        $scriptPath = $MyInvocation.MyCommand.Path
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" 
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At (Get-Date "01/01/2000 $hora")
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MantenimientoPC" -Description "Mantenimiento semanal" -Force
        Write-Host "🗓 Script programado para cada lunes a las $hora." -ForegroundColor Green
    } catch {
        Log-Error "Error al programar la tarea: $_"
    }
}

# ==============================
# OPCIÓN DE REINICIO
# ==============================

$reiniciar = Read-Host "¿Deseas reiniciar el sistema ahora? (s/n)"
if ($reiniciar -eq 's') {
    Write-Host "🔄 Reiniciando..." -ForegroundColor Cyan
    Restart-Computer
} else {
    Write-Host "✅ Sin reinicio. ¡Listo para seguir diseñando!" -ForegroundColor Green
}

Read-Host -Prompt "Presiona ENTER para cerrar"
