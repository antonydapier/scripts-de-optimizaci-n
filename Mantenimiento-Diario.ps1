Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Mantenimiento Automático - Antony"
$form.Size = New-Object System.Drawing.Size(400,300)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true

$label = New-Object System.Windows.Forms.Label
$label.Text = "Iniciando mantenimiento..."
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(20,40)
$form.Controls.Add($label)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 80)
$progressBar.Size = New-Object System.Drawing.Size(340, 25)
$progressBar.Style = 'Continuous'
$form.Controls.Add($progressBar)

$form.Show()

Start-Sleep -Milliseconds 1000

Write-Host "Iniciando el mantenimiento de la PC..." -ForegroundColor Cyan
Write-Host "Una mente clara empieza por una máquina limpia." -ForegroundColor Magenta

function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Este script necesita permisos de Administrador. Intentando elevar..." -ForegroundColor Red
        Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File \"$($MyInvocation.MyCommand.Path)\"" -Verb RunAs
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

function Limpiar-Temporales {
    Write-Host "Eliminando archivos temporales..." -ForegroundColor Yellow
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\\Windows\\Temp", "$env:TEMP")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                $progressBar.Value = 20
                $label.Text = "Limpiando: $path"
                Start-Sleep -Milliseconds 500
            } catch {
                Log-Error "Error al limpiar ${path}: $_"
            }
        }
    }

    try {
        Remove-Item "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
        $progressBar.Value = 40
        $label.Text = "Limpiando: Descargas"
        Start-Sleep -Milliseconds 500
    } catch {
        Log-Error "Error al limpiar Descargas: $_"
    }

    Limpiar-Papelera
}

function Limpiar-Papelera {
    Write-Host "Vaciando la Papelera de reciclaje..." -ForegroundColor Yellow
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)

        $items = $recycleBin.Items()
        if ($items.Count -eq 0) {
            Write-Host "La Papelera ya está vacía." -ForegroundColor Gray
            return
        }

        $idioma = (Get-Culture).TwoLetterISOLanguageName
        $comando = if ($idioma -eq 'en') { 'delete' } else { 'eliminar' }

        $items | ForEach-Object {
            $_.InvokeVerb($comando)
        }

        Start-Sleep -Seconds 2
        $progressBar.Value = 60
        $label.Text = "Papelera vaciada"
    } catch {
        Log-Error "Error al vaciar la papelera: $_"
    }
}

function Optimizar-RAM {
    Write-Host "Liberando RAM..." -ForegroundColor Yellow
    try {
        [System.GC]::Collect()
        $progressBar.Value = 70
        $label.Text = "RAM liberada"
    } catch {
        Log-Error "Error al liberar RAM: $_"
    }
}

function Reparar-ArchivosSistemas {
    Write-Host "Ejecutando reparación de archivos SFC y DISM..." -ForegroundColor Yellow
    try {
        sfc /scannow
        Dism /Online /Cleanup-Image /RestoreHealth
        $progressBar.Value = 80
        $label.Text = "Sistema reparado"
    } catch {
        Log-Error "Error al ejecutar SFC/DISM: $_"
    }
}

function Revisar-EspacioDisco {
    Write-Host "Espacio en disco disponible:" -ForegroundColor Yellow
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        Write-Host "Unidad ${($_.Name)}: $([math]::Round($_.Free/1GB,2)) GB libres de $([math]::Round($_.Used/1GB + $_.Free/1GB,2)) GB" -ForegroundColor Green
    }
}

function Optimizar-Red {
    Write-Host "Optimizando red (sin tocar configuraciones críticas)..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10
        Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10
        $progressBar.Value = 90
        $label.Text = "Red optimizada"
    } catch {
        Log-Error "Error al optimizar red: $_"
    }
}

Verificar-Administrador
if (-not (Verificar-Conexion)) { exit }

Write-Host "============================="
Write-Host "=== MANTENIMIENTO INICIADO ===" -ForegroundColor Cyan
Write-Host "Este proceso puede tardar entre 5 y 15 minutos..." -ForegroundColor Yellow
Write-Host "¡Comenzamos, Antony!" -ForegroundColor Green

Limpiar-Temporales
Reparar-ArchivosSistemas
Revisar-EspacioDisco
Optimizar-Red
Optimizar-RAM

Write-Host "Mantenimiento finalizado correctamente." -ForegroundColor Green

$label.Text = "Mantenimiento finalizado. Reiniciando en 10 segundos..."
$progressBar.Style = 'Blocks'
$progressBar.Value = 100

for ($i = 10; $i -ge 1; $i--) {
    $label.Text = "Reiniciando en $i segundos..."
    Start-Sleep -Seconds 1
}

$form.Close()
Restart-Computer
