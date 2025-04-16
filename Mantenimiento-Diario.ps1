Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Crear la interfaz gráfica
$form = New-Object System.Windows.Forms.Form
$form.Text = "Mantenimiento Automático - Antony"
$form.Size = New-Object System.Drawing.Size(450, 350)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = 'FixedDialog'
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

# Etiqueta para mostrar el estado actual
$label = New-Object System.Windows.Forms.Label
$label.Text = "Iniciando mantenimiento..."
$label.ForeColor = [System.Drawing.Color]::White
$label.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(20, 40)
$form.Controls.Add($label)

# Barra de progreso
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 100)
$progressBar.Size = New-Object System.Drawing.Size(400, 25)
$progressBar.Style = 'Continuous'
$form.Controls.Add($progressBar)

# Ocultar la ventana de PowerShell
$console = Get-Host
$console.UI.RawUI.WindowTitle = "Mantenimiento Automático"
$console.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(1, 1)

# Función para actualizar el progreso
function Update-Progress {
    param ($currentTask, $progress)
    $label.Text = $currentTask
    $progressBar.Value = $progress
    $form.Refresh()
}

# Función para verificar si se ejecuta como administrador
function Verificar-Administrador {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Start-Process powershell "-NoProfile -ExecutionPolicy Bypass -File `\"$($MyInvocation.MyCommand.Path)`\"" -Verb RunAs
        exit
    }
}

# Función para limpiar archivos temporales
function Limpiar-Temporales {
    Update-Progress "Limpiando archivos temporales..." 20
    $paths = @("$env:LOCALAPPDATA\Temp", "C:\\Windows\\Temp", "$env:TEMP")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Update-Progress "Limpiando Descargas..." 40
    Remove-Item "$env:USERPROFILE\Downloads\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# Función para vaciar la papelera
function Limpiar-Papelera {
    Update-Progress "Vaciando la Papelera de reciclaje..." 60
    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(0xA)
        $items = $recycleBin.Items()
        $items | ForEach-Object { $_.InvokeVerb('eliminar') }
    } catch {
        Write-Host "Error al vaciar la papelera: $_"
    }
}

# Función para liberar RAM
function Optimizar-RAM {
    Update-Progress "Liberando RAM..." 70
    [System.GC]::Collect()
}

# Función para reparar archivos del sistema
function Reparar-ArchivosSistemas {
    Update-Progress "Reparando archivos del sistema..." 80
    sfc /scannow
    Dism /Online /Cleanup-Image /RestoreHealth
}

# Función para optimizar la red
function Optimizar-Red {
    Update-Progress "Optimizando red..." 90
    $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPerServer" -Value 10
    Set-ItemProperty -Path $regPath -Name "MaxConnectionsPer1_0Server" -Value 10
}

# Ejecutar todas las funciones
Verificar-Administrador
Limpiar-Temporales
Limpiar-Papelera
Optimizar-RAM
Reparar-ArchivosSistemas
Optimizar-Red

# Finalizar
Update-Progress "Mantenimiento completado, reiniciando..." 100
Start-Sleep -Seconds 2
$form.Close()

Restart-Computer
