# Verificar la versión de Windows
function Obtener-VersionWindows {
    $osVersion = [System.Environment]::OSVersion.Version
    return $osVersion.Major
}

# Limpiar archivos temporales y de la Papelera
function Limpiar-TempYDescargas {
    Write-Host "=============================\nLimpiando archivos temporales, Papelera y Descargas..." -ForegroundColor Yellow

    # Limpiar archivos temporales
    $tempPaths = @("$env:LOCALAPPDATA\Temp", "C:\Windows\Temp", "$env:TEMP")
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                Write-Host "Eliminando archivos en $path..." -ForegroundColor Cyan
                Remove-Item "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Archivos eliminados en $path." -ForegroundColor Green
            } catch {
                Log-Error "Error al eliminar archivos en $path: $_"
            }
        } else {
            Write-Host "No se encontró la carpeta: $path" -ForegroundColor Red
        }
    }

    # Limpiar la Papelera de reciclaje (compatibilidad con versiones anteriores)
    try {
        Write-Host "Limpiando la Papelera de reciclaje..." -ForegroundColor Cyan
        if ((Obtener-VersionWindows) -ge 10) {
            # En Windows 10 y 11 utilizamos el método COM
            $shell = New-Object -ComObject Shell.Application
            $recycleBin = $shell.NameSpace(0x0A)  # Código para la Papelera de reciclaje
            $recycleBin.Items() | ForEach-Object { $recycleBin.InvokeVerb("Eliminar", $_) }
        } else {
            # En versiones anteriores utilizamos el comando CMD
            Start-Process cmd.exe -ArgumentList "/c rd /s /q C:\$Recycle.Bin" -NoNewWindow -Wait
        }
        Write-Host "Papelera de reciclaje vacía." -ForegroundColor Green
    } catch {
        Log-Error "Error al limpiar la Papelera de reciclaje: $_"
    }
}

# Limpiar caché de navegadores
function Limpiar-CachéNavegadores {
    Write-Host "=============================\nLimpiando caché de navegadores..." -ForegroundColor Yellow

    # Chrome
    $chromeCachePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    if (Test-Path $chromeCachePath) {
        try {
            Remove-Item "$chromeCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Caché de Chrome eliminada." -ForegroundColor Green
        } catch {
            Log-Error "Error al limpiar caché de Chrome: $_"
        }
    }

    # Firefox
    $firefoxCachePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxCachePath) {
        try {
            $firefoxProfiles = Get-ChildItem -Path $firefoxCachePath -Directory
            foreach ($profile in $firefoxProfiles) {
                $profileCachePath = "$profile\AppData\Local\Mozilla\Firefox\Profiles\$($profile.Name)\cache2"
                Remove-Item "$profileCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Caché de Firefox eliminada." -ForegroundColor Green
        } catch {
            Log-Error "Error al limpiar caché de Firefox: $_"
        }
    }

    # Edge
    $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    if (Test-Path $edgeCachePath) {
        try {
            Remove-Item "$edgeCachePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Caché de Edge eliminada." -ForegroundColor Green
        } catch {
            Log-Error "Error al limpiar caché de Edge: $_"
        }
    }
}

# Limpiar carpeta de Descargas
function Limpiar-Descargas {
    Write-Host "=============================\nLimpiando carpeta de Descargas..." -ForegroundColor Yellow
    $descargasPath = [System.Environment]::GetFolderPath('UserProfile') + "\Downloads"
    if (Test-Path $descargasPath) {
        try {
            Remove-Item "$descargasPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Archivos eliminados en la carpeta de Descargas." -ForegroundColor Green
        } catch {
            Log-Error "Error al eliminar archivos en la carpeta de Descargas: $_"
        }
    } else {
        Write-Host "No se encontró la carpeta de Descargas." -ForegroundColor Red
    }
}

# Ejecución de funciones
Limpiar-TempYDescargas
Limpiar-CachéNavegadores
Limpiar-Descargas
