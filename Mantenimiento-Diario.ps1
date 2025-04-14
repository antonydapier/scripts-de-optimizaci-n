# -------------- 6. FINALIZAR --------------
Write-Host "Mantenimiento completado. ¡Tu PC está lista para trabajar esta semana!" -ForegroundColor Cyan
Write-Host "❗ Recuerda que el proceso puede tardar entre 5 y 15 minutos. No cierres la ventana hasta que termine." -ForegroundColor Yellow

# Preguntar si desea programar la limpieza
$programar = Read-Host "¿Te gustaría programar esta limpieza para que se ejecute automáticamente cada lunes al iniciar? (S/N)"
if ($programar -eq "S" -or $programar -eq "s") {
    $Trigger = New-ScheduledTaskTrigger -AtStartup -DaysOfWeek Monday
    $Accion = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\ruta\a\tu\script\pc-mantenimiento-diario.ps1"
    Register-ScheduledTask -Action $Accion -Trigger $Trigger -TaskName "Mantenimiento Diario de PC" -Description "Script de mantenimiento automático para optimizar y limpiar tu PC semanalmente." -Force
    Write-Host "Mantenimiento automático programado correctamente para ejecutarse cada lunes al iniciar." -ForegroundColor Green
} else {
    Write-Host "No se programó la limpieza automática. Puedes ejecutar el script manualmente cuando lo desees." -ForegroundColor Yellow
}

# Preguntar si desea reiniciar la PC ahora
$reiniciar = Read-Host "¿Te gustaría reiniciar tu PC ahora para aplicar los cambios? (S/N)"
if ($reiniciar -eq "S" -or $reiniciar -eq "s") {
    Write-Host "Reiniciando la PC..." -ForegroundColor Yellow
    Restart-Computer -Force
} else {
    Write-Host "Recuerda reiniciar tu PC más tarde para asegurarte de que todos los cambios se apliquen correctamente." -ForegroundColor Yellow
    Write-Host "PowerShell se cerrará en 5 segundos..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Exit
}

# Si el usuario no eligió reiniciar, esperar 10 segundos y reiniciar automáticamente
Write-Host "Reiniciando automáticamente en 10 segundos..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer -Force
