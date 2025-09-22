Buu👻 Hola Esto es un Trabajo de varios años,
creado por la necesidad de mantener en buen funcionamiento mis maquinas apra tarbajar,
lo más importante es el enfoque especifico para Diseñadores.
basado en mi experiencia personal y en un uso dìario en el diseño,
Lo comprato con ustedes esperando les sea de útilidad.
---
# Scripts de Optimización para Windows 10 y Windows 11 (Enfoque en Diseñadores)

Este repositorio contiene dos scripts
diseñados para mejorar el rendimiento de Windows 10 y windwos 11 cualquier versión
sin afectar **impresoras, plotters, programas de diseño como Adobe Photoshop e Illustrator, asistencia remota (AnyDesk) y sistemas de transferencia de archivos (Resilio Sync) etc.  

## **Cómo usar los scripts**  

Abre **PowerShell como administrador** y copia uno de los siguientes comando.  

### **Mantenimiento Diario**  
```
iex (iwr https://bit.ly/pc-mantenimiento-diario)
```


## **Explicación del script**  

✅ Lo que el script SÍ HACE:

Preparación Inicial

Verifica que se está ejecutando con permisos de Administrador.
Muestra una advertencia y una cuenta regresiva de 10 segundos para que el usuario pueda cancelar.
Inicia la creación de un informe de texto (.txt) en el Escritorio con todas las acciones.

Paso 1: Verificaciones

Comprueba que haya una conexión a Internet activa para asegurar que todas las tareas funcionen.

Paso 2: Limpieza Profunda del Sistema

Archivos Temporales: Elimina los archivos temporales del usuario y del sistema.
Papelera de Reciclaje: Vacía la Papelera de Reciclaje de todas las unidades.
Registros de Windows: Limpia todos los registros de eventos del sistema para liberar espacio.
Caché de Windows Update: Vacía la carpeta de descargas de Windows Update (SoftwareDistribution).

Bloatware:
Crea un punto de restauración del sistema por seguridad.
Desinstala aplicaciones preinstaladas no deseadas (la lista varía para Windows 10 y 11).

Google Chrome:
Cierra el navegador.
Activa la "Aceleración por hardware" y el "Ahorro de memoria".
Desactiva la ejecución de aplicaciones en segundo plano.
Limpia el historial y la caché.

Aplicaciones de Adobe:
Cierra los programas de Adobe (Photoshop, Premiere, etc.).
Limpia las carpetas de caché de medios (Media Cache).
Drivers Antiguos: Elimina los paquetes de controladores de dispositivos que ya no están en uso.

Paso 3: Optimización del Sistema y Red
DNS: Configura los servidores DNS de Google (8.8.8.8, 8.8.4.4) para una navegación potencialmente más rápida.
Conexiones de Red: Aumenta el número de conexiones simultáneas que Windows puede hacer a un servidor.
Ancho de Banda: Elimina el límite del 20% de ancho de banda que Windows reserva para sus propias tareas.
Caché de DNS: Limpia la caché de resolución de nombres de dominio.
Aplicaciones de Inicio: Deshabilita programas no esenciales para que no se inicien con Windows.
Telemetría: Desactiva servicios y tareas programadas de Windows que recopilan datos de uso.
SysMain (Superfetch): Deshabilita el servicio de precarga para reducir el uso del disco.
Funciones de Juego: Desactiva la Barra de Juegos de Xbox y sus servicios asociados.
Efectos Visuales: Configura la apariencia de Windows para "Mejor rendimiento", pero mantiene el suavizado de fuentes y las miniaturas de iconos para un balance ideal.

Paso 4: Mantenimiento de Integridad y Discos
Optimización de Discos:
Ejecuta TRIM en las unidades de estado sólido (SSD) para mantener su rendimiento.
Ejecuta la desfragmentación en los discos duros mecánicos (HDD).
Reparación de Archivos de Sistema:
Limpia componentes antiguos de Windows Update (DISM /StartComponentCleanup).
Escanea y repara archivos corruptos del sistema (SFC /scannow).
Repara la imagen del sistema operativo (DISM /RestoreHealth).
Paso 5: Finalización

Muestra un informe final del espacio libre en disco.
Guarda el informe detallado en el Escritorio.
Pregunta al usuario si desea reiniciar el equipo para aplicar todos los cambios.

❌ Lo que el script NO HACE (Garantías para Diseñadores):
NO desinstala tus programas de diseño:

Tu suite de Adobe Creative Cloud (Photoshop, Illustrator, Premiere, After Effects), Autodesk (AutoCAD, 3ds Max, Maya), CorelDRAW, SketchUp, Blender, etc., NO serán tocados. El script solo apunta a la lista específica de "bloatware" de Microsoft.
NO interfiere con tus periféricos profesionales:

No elimina drivers de impresoras, plotters o escáneres. La limpieza de drivers (pnputil) está diseñada para eliminar solo las versiones obsoletas y no utilizadas, sin afectar los controladores actualmente en uso.
Los drivers de tus tabletas gráficas (Wacom, Huion, Xencelabs) y otros dispositivos especializados están seguros.
NO afecta tus servicios de red, nube o acceso remoto:

Servicios como OneDrive, Dropbox, Google Drive, WeTransfer, Resilio Sync, o AnyDesk seguirán funcionando con normalidad. De hecho, la función que deshabilita apps de inicio tiene una lista de exclusiones para no tocar OneDrive y Dropbox.
NO borra tus archivos de trabajo ni datos personales:

El script NO toca las carpetas de Documentos, Imágenes, Música, Videos ni el Escritorio.
En resumen, puedes ver este script como un técnico de mantenimiento que hace una puesta a punto del "motor" de tu Windows sin reorganizar ni tocar nada de tu "taller" creativo.
---

## **Requisitos**  
- PowerShell debe estar habilitado.  
- Ejecutar como **Administrador** para un funcionamiento correcto.
- Copia u pega y ejecuta. 

🚀 **Listo! Ahora puedes optimizar y mantener tu sistema sin preocupaciones.**   

✅ ¡Así de fácil! es ejecutar los scripts con un solo comando en Powershell. 🚀😃
