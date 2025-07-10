Buu👻 Hola Esto es un Trabajo de varios años,
creado por la necesidad de mantener en buen funcionamiento mis maquinas apra tarbajar,
lo más importante es el enfoque especifico para Diseñadores.
basado en mi experiencia personal y en un uso dìario en el diseño,
Lo comprato con ustedes esperando les sea de útilidad.
---
# Scripts de Optimización para Windows (Enfoque en Diseñadores)

Este repositorio contiene dos scripts
diseñados para mejorar el rendimiento de Windows 10 cualquier versión
sin afectar **impresoras, plotters, programas de diseño como Adobe Photoshop e Illustrator, asistencia remota (AnyDesk) y sistemas de transferencia de archivos (Resilio Sync)**.  

## **Cómo usar los scripts**  

Abre **PowerShell como administrador** y copia uno de los siguientes comandos según el script que quieras ejecutar.  

### **Optimización del sistema*  
```
iex (iwr https://bit.ly/optimizar-pc)
```

### **Mantenimiento Diario**  
```
iex (iwr https://bit.ly/pc-mantenimiento-diario)
```


## **Explicación de los scripts**  

### 🛠 **Optimizar-PC.ps1**  
Realiza una optimización enfocada en mejorar el rendimiento del sistema sin afectar software de diseño ni servicios esenciales.  

### **Mantenimiento-Diario.ps1**  
Resumen de Acciones del Script de Optimización
Este script está diseñado para mejorar el rendimiento general de Windows eliminando archivos innecesarios y desactivando funciones que consumen recursos en segundo plano, sin interferir con tu flujo de trabajo creativo.

✅ Lo que el script SÍ HACE:
Limpieza Profunda de Archivos Basura:

Elimina archivos temporales de Windows y de tu perfil de usuario.
Vacia la Papelera de Reciclaje de todas las unidades.
Limpia el almacén de drivers antiguos (DriverStore), liberando gigabytes de espacio ocupado por controladores de dispositivos que ya no usas (como versiones viejas de drivers de ratones, teclados, etc.).
Optimización del Sistema y Rendimiento:

Desactiva SysMain (Superfetch): Previene el uso excesivo del disco duro, un problema común que ralentiza el PC, especialmente en equipos con discos mecánicos (HDD).
Desactiva la Telemetría de Microsoft: Reduce la cantidad de datos que Windows envía a Microsoft en segundo plano, liberando CPU y ancho de banda.
Deshabilita Servicios en Segundo Plano no Esenciales: Detiene servicios como el "Registro Remoto" o el "Servicio de Fax", que la mayoría de los usuarios no necesita y consumen memoria.
Ajusta Efectos Visuales: Configura Windows para priorizar el rendimiento sobre las animaciones y transparencias de la interfaz.
Eliminación de "Bloatware" (Software Preinstalado):

Desinstala únicamente las aplicaciones preinstaladas de Microsoft que no son esenciales, como Candy Crush, 3D Viewer, Xbox Game Bar y otras apps de la Tienda Windows que vienen con el sistema.
Mantenimiento del Sistema de Archivos:

Repara Archivos de Sistema: Ejecuta las herramientas SFC /scannow y DISM para verificar y corregir la integridad de los archivos de Windows, previniendo errores y cuelgues.
Optimiza las Unidades de Disco: Ejecuta el desfragmentador en discos HDD y el comando TRIM en unidades SSD para mantener la velocidad de lectura/escritura.
Optimización de Red (Básica y Segura):

Limpia la caché de DNS para resolver posibles problemas de conexión a sitios web.
Ajusta el número de conexiones simultáneas para mejorar ligeramente la velocidad de navegación.

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
Como solicitaste, la función de borrar la carpeta de Descargas fue eliminada, por lo que tus archivos descargados están completamente a salvo.
En resumen, puedes ver este script como un técnico de mantenimiento que hace una puesta a punto del "motor" de tu Windows sin reorganizar ni tocar nada de tu "taller" creativo.

---

## **Requisitos**  
- PowerShell debe estar habilitado.  
- Ejecutar como **Administrador** para un funcionamiento correcto.  

🚀 **Listo! Ahora puedes optimizar y mantener tu sistema sin preocupaciones.**  

---

**INSTRUCCIONES:**  
1. **Copia todo este texto.**  
2. **Ve a tu repositorio en GitHub.**  
3. **Edita o crea el archivo `README.md`.**  
4. **Pega el contenido y guarda los cambios.**  

✅ ¡Así de fácil! es ejecutar los scripts con un solo comando en Powershell. 🚀😃
