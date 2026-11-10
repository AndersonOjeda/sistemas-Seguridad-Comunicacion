# Laboratorio de seguridad Nginx

Demostración de hardening HTTP y limitación de tráfico en capa 7. Incluye un panel web con pruebas reales sobre el propio servidor: GET, POST restringido y una ráfaga acotada de 40 solicitudes. No requiere backend adicional, base de datos, paquetes JavaScript ni servicios externos.

## Ejecutar en Windows

Requisitos: Docker Desktop en ejecución con contenedores Linux, Docker Compose y el puerto 80 libre.

Desde PowerShell, en la carpeta que contiene `docker-compose.yml`:

```powershell
cd 'C:\Users\isamu\Desktop\seguridad\sistemas-Seguridad-Comunicacion'
docker compose up -d
docker compose ps
```

Abrir **http://localhost**. La primera ejecución descarga las imágenes. Si el laboratorio ya estaba encendido, recargar con **Ctrl + F5** para ver el nuevo panel. Los archivos de `html/` se montan directamente; no es necesario construir imágenes ni instalar dependencias. Abrir `index.html` como archivo no ejecuta las pruebas de Nginx.

## Demostración en unos 5 minutos

1. Mostrar el diagrama: el navegador envía HTTP y Nginx decide si permite la solicitud. Explicar que el trabajo principal está en `nginx.conf`; el panel permite observarlo.
2. Pulsar **Probar consulta GET**. Mostrar `200 OK` y bajar a las cabeceras recibidas: `Server: nginx` sin versión, restricciones de marcos, tipos de contenido y recursos permitidos.
3. Pulsar **Probar bloqueo de POST**. Mostrar `403 Forbidden`: en esta ruta solo están permitidos GET y HEAD. Se envía un POST vacío, sin cambiar datos.
4. Pulsar **Enviar ráfaga de 40**. Mostrar la proporción real de respuestas 200/503, el registro de solicitudes y la página de rechazo devuelta por Nginx. Explicar `rate=5r/s`, `burst=10` y `nodelay`: tolera un pico breve, luego rechaza el exceso sin introducir una cola de espera.
5. Aclarar que un 503 aquí es un rechazo del laboratorio. Confirmar su causa en los registros si se necesita distinguir límite de peticiones de límite de conexiones. Las cantidades y los tiempos pueden variar entre ejecuciones.

El panel espera tres segundos entre pruebas para permitir que se recupere el límite. Las pestañas y usuarios que Nginx vea con la misma IP comparten la cuota. Los navegadores regulan sus conexiones: si una ráfaga no produce 503, revisar el ritmo observado y usar Apache Benchmark como prueba complementaria.

## Comandos complementarios

```powershell
# Validar la configuración y consultar rechazos recientes
docker exec servidor-defensa nginx -t
docker logs --tail 30 servidor-defensa

# Prueba de carga desde el cliente del laboratorio (opcional)
docker exec cliente-atacante apk add --no-cache apache2-utils curl
docker exec cliente-atacante ab -n 1000 -c 50 http://172.28.0.10/

# Detener y retirar los contenedores del laboratorio
docker compose down
```

`apache2-utils` se instala de nuevo si se recrea el contenedor cliente. Los resultados de `ab` incluyen respuestas de rechazo: `Non-2xx responses` no significa por sí solo que el servidor se haya caído.

## Archivos y alcance

- `nginx.conf`: cabeceras, métodos, tasa de 5 peticiones/s por IP con ráfaga de 10, límite de conexiones y tiempos de espera.
- `docker-compose.yml`: servidor, cliente y red del laboratorio; servidor limitado a 128 MB y 0.50 CPU.
- `html/index.html`, `html/panel.css`, `html/panel.js`: panel sin dependencias; consulta el mismo origen, sin destinos configurables. Muestra respuestas reales, no telemetría global ni resultados simulados. El script externo respeta la CSP existente.
- `html/custom_503.html`: respuesta de rechazo compartida por los límites configurados.
- `INFORME_Y_GUIA_DE_SUSTENTACION.md` y `.pdf`: informe académico original. Sus cifras de una ejecución previa no son valores garantizados; la ruta de arranque antigua debe sustituirse por la de tu equipo. La página 503 se ha actualizado, por lo que su tamaño también cambió.

La demostración cubre controles HTTP locales y las medidas documentadas con la referencia OWASP A05:2021. La prueba del navegador no valida resistencia a DDoS volumétrico, Slowloris, uso de CPU/RAM ni todos los riesgos de OWASP. El laboratorio usa HTTP sin TLS. El puerto `80:80` se publica en las interfaces del equipo; la red bridge separa los contenedores, pero el sitio no queda limitado a localhost.
