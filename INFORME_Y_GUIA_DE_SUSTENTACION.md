# PROYECTO FINAL: BASTIONADO INTEGRAL (HARDENING) Y DEFENSA ACTIVA EN CAPA 7 DE SERVIDORES NGINX CON DOCKER
## Mitigación de Vulnerabilidades OWASP A05:2021 y Ataques DoS (HTTP Flood)

**Asignatura:** Sistemas de Comunicación y Seguridad Informática  
**Nivel Académico:** 8vo Semestre — Ingeniería de Sistemas / Telecomunicaciones / Informática  
**Integración Curricular:** Semanas 5 (Hardening & OWASP) y 10 (Defensa en Redes & Control DoS/DDoS)  
**Equipo de Trabajo:** 3 Integrantes (Roles: 3 Expositores e Ingenieros de Seguridad)  

---

## ÍNDICE GENERAL
1. [Resumen Ejecutivo (Abstract)](#1-resumen-ejecutivo-abstract)
2. [Fase 1: Contextualización y Escenario de Amenaza](#2-fase-1-contextualización-y-escenario-de-amenaza)
3. [Fase 2: Fundamentación Teórica](#3-fase-2-fundamentación-teórica)
   - 3.1 OWASP Top 10: A05:2021 (Security Misconfiguration)
   - 3.2 Defensa Activa y Preservación de la Disponibilidad (Tríada CIA)
   - 3.3 Modelo Matemático y Algoritmo de Rate Limiting (Leaky Bucket)
4. [Fase 3: Arquitectura y Topología del Laboratorio](#4-fase-3-arquitectura-y-topología-del-laboratorio)
5. [Fase 4: Implementación Técnica del Stack](#5-fase-4-implementación-técnica-del-stack)
   - 5.1 Configuración Definitiva de Nginx (`nginx.conf`)
   - 5.2 Orquestación con Docker Compose y Docker CLI
   - 5.3 Procedimiento de Ejecución Paso a Paso
6. [Fase 5: Análisis Forense y Validación de Resultados](#6-fase-5-análisis-forense-y-validación-de-resultados)
   - 6.1 Auditoría Perimetral de Cabeceras con `curl.exe`
   - 6.2 Desglose Matemático del Ataque DoS (`ab`): ¿Por qué 31 OK y 969 Bloqueadas?
   - 6.3 Comparativa Forense: Falla de Servidor vs. Rechazo Activo Fail-Fast
7. [Diseño Estructurado de 10 Diapositivas para la Exposición](#7-diseño-estructurado-de-10-diapositivas-para-la-exposición)
8. [Guion de Sustentación Formal para los 3 Integrantes](#8-guion-de-sustentación-formal-para-los-3-integrantes)
9. [Manual Rápido de Comandos para Demostración en Vivo (Cheat Sheet)](#9-manual-rápido-de-comandos-para-demostración-en-vivo-cheat-sheet)
10. [Banco de Preguntas Avanzadas de Sustentación con Respuestas](#10-banco-de-preguntas-avanzadas-de-sustentación-con-respuestas)

---

## 1. RESUMEN EJECUTIVO (ABSTRACT)

El presente proyecto implementa y valida un esquema integral de **Bastionado (Hardening)** y **Defensa Activa en Capa 7 (Capa de Aplicación del Modelo OSI)** sobre un servidor web Nginx desplegado en un entorno aislado de contenedores mediante Docker. 

La solución neutraliza dos vectores de amenaza primarios:
1. **Exposición de Metadatos y Vulnerabilidades del Cliente (OWASP A05:2021 - Security Misconfiguration):** Se suprime el banner del software y su versión mediante directivas nativas del motor HTTP, se restringen los métodos HTTP permitidos (`GET`/`HEAD`) y se inyectan cabeceras de respuesta de seguridad obligatorias (`X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `X-XSS-Protection: 0`, `Referrer-Policy`, `Permissions-Policy`) para mitigar ataques de **Clickjacking (UI Redressing)**, **XSS** y **MIME-Sniffing (Type Confusion)**.
2. **Denegación de Servicio en Capa de Aplicación (Capa 7 HTTP Flood y Slowloris):** Mediante los módulos nativos `ngx_http_limit_req_module` y `ngx_http_limit_conn_module`, se implementan zonas de memoria compartida (Shared Memory Zones) con control de estado por IP binaria (`$binary_remote_addr`): el algoritmo **Leaky Bucket** a $5\text{ peticiones/segundo}$ con ráfaga de 10 slots (`burst=10 nodelay`), un límite de **20 conexiones TCP concurrentes por IP** y timeouts estrictos anti-Slowloris (`10s`).

La efectividad del sistema es auditada con herramientas de inspección HTTP (`curl`) y evaluada bajo condiciones de estrés mediante **Apache Benchmark (`ab`)**, inyectando una carga concurrente de 1000 solicitudes sobre 50 hilos simultáneos. En la prueba verificada en el laboratorio Dockerizado, el servidor procesa las 1000 peticiones en **4.100 segundos**, admitiendo exactamente **31 peticiones legítimas** (`200 OK`) acordes al drenaje continuo del balde durante esa ventana y bloqueando de manera activa **969 peticiones excedentes** (`96.9%`) con código `503 Service Unavailable` (`custom_503.html` de 749 bytes), además de rechazar métodos no permitidos (`POST` -> `403 Forbidden`), manteniendo el contenedor estable bajo un límite estricto de 128 MB de RAM y 0.50 CPU.

---

## 2. FASE 1: CONTEXTUALIZACIÓN Y ESCENARIO DE AMENAZA

En el ecosistema tecnológico actual, el servidor web y proxy inverso opera como la cara perimetral frontal de las organizaciones. A diferencia de los componentes internos de base de datos o lógica de negocio, se encuentra expuesto sin intermediación a internet público.

```
+-----------------------------------------------------------------------------------------+
|                                ESCENARIO DE AMENAZA (CAPA 7 OSI)                        |
+-----------------------------------------------------------------------------------------+
|   [ Atacante / Botnet ]                                                                 |
|            |                                                                            |
|            +---> 1. Reconocimiento: Banner Grabbing (curl -I / Nmap)                    |
|            |     Detecta: "Server: nginx/1.24.0" -> Busca CVEs de RCE / Buffer Overflow  |
|            |                                                                            |
|            +---> 2. Inyección Client-Side: Iframe Malicioso & Type Confusion            |
|            |     Explota ausencia de X-Frame-Options y X-Content-Type-Options           |
|            |                                                                            |
|            +---> 3. Saturación L7: HTTP Flood Concurrente (Apache Benchmark / Botnet)   |
|                  Envía miles de GETs válidos con TCP Handshake completo                 |
|                                                                                         |
|                                         | Tráfico de Ataque                             |
|                                         v                                               |
|               +-------------------------------------------------------+                 |
|               |              FRONTERA DE RED PERIMETRAL               |                 |
|               +-------------------------------------------------------+                 |
|                                         |                                               |
|                                         v                                               |
|         +-------------------------------------------------------------------+           |
|         |        CONTENEDOR NGINX DEFENSOR (IP: 172.28.0.10)                |           |
|         |                                                                   |           |
|         |   [ Capa de Hardening OWASP ]     [ Capa de Defensa Activa L7 ]   |           |
|         |   - server_tokens off             - Shared Memory: 10 MB          |           |
|         |   - X-Frame-Options: SAMEORIGIN   - Algoritmo: Leaky Bucket       |           |
|         |   - X-Content-Type: nosniff       - Rate: 5 r/s | Burst: 10       |           |
|         |   - Políticas RFC estrictas       - Modo Fail-Fast: nodelay       |           |
|         +-------------------------------------------------------------------+           |
+-----------------------------------------------------------------------------------------+
```

### 2.1 Amenaza 1: Escaneo Automatizado y Banner Grabbing
Los atacantes utilizan agentes de reconocimiento (motores como Shodan, Censys, o herramientas como Nmap y WhatWeb) que envían peticiones `HEAD` o `GET` a gran escala. Cuando un servidor Nginx opera con su configuración predeterminada de fábrica, incluye en los encabezados HTTP de respuesta la directiva:
```http
Server: nginx/1.25.3 (Ubuntu)
```
Esta fuga de información (*Information Disclosure*) permite al atacante automatizar la consulta de bases de datos de vulnerabilidades conocidas (NVD - National Vulnerability Database de NIST) e identificar vulnerabilidades específicas (Common Vulnerabilities and Exposures - CVE) asociadas a dicha versión para compilar un exploit dirigido.

### 2.2 Amenaza 2: Ataques Client-Side por Desconfiguración (OWASP A05)
Cuando el servidor no fuerza políticas de seguridad en sus cabeceras:
* **Clickjacking:** Un atacante diseña un portal fraudulento e inserta el sitio web legítimo dentro de una etiqueta `<iframe src="https://victima.com">` completamente transparente, ubicando botones maliciosos justo debajo del puntero del usuario. El usuario cree hacer clic en un enlace inofensivo, pero en realidad ejecuta transferencias de fondos, cambios de credenciales o eliminación de recursos con su sesión activa.
* **MIME-Sniffing:** Si un usuario sube un archivo con código ejecutable malicioso (JavaScript camuflado dentro de un archivo con extensión `.jpg` o `.png`), y el servidor no instruye de forma estricta al navegador cómo procesarlo, algunos navegadores antiguos o permisivos intentarán "adivinar" el contenido ejecutando el script en el contexto de seguridad del dominio de la víctima.

### 2.3 Amenaza 3: Inundación HTTP en Capa 7 (HTTP Flood DoS)
A diferencia de los ataques en Capas 3 y 4 del modelo OSI (como SYN Floods o amplificación UDP que buscan saturar los enlaces físicos o las tablas de estados de los enrutadores), un ataque **HTTP Flood en Capa 7** es semánticamente invisible para los firewalls convencionales sin inspección profunda (DPI):
* El atacante completa exitosamente el **TCP Three-Way Handshake** (SYN, SYN-ACK, ACK).
* La conexión es legal y válida.
* El atacante despacha solicitudes HTTP `GET /` de forma masiva y concurrente.
* Cada solicitud obliga al servidor a asignar un descriptor de archivo (*file descriptor*), abrir un buffer de socket en el kernel del sistema operativo, parsear la cabecera HTTP y procesar el contenido web.
* En un servidor sin defensa activa, unos pocos cientos de solicitudes concurrentes pueden agotar los *workers* del servidor web, llevando la CPU al 100% y denegando el servicio a usuarios legítimos.

---

## 3. FASE 2: FUNDAMENTACIÓN TEÓRICA

### 3.1 OWASP Top 10: A05:2021 (Security Misconfiguration)
El proyecto OWASP (*Open Worldwide Application Security Project*) clasifica en la posición **A05:2021** a las fallas de configuración de seguridad. Esta categoría ocurre cuando los administradores mantienen habilitadas características innecesarias, puertos abiertos, cuentas por defecto o cabeceras de respuesta desprotegidas.

Las contramedidas técnicas de hardening aplicadas son:
1. **`server_tokens off;`**: Elimina el número de versión de Nginx en la cabecera `Server` y en todas las páginas de error HTML generadas por el servidor.
2. **`add_header X-Frame-Options "SAMEORIGIN" always;`**: Ordena taxativamente a los navegadores que sólo permitan el embebido de páginas en marcos (`<iframe>`, `<frame>`, `<object>`) si el sitio que solicita el marco comparte el mismo origen exacto (protocolo, dominio y puerto).
3. **`add_header X-Content-Type-Options "nosniff" always;`**: Instruye al cliente para que inhabilite la autodetección de tipos MIME. Si el encabezado dice `Content-Type: text/html`, el navegador jamás intentará ejecutarlo como script o estilo alternativo.
4. **`add_header Content-Security-Policy ... always;` y `X-XSS-Protection "0" always;`**: Define una política estricta de orígenes permitidos (`default-src 'self'`, `object-src 'none'`, `frame-ancestors 'self'`), reemplazando el obsoleto filtro `X-XSS-Protection` (siguiendo la guía actual de OWASP).
5. **`add_header Permissions-Policy ... always;` y `Referrer-Policy ... always;`**: Restringe el acceso a APIs sensibles del navegador (`geolocation`, `microphone`, `camera`) y evita filtrar rutas/parámetros en cabeceras `Referer`.
6. **Bandera `always`:** Por defecto, Nginx suprime las cabeceras personalizadas de seguridad cuando la respuesta HTTP es un error (códigos 4xx o 5xx). Al declarar la bandera `always`, se fuerza al servidor a emitir estas cabeceras en **todas las respuestas sin excepción**, blindando incluso las respuestas ante peticiones fallidas.
7. **Restricción de métodos y defensa anti-Slowloris:** `limit_except GET { deny all; }` bloquea verbos innecesarios (`POST`, `PUT`, `DELETE`, `TRACE`), mientras que `limit_conn zona_conn 20;` y los timeouts de 10 segundos (`client_header_timeout`, `client_body_timeout`, `send_timeout`) evitan el agotamiento de sockets por conexiones lentas.

### 3.2 Defensa Activa y Preservación de la Disponibilidad (Tríada CIA)
La seguridad informática descansa sobre tres pilares fundamentales: **Confidencialidad, Integridad y Disponibilidad (Tríada CIA)**. La disponibilidad garantiza que los sistemas y servicios sean accesibles de forma confiable cuando un usuario autorizado lo requiera.

La **Defensa Activa** trasciende el modelo de seguridad pasiva (como un log de auditoría que registra una intrusión post-mortem). La defensa activa reacciona y mitiga el ataque en tiempo real, bloqueando el tráfico abusivo en el milisegundo en que se detecta el comportamiento anómalo.

### 3.3 Modelo Matemático y Algoritmo de Rate Limiting (Leaky Bucket)
Nginx implementa una variante de alto rendimiento del algoritmo **Leaky Bucket** (Cubo Perforado) a través de su módulo nativo `ngx_http_limit_req_module`.

```
                    Flujo de Peticiones Entrantes
                          (Concurrencia: c=50)
                                | | | | |
                                v v v v v
                     +-----------------------------+
                     |    CAPACIDAD DEL BÚFER      |
                     |         (burst=10)          |
                     |  [Slot 1] [Slot 2] ...      |
                     +-----------------------------+
                       /                         \
         (Dentro de Capacidad)             (Exceso de Capacidad)
                  |                                  |
                  v                                  v
     [ Despacho Inmediato: nodelay ]       [ Rechazo Inmediato: Fail-Fast ]
       Peticiones procesadas (200 OK)        HTTP 503 Service Unavailable
       Tasa de fuga: 5 req/s (1 c/200ms)     Evaluado en RAM Compartida (SHM)
```

#### Parámetros del Algoritmo en Nginx
* **Variable `$binary_remote_addr`:** Clave utilizada para indexar el cliente. Guarda la dirección IP de origen en representación binaria. Para IPv4 requiere únicamente **4 bytes** de memoria (frente a los 7 a 15 bytes que exigiría una cadena de texto estándar).
* **Zona de Memoria Compartida (`zone=zona_limite:10m`):** Se reservan 10 MB de memoria RAM compartida accesible de forma simultánea por todos los procesos worker de Nginx. Cada registro de estado de cliente consume 64 bytes en arquitecturas de 64 bits. En consecuencia, una zona de 10 MB puede almacenar y gestionar en vivo el estado de:
  $$\text{Capacidad de clientes en RAM} = \frac{10 \times 1024 \times 1024 \text{ bytes}}{64 \text{ bytes/cliente}} \approx 163,840 \text{ IPs concurrentes}$$
* **Tasa de Drenaje (`rate=5r/s`):** Establece la velocidad a la que el "cubo" se vacía. Una tasa de 5 peticiones por segundo significa que el servidor otorga un crédito de una petición cada $\frac{1000\text{ ms}}{5} = 200\text{ milisegundos}$.
* **Búfer de Tolerancia a Ráfagas (`burst=10`):** Define cuántas peticiones que excedan la tasa de 5 r/s pueden ser retenidas o admitidas temporalmente para acomodar la carga legítima de páginas web complejas (carga simultánea de HTML, CSS, imágenes y scripts).
* **Directiva `nodelay`:** Si no se incluye `nodelay`, Nginx introduce retardos artificiales (pausas de 200 ms) a las peticiones del burst para forzar la tasa a exactamente 5 r/s, degradando la experiencia de usuario y reteniendo sockets abiertos. Con `nodelay`, Nginx **procesa las peticiones autorizadas del burst inmediatamente**, pero en el instante en que el total de peticiones activas supera el umbral (`burst + tasa instantánea`), rechaza inmediatamente las peticiones excedentes con código `503 Service Unavailable` sin retardo alguno (**Fail-Fast**).

---

## 4. FASE 3: ARQUITECTURA Y TOPOLOGÍA DEL LABORATORIO

Para garantizar mediciones científicamente válidas y sin variaciones espurias ocasionadas por el tráfico de la red física, se configuró un entorno totalmente aislado mediante contenedores Docker sobre una subred virtual dedicada (*Software-Defined Network*).

```
+-----------------------------------------------------------------------------------------+
|                                    HOST ANFITRIÓN                                       |
|                                                                                         |
|    RED DOCKER BRIDGE AISLADA: red-defensa (Segmento CIDR: 172.28.0.0/16)                |
|                                                                                         |
|    +------------------------------------+      +------------------------------------+   |
|    |      NODO CLIENTE / ATACANTE       |      |       NODO SERVIDOR PROTEGIDO      |   |
|    |                                    |      |                                    |   |
|    |  Contenedor: cliente-atacante      |      |  Contenedor: servidor-defensa      |   |
|    |  IP Asignada: 172.28.0.20          |      |  IP Asignada: 172.28.0.10          |   |
|    |  S.O.: Alpine Linux 3.19           |      |  S.O.: Nginx Alpine                |   |
|    |                                    |      |                                    |   |
|    |  Software Instalado:               |=====>|  Políticas Activas:                |   |
|    |  - Apache Benchmark (ab)           |      |  - Ocultamiento de versión         |   |
|    |    Generador de concurrencia L7    |      |  - Cabeceras de seguridad OWASP    |   |
|    |  - cURL                            |      |  - Memoria Compartida: 10 MB       |   |
|    |    Auditor de cabeceras HTTP       |      |  - Rate Limiting: 5 r/s burst=10   |   |
|    +------------------------------------+      +------------------------------------+   |
|                         ^                                         |                     |
|                         |                                         v                     |
|    +--------------------------------------------------------------------------------+   |
|    |                 CONSOLA DE GESTIÓN DEL ADMINISTRADOR (POWERSHELL)              |   |
|    |  - Auditoría externa: curl.exe -I http://localhost (Mapeo de Puerto 80:80)     |   |
|    |  - Monitoreo de telemetría y CPU/RAM con docker stats                          |   |
|    +--------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

### Justificación de Componentes:
1. **Red Bridge Aislada (`red-defensa`):** Permite comunicación determinista entre el atacante (`172.28.0.20`) y el defensor (`172.28.0.10`) con latencias submilisegundo ($<0.1\text{ ms}$), eliminando factores de congestión externa de red.
2. **Imagen Nginx Alpine:** Seleccionada por su mínima superficie de ataque (tamaño $<15\text{ MB}$), ausencia de compiladores o binarios innecesarios (como `perl`, `python` o gestores de paquetes activos en runtime).
3. **Montaje de Volúmenes en Solo Lectura (`:ro`):** Los archivos `nginx.conf` y el contenido web se montan con el atributo `ro` (Read-Only) en el contenedor, previniendo alteraciones locales incluso ante un eventual compromiso de ejecución arbitraria de código.

---

## 5. FASE 4: IMPLEMENTACIÓN TÉCNICA DEL STACK

### 5.1 Configuración Definitiva de Nginx (`nginx.conf`)
El archivo de configuración unificado se encuentra ubicado en la raíz del proyecto (`nginx.conf`):

```nginx
events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    # =========================================================================
    # FASE 2 & 4: MITIGACIÓN OWASP A05:2021 (SECURITY MISCONFIGURATION)
    # =========================================================================
    server_tokens off;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # =========================================================================
    # FASE 2 & 4: PROTECCIÓN ANTI-SLOWLORIS Y LÍMITES DE CONEXIÓN / TIMEOUTS
    # =========================================================================
    client_header_timeout 10s;
    client_body_timeout   10s;
    send_timeout          10s;
    keepalive_timeout     15s;
    reset_timedout_connection on;
    client_max_body_size  1m;

    limit_conn_zone $binary_remote_addr zone=zona_conn:10m;
    limit_conn_status 503;

    # =========================================================================
    # FASE 2 & 4: DEFENSA ACTIVA EN CAPA 7 - RATE LIMITING (LEAKY BUCKET)
    # =========================================================================
    limit_req_zone $binary_remote_addr zone=zona_limite:10m rate=5r/s;
    limit_req_status 503;

    server {
        listen 80;
        server_name localhost;

        location / {
            limit_except GET {
                deny all;
            }

            limit_conn zona_conn 20;
            limit_req zone=zona_limite burst=10 nodelay;

            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }

        error_page 503 /custom_503.html;
        location = /custom_503.html {
            root /usr/share/nginx/html;
            internal;
        }
    }
}
```

### 5.2 Orquestación con Docker Compose (`docker-compose.yml`)
Ubicado en la raíz del proyecto (`docker-compose.yml`):

```yaml
services:
  servidor-defensa:
    image: nginx:alpine
    container_name: servidor-defensa
    restart: always
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./html:/usr/share/nginx/html:ro
    security_opt:
      - no-new-privileges:true
    mem_limit: 128m
    cpus: 0.50
    networks:
      red-defensa:
        ipv4_address: 172.28.0.10

  cliente-atacante:
    image: alpine:latest
    container_name: cliente-atacante
    command: tail -f /dev/null
    networks:
      red-defensa:
        ipv4_address: 172.28.0.20
    depends_on:
      - servidor-defensa

networks:
  red-defensa:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### 5.3 Procedimiento de Ejecución Paso a Paso

#### Paso 1: Inicialización del Laboratorio
En una ventana de PowerShell o terminal Linux, situarse en el directorio del proyecto y ejecutar:
```powershell
# Opción A: Despliegue con comandos Docker directos
docker network create --subnet=172.28.0.0/16 red-defensa

docker run -d --name servidor-defensa --net red-defensa --ip 172.28.0.10 -p 80:80 -v "${PWD}/nginx.conf:/etc/nginx/nginx.conf:ro" -v "${PWD}/html:/usr/share/nginx/html:ro" nginx:alpine

docker run -d --name cliente-atacante --net red-defensa --ip 172.28.0.20 alpine:latest tail -f /dev/null

# Instalar herramientas de auditoría y ataque en el contenedor cliente
docker exec -it cliente-atacante apk add --no-cache apache2-utils curl
```

*(O bien, **Opción B**: ejecutar simplemente `docker compose up -d` y posteriormente el comando `apk add`).*

---

## 6. FASE 5: ANÁLISIS FORENSE Y VALIDACIÓN DE RESULTADOS

### 6.1 Auditoría Perimetral de Cabeceras y Métodos con `curl.exe`
Desde la terminal del host se ejecuta una petición de inspección de encabezados hacia el puerto publicado:
```powershell
curl.exe -I http://localhost
```

#### Salida de Inspección Obtenida:
```http
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 10 Nov 2026 18:28:39 GMT
Content-Type: text/html
Content-Length: 1203
Last-Modified: Tue, 10 Nov 2026 04:54:42 GMT
Connection: keep-alive
ETag: "6af2a392-4b3"
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Accept-Ranges: bytes
```

Asimismo, se valida el rechazo de métodos HTTP no permitidos (`POST`):
```powershell
curl.exe -s -o NUL -w "POST status: %{http_code}`n" -X POST http://localhost
# Salida: POST status: 403
```

#### Análisis Forense de Cumplimiento:
1. **Ocultamiento de Versión:** El campo `Server` únicamente refleja la cadena genérica `nginx`. Se ha eliminado la subversión de compilación (ej. `nginx/1.27.x`), impidiendo el banner grabbing por agentes de reconocimiento.
2. **Defensa Clickjacking:** Se valida la inclusión de `X-Frame-Options: SAMEORIGIN` reforzada con `frame-ancestors 'self'` en `Content-Security-Policy`.
3. **Defensa MIME-Sniffing y XSS moderno:** Se valida `X-Content-Type-Options: nosniff`, una política `Content-Security-Policy` restrictiva (`object-src 'none'`, `base-uri 'self'`) y `X-XSS-Protection: 0` conforme a la recomendación actual de OWASP.
4. **Principio de Mínimo Privilegio en Métodos y APIs:** `Permissions-Policy` deshabilita sensores innecesarios y `limit_except GET` bloquea verbos de escritura (`POST` -> `403 Forbidden`).

---

### 6.2 Desglose Matemático del Ataque DoS (`ab`): ¿Por qué 31 OK y 969 Bloqueadas?
Desde el contenedor atacante se ejecuta la prueba de estrés de alta concurrencia:
```powershell
docker exec -it cliente-atacante ab -n 1000 -c 50 http://172.28.0.10/
```

#### Salida Forense del Generador de Carga:
```text
Server Software:        nginx
Server Hostname:        172.28.0.10
Server Port:            80

Document Path:          /
Document Length:        1203 bytes

Concurrency Level:      50
Time taken for tests:   4.100 seconds
Complete requests:      1000
Failed requests:        969
   (Connect: 0, Receive: 0, Length: 969, Exceptions: 0)
Non-2xx responses:      969
Total transferred:      1306314 bytes
HTML transferred:       763074 bytes
Requests per second:    243.88 [#/sec] (mean)
Time per request:       205.018 [ms] (mean)
Time per request:       4.100 [ms] (mean, across all concurrent requests)
Transfer rate:          311.12 [Kbytes/sec] received
```

```
+-----------------------------------------------------------------------------------------+
|                  DESGLOSE TÉCNICO DE LAS 1000 SOLICITUDES PROCESADAS                    |
+-----------------------------------------------------------------------------------------+
| TOTAL: 1000 Solicitudes                                                                 |
|                                                                                         |
|  [+] 31 Solicitudes con Estado HTTP 200 OK (Procesadas exitosamente):                   |
|      - Solicitud 1: Consumo de la cuota nominal inicial disponible en t = 0 ms.         |
|      - 10 Solicitudes: Absorbidas por los 10 slots del búfer (burst=10) con nodelay.    |
|      - ~20 Solicitudes adicionales: Drenaje continuo del balde a razón de 5 req/s       |
|        durante los 4.100 segundos que duró la prueba (5 × 4.100 = 20.5 tokens).         |
|                                                                                         |
|  [-] 969 Solicitudes con Estado HTTP 503 Service Unavailable (Rechazo Activo):          |
|      - Al superar la capacidad instantánea (burst=10) y la tasa de fuga de 5 r/s,       |
|        Nginx descarta cada petición excedente en memoria RAM compartida (SHM)           |
|        sirviendo la página ligera custom_503.html (749 bytes).                         |
+-----------------------------------------------------------------------------------------+
```

#### Deducción Matemática:
* Con `rate=5r/s`, el intervalo de drenaje teórico es $\Delta t = \frac{1000\text{ ms}}{5} = 200\text{ ms}$ (equivalente a un decaimiento continuo de $5\text{ tokens/segundo}$ calculado en milisegundos).
* La prueba inyecta 1000 peticiones con 50 conexiones concurrentes durante **4.100 segundos** (bajo restricción de `cpus: 0.50` y red virtualizada del contenedor).
* El número esperado de solicitudes admitidas responde directamente a la fórmula del *Leaky Bucket*:
  $$\text{Peticiones 200 OK} \approx 1\text{ (base)} + 10\text{ (burst)} + \lfloor 5\text{ r/s} \times 4.100\text{ s} \rfloor = 1 + 10 + 20 = 31\text{ peticiones}$$
* Las restantes **969 peticiones** (`96.9%`) desbordan la cuota y son rechazadas mediante la política Fail-Fast con código `503 Service Unavailable` (verificado en los logs de Nginx: `31` respuestas `200 1203` y `969` eventos `limiting requests ... 503 749`).

---

### 6.3 Comparativa Forense: Servidor sin Protección Aguas Abajo vs. Defensa Activa Fail-Fast

Es importante distinguir el impacto sobre un **servicio o backend protegido detrás de Nginx** frente al rechazo activo perimetral:

| Métrica Forense | Backend / Servidor Sin Rate Limiting | Servidor Bastionado con Nginx (Defensa Activa) |
| :--- | :--- | :--- |
| **Código de Respuesta ante Flood** | El 100% del tráfico llega al aplicativo; bajo saturación produce `504 Gateway Timeout`, `502 Bad Gateway` o *Connection Reset*. | Respuestas HTTP deterministas y controladas: **`503 Service Unavailable`** (`custom_503.html`). |
| **Exposición del Backend** | 1000 peticiones simultáneas golpean la lógica de negocio o base de datos. | **Solo 31 peticiones (3.1%)** pasan en 4.1s; **969 (96.9%)** se frenan en el perímetro. |
| **Protección contra Conexiones Lentas** | Vulnerable a agotamiento de workers/sockets (*Slowloris*). | **`limit_conn 20`** + timeouts de **10s** + `reset_timedout_connection on`. |
| **Uso de CPU y Memoria** | Escala linealmente con el procesamiento del aplicativo y riesgo de OOM. | Contenedor acotado a **128 MB RAM / 0.50 CPU** y evaluación **$O(1)$** en SHM (`10 MB`). |
| **Mecanismo de Descarte** | Desbordamiento del socket backlog o caída de procesos backend. | **Evaluación determinista $O(1)$** en memoria compartida antes de tocar disco o backend. |

**Conclusión Forense:** El servidor mantuvo su disponibilidad y protegió el servicio frente a una ráfaga de 1000 solicitudes concurrentes, demostrando la eficacia del control perimetral en Capa 7.

---

## 7. DISEÑO ESTRUCTURADO DE 10 DIAPOSITIVAS PARA LA EXPOSICIÓN

A continuación se presenta la estructura diapositiva por diapositiva para preparar el material visual (en PowerPoint, Canva o Google Slides):

---

### Diapositiva 1: Portada Oficial
* **Encabezado:** Universidad — Facultad de Ingeniería  
* **Asignatura:** Sistemas de Comunicación y Seguridad Informática (8vo Semestre)  
* **Título:** Bastionado Integral (Hardening) y Defensa Activa en Capa 7 de Servidores Nginx con Docker  
* **Subtítulo:** Mitigación Práctica de OWASP A05:2021 y Ataques DoS HTTP Flood  
* **Autores / Expositores:** [Nombres completos de los 3 integrantes]  
* **Recurso Gráfico:** Logotipos de Nginx, Docker, OWASP Top 10 y un escudo de ciberseguridad.

---

### Diapositiva 2: Planteamiento del Problema — El Escenario de Amenaza
* **Título:** Exposición Perimetral y Vectores de Ataque en Capa 7  
* **Puntos Clave:**
  * La Capa 7 (Aplicación) es el blanco predilecto: los firewalls tradicionales de paquetes (Capas 3 y 4) no distinguen solicitudes HTTP válidas de solicitudes maliciosas.
  * **Reconocimiento Pasivo/Activo:** El atacante utiliza *Banner Grabbing* para identificar la versión exacta de Nginx y seleccionar CVEs precompilados.
  * **Agotamiento de Recursos (HTTP Flood):** Conexiones TCP legales que buscan saturar los descriptores de archivo y los procesos worker.
* **Recurso Gráfico:** Esquema de un atacante enviando sondas de reconocimiento y luego un diluvio de tráfico HTTP hacia un servidor desprotegido.

---

### Diapositiva 3: Marco Teórico — OWASP A05:2021 (Security Misconfiguration)
* **Título:** Hardening de Cabeceras HTTP contra Amenazas en el Cliente  
* **Puntos Clave:**
  * La configuración por defecto es insegura: divulga metadatos e ignora directivas de renderizado.
  * **Clickjacking (UI Redressing):** Secuestro visual mediante superposición de iframes transparentes. Mitigación: `X-Frame-Options: SAMEORIGIN`.
  * **MIME-Sniffing:** Ejecución involuntaria de scripts debido a ambigüedad de contenido. Mitigación: `X-Content-Type-Options: nosniff`.
  * **Principio de Ocultamiento:** `server_tokens off` para eliminar el banner de versión.
* **Recurso Gráfico:** Diagrama comparativo mostrando un iframe malicioso bloqueado por la cabecera `X-Frame-Options`.

---

### Diapositiva 4: Marco Teórico — Defensa Activa y Tríada CIA
* **Título:** Preservación de la Disponibilidad Mediante Rate Limiting  
* **Puntos Clave:**
  * **Tríada CIA:** La Disponibilidad se defiende con controles preventivos activos y principio de mínimo privilegio.
  * **Algoritmo Leaky Bucket:** Modelado de flujo constante a 5 peticiones/segundo con absorción de ráfagas (`burst=10`).
  * **Comportamiento Fail-Fast (`nodelay`):** Despacho sin esperas artificiales y rechazo instantáneo en memoria RAM.
  * **Códigos HTTP de Defensa:** Uso de `503 Service Unavailable` frente al estándar `429 Too Many Requests` (RFC 6585).
* **Recurso Gráfico:** Diagrama de flujo del "Balde Perforado" con gotas de agua que representan peticiones aceptadas y el rebose descartado.

---

### Diapositiva 5: Arquitectura del Laboratorio de Demostración
* **Título:** Topología Aislada y Stack Técnico en Contenedores  
* **Puntos Clave:**
  * **Orquestación con Docker:** Aislamiento en namespaces de red y filesystem inmutable en solo lectura (`:ro`).
  * **Red Bridge Dedicada (`red-defensa` - 172.28.0.0/16):** Entorno de pruebas determinista sin interferencia externa.
  * **Servidor Nginx (172.28.0.10):** Motor con directivas de hardening y módulo `ngx_http_limit_req_module`.
  * **Cliente Atacante (172.28.0.20):** Contenedor Alpine instrumentalizado con `ab` (Apache Benchmark) y `curl`.
* **Recurso Gráfico:** Diagrama de red Docker mostrando los dos contenedores en la red `red-defensa`.

---

### Diapositiva 6: Implementación Técnica — El Archivo `nginx.conf`
* **Título:** Configuración Unificada de Seguridad y Control de Tasa  
* **Puntos Clave:**
  * `limit_req_zone $binary_remote_addr zone=zona_limite:10m rate=5r/s;`
    * Explicación: Memoria binaria (4 bytes/IP) que permite rastrear hasta 160,000 IPs en 10 MB de SHM.
  * `limit_req zone=zona_limite burst=10 nodelay;`
    * Explicación: Tolerancia a picos legítimos sin encolamiento bloqueante.
  * Inyección de directivas con parámetro `always` para forzar su envío en respuestas de error.
* **Recurso Gráfico:** Bloque de código Nginx con recuadros destacados en color sobre las directivas clave.

---

### Diapositiva 7: Demostración Práctica 1 — Auditoría Perimetral OWASP
* **Título:** Validación de Hardening y Supresión de Banner con cURL  
* **Puntos Clave:**
  * Comando ejecutado: `curl.exe -I http://localhost`
  * Verificación de la cabecera `Server: nginx` (subversión oculta con éxito).
  * Confirmación de presencia de las cabeceras `X-Frame-Options: SAMEORIGIN` y `X-Content-Type-Options: nosniff`.
  * Evaluación de conformidad: Se neutraliza el vector de reconocimiento automatizado.
* **Recurso Gráfico:** Captura de pantalla de la terminal PowerShell mostrando la salida HTTP limpia y segura.

---

### Diapositiva 8: Demostración Práctica 2 — Simulación de Ataque DoS L7
* **Título:** Ataque de Inundación HTTP con Apache Benchmark  
* **Puntos Clave:**
  * Comando ejecutado: `ab -n 1000 -c 50 http://172.28.0.10/`
  * Escenario de estrés: 1000 peticiones enviadas por 50 clientes simultáneos contra la ruta raíz.
  * Monitoreo de telemetría: Tiempo de respuesta ultra-rápido sin degradación de los recursos de cómputo del anfitrión.
* **Recurso Gráfico:** Captura de pantalla del comando `ab` ejecutándose desde el contenedor atacante.

---

### Diapositiva 9: Análisis Forense de Resultados
* **Título:** Desglose Forense: Control Determinista bajo Ataque HTTP Flood  
* **Puntos Clave:**
  * **Desglose Matemático:** $1 \text{ (nominal)} + 10 \text{ (burst)} + \lfloor 5\text{ r/s} \times T\text{ (s)} \rfloor$. En nuestra corrida real de `4.100 s`: **31 respuestas `200 OK`** (`3.1%`).
  * **Bloqueo Activo:** **969 solicitudes rechazadas** (`96.9%`) con código HTTP `503` (`custom_503.html` de 749 bytes).
  * **Defensa Complementaria:** `POST` rechazado con `403 Forbidden`, límite de 20 conexiones TCP/IP y timeouts anti-Slowloris de `10 s`.
  * **Conclusión:** Descarte en memoria RAM compartida mediante evaluación Fail-Fast $O(1)$, protegiendo el servicio y los límites del contenedor (`128 MB` / `0.50 CPU`).
* **Recurso Gráfico:** Gráfica de pastel mostrando ~3.1% de peticiones 200 OK frente a ~96.9% de peticiones 503 bloqueadas.

---

### Diapositiva 10: Conclusiones y Recomendaciones de Ingeniería
* **Título:** Conclusiones y Buenas Prácticas en Infraestructuras Críticas  
* **Puntos Clave:**
  * La defensa en profundidad exige controles en Capa 7: un firewall perimetral L3/L4 es insuficiente por sí solo.
  * Nginx en contenedores inmutables ofrece resiliencia contra ataques de denegación de servicio a escala de microservicios.
  * La memoria compartida (SHM) garantiza un rendimiento predecible y evita la saturación del sistema operativo.
  * Automatización: Se recomienda auditar cabeceras y límites en pipelines de integración continua (CI/CD).
* **Recurso Gráfico:** Cuadro resumen con las directivas de hardening y espacio para la sesión de preguntas y respuestas.

---

## 8. GUION DE SUSTENTACIÓN FORMAL PARA LOS 3 INTEGRANTES

Este guion está adaptado para que los 3 integrantes asuman las secciones con balance equitativo de tiempo y un vocabulario riguroso de ingeniería de ciberseguridad:

---

### Expositor 1: Introducción, Escenario de Amenaza y OWASP A05:2021 (Diapositivas 1 a 3)
> *"Muy buenas tardes, profesor y compañeros. En esta sustentación final, nuestro equipo presenta el proyecto titulado: **Bastionado Integral y Defensa Activa en Capa 7 de Servidores Nginx mediante Contenedores Docker**.*
> 
> *Al analizar la seguridad bajo el modelo OSI, observamos que las organizaciones blindan las Capas 3 y 4 con firewalls de paquetes, pero dejan desprotegida la **Capa 7 (Capa de Aplicación)**. Un atacante no necesita saturar el enlace con un ataque volumétrico UDP; le basta con establecer conexiones TCP legítimas mediante el Three-Way Handshake y bombardear el servidor con solicitudes HTTP formalmente válidas que agotan sockets, memoria y descriptores de archivo.*
> 
> *A su vez, mediante técnicas de **Banner Grabbing**, herramientas automatizadas escanean el encabezado `Server` para correlacionar versiones exactas con vulnerabilidades CVE conocidas. En este proyecto atacamos directamente la categoría **OWASP A05:2021 (Security Misconfiguration)**: primero, suprimiendo la versión con `server_tokens off`, y segundo, inyectando cabeceras mandatorias con la bandera `always`: `X-Frame-Options: SAMEORIGIN` para neutralizar el **Clickjacking** (secuestro de clics mediante iframes) y `X-Content-Type-Options: nosniff` para erradicar el **MIME-Sniffing** o confusión de contenido en el navegador."*

---

### Expositor 2: Fundamentación Teórica, Rate Limiting y Arquitectura Docker (Diapositivas 4 a 6)
> *"Para garantizar el pilar de **Disponibilidad en la Tríada CIA**, implementamos una estrategia de Defensa Activa fundamentada en el algoritmo **Leaky Bucket (Cubo Perforado)** mediante el módulo nativo `ngx_http_limit_req_module`.*
> 
> *Nuestra directiva central es: `limit_req_zone $binary_remote_addr zone=zona_limite:10m rate=5r/s;`. Destacamos el uso de la variable `$binary_remote_addr`: representa la dirección IP en formato de red binario de **4 bytes** para IPv4, a diferencia de los 15 bytes que consume una cadena de texto. En un segmento de **10 MB de memoria compartida (SHM)**, Nginx tiene la capacidad de monitorear y calcular el estado de flujo de más de **160,000 direcciones IP simultáneas** en tiempo real.*
> 
> *Fijamos una tasa de vaciado de 5 peticiones por segundo combinada con `burst=10 nodelay`. Esta directiva es vital: permite absorber ráfagas legítimas de tráfico transitorio despachándolas inmediatamente sin pausas artificiales, pero aplicando una política **Fail-Fast** en memoria RAM compartida: toda solicitud que desborde el bucket es rechazada de inmediato con código `503 Service Unavailable` sin tocar el sistema de archivos.*
> 
> *Toda la solución se encuentra orquestada en una red bridge aislada `red-defensa (172.28.0.0/16)` sobre contenedores Alpine Linux con volúmenes montados con permisos estrictos de solo lectura (`:ro`), cumpliendo con el principio de mínimo privilegio."*

---

### Expositor 3: Demostración en Vivo, Análisis Forense de Resultados y Conclusiones (Diapositivas 7 a 10)
> *(El Expositor 3 toma el control de la consola PowerShell para ejecutar los comandos en tiempo real).*
> 
> *"Procederemos ahora con la demostración práctica en vivo y el análisis forense de la telemetría.*
> 
> *En primer lugar, realizamos la auditoría de hardening perimetral ejecutando `curl.exe -I http://localhost` desde el host. Confirmamos que el encabezado `Server` reporta exclusivamente `nginx`, ocultando la subversión, y constatamos la emisión activa de `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Permissions-Policy` y `X-XSS-Protection: 0` en cumplimiento estricto con OWASP A05:2021.*
> 
> *A continuación, nos posicionamos en el contenedor atacante e iniciamos un ataque de estrés en Capa 7 utilizando Apache Benchmark: `ab -n 1000 -c 50 http://172.28.0.10/`, inyectando 1000 peticiones en 50 hilos simultáneos.*
> 
> *(Ejecuta la prueba y muestra los resultados en la consola)*
> 
> *Observen las métricas forenses: de las 1000 peticiones procesadas en **4.100 segundos**, **exactamente 31 peticiones resultaron exitosas (200 OK) y 969 fueron bloqueadas con código 503**. La deducción matemática coincide con el algoritmo Leaky Bucket: se concede 1 petición base en $t=0$, 10 peticiones absorben los slots del `burst=10`, y durante los $4.100\text{ s}$ de la prueba el cubo drena $5 \times 4.100 \approx 20$ tokens adicionales ($1 + 10 + 20 = 31$). Las 969 solicitudes restantes fueron interceptadas y rechazadas al instante en memoria compartida.*
> 
> *Esto demuestra que el servidor no colapsó ni desbordó sus límites de 128 MB de RAM y 0.50 CPU, sino que ejecutó una **Defensa Activa Exitosa en Capa 7**, complementada con límites de 20 conexiones concurrentes (`limit_conn`), timeouts de 10 segundos anti-Slowloris y restricción de métodos HTTP (`limit_except GET`). Con esto concluimos y quedamos a disposición del profesor para la ronda de preguntas."*

---

## 9. MANUAL RÁPIDO DE COMANDOS PARA DEMOSTRACIÓN EN VIVO (CHEAT SHEET)

Tener este bloque a mano para copiar y pegar durante la sustentación práctica:

### 1. Inicialización de la Infraestructura (Recomendado con Docker Compose)
```powershell
# Ubicarse en el directorio del proyecto
cd "c:\Users\Anderson Ojeda\Downloads\final2\final2"

# Levantar el servidor protegido y el contenedor atacante
docker compose up -d

# Instalar utilidades de auditoría y ataque en el contenedor atacante
docker exec cliente-atacante apk add --no-cache apache2-utils curl
```

### 2. Prueba 1: Auditoría de Cabeceras y Métodos (OWASP A05)
```powershell
curl.exe -I http://localhost
curl.exe -s -o NUL -w "POST status: %{http_code}`n" -X POST http://localhost
```

### 3. Prueba 2: Ataque de Estrés DoS L7 (1000 reqs / 50 concurrencia)
```powershell
docker exec -it cliente-atacante ab -n 1000 -c 50 http://172.28.0.10/
```

### 4. Prueba 3: Inspección Forense de Logs de Nginx
```powershell
docker logs --tail 25 servidor-defensa
```

### 5. Limpieza Post-Demostración
```powershell
docker compose down
```

---

## 10. BANCO DE PREGUNTAS AVANZADAS DE SUSTENTACIÓN CON RESPUESTAS

Estas 5 preguntas abarcan los puntos más profundos que el docente evaluador podría cuestionar:

---

### Pregunta 1
**Pregunta del Profesor:**  
*"¿Por qué utilizaron `$binary_remote_addr` en lugar de `$remote_addr` en la directiva `limit_req_zone`, y qué implicación tiene esto en la memoria compartida de Nginx?"*

**Respuesta para el Estudiante:**  
> *"Utilizamos `$binary_remote_addr` porque almacena la dirección IP en formato de red binario. En el caso de IPv4, esto ocupa invariablemente **4 bytes**, y en IPv6 ocupa **16 bytes**. Por el contrario, la variable `$remote_addr` almacena la IP como una cadena de caracteres ASCII, lo cual consume entre 7 y 15 bytes para IPv4 únicamente en el texto, más la sobrecarga del objeto de cadena de Nginx.  
> 
> En términos de escalabilidad de memoria compartida (*SHM*), cada entrada de cliente en la tabla hash de 64 bits ocupa aproximadamente 64 bytes cuando usamos formato binario. Gracias a esto, en nuestra zona asignada de **10 MB (`10m`)**, Nginx es capaz de registrar y gestionar en vivo el estado de aproximadamente **160,000 direcciones IP únicas** en paralelo. Usar `$remote_addr` reduciría esta capacidad a menos de la mitad, limitando la efectividad frente a ataques distribuidos."*

---

### Pregunta 2
**Pregunta del Profesor:**  
*"Si ustedes configuraron una tasa nominal de 5 peticiones por segundo (`rate=5r/s`), ¿por qué la prueba de Apache Benchmark arrojó 31 peticiones exitosas (código 200 OK) y no solamente 5?"*

**Respuesta para el Estudiante:**  
> *"Esto se debe al acoplamiento de `burst=10`, `nodelay` y el tiempo total que duró la prueba (`4.100 s`).  
> 
> La tasa `rate=5r/s` define la velocidad de drenaje continuo del algoritmo Leaky Bucket (5 tokens por segundo, calculados con precisión de milisegundos). Al recibir tráfico concurrente, se aprueba 1 petición inicial, se absorben 10 peticiones en los slots de `burst=10` (atendidas sin retardo gracias a `nodelay`), y durante los **4.100 segundos** que tomó despachar las 1000 peticiones en el contenedor limitado a `0.50 CPU`, el cubo drenó $\lfloor 5 \times 4.100 \rfloor = 20$ tokens adicionales. La suma coincide exactamente: $1 + 10 + 20 = 31\text{ peticiones } 200\text{ OK}$, mientras las 969 restantes fueron rechazadas al instante con código 503."*

---

### Pregunta 3
**Pregunta del Profesor:**  
*"Desde el punto de vista de las normas RFC y el diseño de APIs REST, ¿cuál es la diferencia conceptual entre responder con HTTP 503 frente a HTTP 429 ante un exceso de solicitudes?"*

**Respuesta para el Estudiante:**  
> *"La diferencia radica en la semántica del estándar RFC:  
> * El código **`503 Service Unavailable`** (RFC 7231 / RFC 9110) es un código genérico de Capa de Aplicación que notifica que el servidor no puede atender la petición en ese instante debido a una sobrecarga transitoria o mantenimiento. Es el código que Nginx utiliza por defecto en `limit_req` porque el servidor decide voluntariamente rehusarse a prestar servicio para resguardar su propia integridad.  
> * El código **`429 Too Many Requests`** fue introducido formalmente en el **RFC 6585** específicamente para mecanismos de limitación de tasa (*Rate Limiting*). Indica explícitamente al cliente que ha sobrepasado su cuota en un intervalo de tiempo determinado y suele acompañarse de la cabecera `Retry-After`.  
> 
> Nginx permite alternar fácilmente a este comportamiento mediante la directiva `limit_req_status 429;` si se desea cumplir estrictamente con especificaciones de APIs modernas."*

---

### Pregunta 4
**Pregunta del Profesor:**  
*"¿Por qué la prueba de estrés de 1000 solicitudes sobre 50 hilos no saturó la CPU ni la memoria del servidor anfitrión ni derribó el contenedor?"*

**Respuesta para el Estudiante:**  
> *"La razón fundamental se encuentra en la arquitectura asíncrona no bloqueante de Nginx basada en eventos (`epoll`) y en el principio de **Fail-Fast** en memoria compartida, sumado al acotamiento del contenedor (`128 MB` de RAM y `0.50 CPU`).  
> 
> Nginx no asigna un proceso ni un hilo por cada cliente nuevo, como lo haría un servidor tradicional `mpm_prefork`. Cuando llega una solicitud, el worker lee las cabeceras básicas y consulta de inmediato la tabla hash en memoria compartida (`SHM`). Al verificar en tiempo $O(1)$ que el cliente ha agotado su cuota, Nginx aborta el procesamiento normal y despacha una respuesta 503 ligera (`custom_503.html` de 749 bytes).  
> 
> Esto significa que las 969 peticiones bloqueadas jamás saturaron discos ni un eventual backend aguas abajo; además, `limit_conn 20` y los timeouts de 10 segundos impiden que conexiones abiertas lentamente agoten los descriptores de sockets."*

---

### Pregunta 5
**Pregunta del Profesor:**  
*"¿Por qué fue indispensable incluir la palabra clave `always` al final de las directivas `add_header` para las cabeceras de seguridad como `X-Frame-Options`?"*

**Respuesta para el Estudiante:**  
> *"Fue indispensable debido al comportamiento interno de Nginx por defecto.  
> 
> Si se omite la palabra clave `always`, Nginx únicamente añade las cabeceras personalizadas de `add_header` en aquellas respuestas cuyo código de estado sea considerado de éxito (como 200, 201, 204, 301, 302). Si el servidor llega a emitir un código de error de cliente o de servidor (como 404 Not Found, 500 Internal Server Error o nuestras respuestas defensivas 503), Nginx suprime por defecto dichas cabeceras de seguridad.  
> 
> Un atacante podría provocar deliberadamente un error 404 o 503 en una URL y, al carecer dicha respuesta de la cabecera `X-Frame-Options`, podría embeber esa página de error en un iframe para realizar ataques de Clickjacking o Phishing. Al declarar `always`, garantizamos que las políticas de seguridad se inyecten de forma obligatoria en **todas las respuestas HTTP**, sin importar el código de estado devuelto."*
