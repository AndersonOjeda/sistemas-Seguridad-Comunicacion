# Mercado Local · Laboratorio de seguridad

Demostración local con **Nginx, Docker Compose, Python estándar y HTML/CSS/JS**. Reutiliza los tres servicios originales; no necesita frameworks, paquetes Python ni base de datos. El inventario es ficticio y de sólo lectura.

## Iniciar

Con Docker Desktop abierto y el puerto 80 libre:

```powershell
docker compose up -d
docker compose exec -T servidor-defensa nginx -t
docker compose exec -T servidor-defensa nginx -s reload
```

Abre **http://localhost**. Usa ese nombre para las cookies `Secure` en el entorno HTTP local; no accedas mediante la IP Docker desde el navegador.

| Cuenta ficticia | Contraseña | Acceso |
| --- | --- | --- |
| `usuario` | `UsuarioDemo2026!` | `/panel`, inventario |
| `admin` | `AdminDemo2026!` | `/panel`, `/admin`, auditoría, logs y carga |

Para detener: `docker compose down`. Los logs persisten en el volumen `monitor_logs`; las sesiones se pierden al reiniciar la aplicación.

## Demostrar

- Login correcto: **200**; credenciales incorrectas: **401**. Se conserva el bloqueo de cuenta original: desde el quinto fallo, **429** durante 30 s.
- Con `usuario`, escribe `/admin` en la dirección: el **backend responde 403**. También protege `/monitor.html`, `/api/monitor` y la API de carga. Sin sesión responde 401.
- Con `admin`, pulsa **Ejecutar 1.000 POST**. El servicio `cliente-atacante` envía exactamente 1.000 POST ficticios al login `http://172.28.0.10/api/auth/login`, con máximo 50 concurrentes. Usa la cuenta ficticia de usuario y descarta las cookies recibidas. El navegador sólo inicia y consulta el trabajo.
- El resultado muestra códigos HTTP reales, admitidas, rechazadas con **503**, duración y errores de transporte separados. No hay cifras prefijadas: cambian según la ejecución. Admitidas significa que llegaron a Python (200/400/401/429); no equivale siempre a autenticación exitosa.
- Sólo un administrador con token CSRF puede iniciar la carga. Una segunda prueba activa devuelve **409**. No se aceptan parámetros de destino, volumen, concurrencia ni comandos; el ejecutor interno sólo acepta el origen Docker de la aplicación. No tiene puertos publicados ni acceso al socket Docker.
- **Auditar cabeceras** consulta una respuesta real. **Actividad reciente** lee las últimas 500 líneas del log de Nginx y muestra hasta 100 eventos; excluye las consultas de monitor y progreso. No es un total histórico. El log identifica rechazos por tasa o por conexiones, sin cuerpos POST, cookies, contraseñas ni query strings.

## Defensas conservadas

Cabeceras OWASP con `always`, `server_tokens off`, `limit_req 5r/s burst=10 nodelay`, `limit_conn 20`, las dos zonas SHM de 10 MB, timeouts de cabeceras/cuerpo/envío de 10 s, límites de recursos, logs y página de error **503**. Se conservan las rutas originales de comparación `/api/demo/open`, `/api/demo/protected` y `/api/demo/stats`.

POST se permite únicamente en `/api/auth/login`, `/api/auth/logout` y `/api/admin/load` (esta última también permite GET/HEAD para consultar progreso). Las demás rutas conservan GET/HEAD; métodos no autorizados reciben 403 (TRACE conserva el 405 nativo de Nginx). Nginx publica exclusivamente `127.0.0.1:80`. El atacante usa la imagen Python sobre Alpine, compartida con la aplicación, y reutiliza `app.py --attacker` sin instalar herramientas al arrancar.

Las contraseñas se verifican con PBKDF2-HMAC-SHA256, 210.000 iteraciones y sal individual. Sesiones opacas de 30 minutos en memoria, cookies `HttpOnly; Secure; SameSite=Strict`, rotación al iniciar sesión, revocación al salir y CSRF en acciones autenticadas. No se guardan tokens en localStorage. HTTP sobre localhost es una excepción de los navegadores para cookies Secure, no cifra el transporte; este laboratorio no configura TLS ni se publica para producción.

## Validar

```powershell
python tests/validate_lab.py
curl.exe -I http://localhost/
curl.exe -i -X POST http://localhost/
docker compose logs --tail=20 servidor-defensa cliente-atacante
docker compose exec -T servidor-defensa tail -n 20 /monitor/access.log
```

La prueba automatizada valida login, autorización y rutas antiguas, métodos, cabeceras, cookies, CSRF, revocación y una carga real de 1.000 POST; coteja sus códigos con el log de Nginx. Ejecútala sin otra carga activa. La prueba termina conservando el resultado para revisarlo en `/admin`.
