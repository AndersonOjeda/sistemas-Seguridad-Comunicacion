# Mercado Local ? Laboratorio de seguridad

Aplicaci?n local con inicio de sesi?n, inventario ficticio y centro de actividad. Utiliza Nginx, Python, SQLite y Docker Compose.

## Iniciar

Con Docker Desktop abierto y el puerto 80 libre:

```powershell
cd 'C:\Users\isamu\Desktop\seguridad\sistemas-Seguridad-Comunicacion'
docker compose up -d
```

Abre http://localhost e inicia sesi?n con `admin` y `demo1234`. Para detenerlo: `docker compose down`.

## Demostraci?n

El acceso correcto abre el inventario. La secci?n **Actividad** muestra las ?ltimas 500 solicitudes registradas por Nginx y sus c?digos, sin incluir las consultas autom?ticas al propio centro de actividad. Se actualiza cada cinco segundos. El bot?n de tr?fico env?a 1.000 solicitudes a una ruta local protegida por Nginx.

Para observar el l?mite de cuenta, cierra sesi?n y prueba cinco veces una contrase?a incorrecta. Las primeras respuestas son 401 y desde el quinto intento se responde 429 durante 30 segundos para ese nombre de usuario. Luego puedes iniciar sesi?n y revisar los registros. El contador de intentos se mantiene en memoria y se reinicia al reiniciar la aplicaci?n.

Nginx limita la tasa por IP a 5 solicitudes por segundo con una r?faga de 10. El exceso recibe 503. El centro de actividad lee el registro de Nginx, por lo que tambi?n muestra solicitudes rechazadas antes de llegar a Python. La prueba de tr?fico puede afectar temporalmente otras solicitudes de la misma IP; espera unos segundos si aparece un 503.

El inventario requiere una cookie de sesi?n firmada. Las consultas de login usan par?metros SQL. La cuenta y los datos son ficticios y se recrean en almacenamiento temporal. El registro de acceso persiste en un volumen Docker y contiene ruta, m?todo, IP, c?digo y tiempo, sin cuerpos ni contrase?as. El monitoreo muestra una ventana de 500 registros, no estad?sticas hist?ricas completas.

El proyecto es local y did?ctico: cuenta con credenciales de muestra, contrase?as de ejemplo y limitaci?n en memoria. No est? preparado para producci?n.
