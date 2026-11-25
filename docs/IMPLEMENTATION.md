# Guía de implementación y pruebas

Esta guía describe cómo ejecutar CicloSec localmente y cómo preparar un
despliegue de producción en Linux con Docker Compose. Las dos rutas no tienen
el mismo nivel de soporte: **la ejecución local está implementada; producción
todavía no está lista para exposición pública**. Consulta los bloqueos de
producción antes de desplegar.

## 1. Preparación automática local

### 1.1 Requisito del host

- Docker Desktop o Docker Engine con Docker Compose y daemon activo.
- PowerShell 5.1+ en Windows o Bash en Linux/macOS.
- Acceso a un repositorio autorizado solo si luego vas a probar escaneos reales.

No hace falta instalar Python, `uv`, Trivy ni OSV-Scanner manualmente. El modo
nativo instala `uv`, Python 3.12, las dependencias bloqueadas y los escáneres
verificados dentro del entorno del proyecto. El modo Docker instala las
dependencias Python y los escáneres en la imagen. Docker es el único requisito
manual del host; se necesita para PostgreSQL y Redis en ambos modos.

Desde la raíz del proyecto, ejecuta una opción:

```powershell
.\scripts\setup.ps1
```

```bash
bash scripts/setup.sh
```

Para ejecutar web y worker en contenedores en lugar del entorno Python local:

```powershell
.\scripts\setup.ps1 -Docker
```

```bash
bash scripts/setup.sh --docker
```

El bootstrap crea `.env` y `config/ciclosec.yaml` solo si no existen. En el
primer uso genera contraseñas y una clave Django local; no sobrescribe
configuración previa. Si `.env` existente aún contiene placeholders, la
instalación se detiene para evitar iniciar servicios con secretos inseguros.
Antes de repetir la instalación, comprueba que no hay trabajos activos ni
reservados: el modo Docker puede reconstruir la imagen, recrear web y worker
y ejecutar migraciones. El modo nativo también arranca servicios y ejecuta
migraciones. No uses la reinstalación para recuperar trabajos interrumpidos.
Los escáneres se descargan de sus releases oficiales, se verifican con los
manifiestos SHA-256 y quedan en el entorno que ejecuta el worker.
Antes de reemplazar un escáner existente, el instalador comprueba la versión
del nuevo ejecutable en el mismo sistema de archivos. Si falla la descarga,
el checksum o esa comprobación, conserva el ejecutable anterior e informa
del error.
Se necesita salida HTTPS a Astral, GitHub, PyPI y los registros de imágenes
Docker para instalar los componentes.

No se instala Docker automáticamente: requiere privilegios del sistema y
puede necesitar reiniciar servicios o el equipo. La aplicación no configura
tokens de GitHub ni habilita escaneos bajo demanda.

El modo nativo de Windows requiere arquitectura AMD64 porque Trivy y
OSV-Scanner no publican ambos binarios para Windows ARM64 en las versiones
fijadas. En Windows ARM, usa el modo Docker con contenedores Linux ARM64.

### 1.2 Ejecutar el modo nativo

El script nativo deja instalados el entorno Python, los escáneres, PostgreSQL,
Redis y las migraciones. Crea una cuenta local:

```powershell
uv run python manage.py createsuperuser
```

Inicia la web y el worker en terminales separadas:

```powershell
uv run python manage.py runserver 127.0.0.1:8000
```

```powershell
uv run celery -A ciclosec.project.celery:app worker --loglevel INFO --pool solo
```

En Windows se usa `solo`: el pool predeterminado falla al crear procesos. Este
pool ejecuta una tarea a la vez; mientras está ocupado puede no responder al
ping del diagnóstico. En Linux o macOS, usa el pool predeterminado:

```bash
uv run celery -A ciclosec.project.celery:app worker --loglevel INFO
```

PostgreSQL y Redis se ejecutan en Docker y sus puertos de host están enlazados
a loopback (`5433` y `6380` por defecto). El volumen `postgres_data` persiste
al detener los servicios; no uses `docker compose down --volumes` para resolver
problemas de conexión. En instalaciones nuevas la URL nativa de PostgreSQL usa
`127.0.0.1`, como el puerto publicado por Compose. Si una instalación existente
usa `localhost` y tarda en conectar, cambia solo el host de
`CICLOSEC_DATABASE_URL` en tu `.env` local a `127.0.0.1`; conserva el resto
de la URL y no compartas sus credenciales. El instalador no modifica `.env`.

### 1.3 Ejecutar el modo Docker

El modo Docker construye una imagen local con Python, las dependencias del
proyecto y ambos escáneres; aplica migraciones y arranca web y worker:

```powershell
docker compose --profile app ps
```

Docker Compose pasa las credenciales de proveedor del `.env` solo al worker;
la web, las migraciones y Beat reciben únicamente la configuración que
necesitan para Django, PostgreSQL y Redis.

Abre `http://127.0.0.1:8000/` y crea una cuenta con:

```powershell
docker compose exec web python manage.py createsuperuser
```

Beat no se inicia por defecto porque ejecuta sincronizaciones contra
proveedores externos. Si vas a probarlas, inicia una sola instancia:

```powershell
docker compose --profile scheduler up -d beat
```

### 1.4 Diagnóstico local sin iniciar trabajos

En modo nativo, con la configuración local ya preparada:

```powershell
uv run --no-sync python manage.py ciclosec_doctor --mode native
```

En Docker, construye primero la imagen de la versión que se va a comprobar y
ejecuta un contenedor temporal con la configuración del worker:

```powershell
docker compose --profile app build worker
docker compose --profile app run --rm --no-deps -T worker python manage.py ciclosec_doctor --mode docker
```

El diagnóstico comprueba la configuración cargada, el espacio del sistema de
archivos **del proceso**, la conexión y migraciones de la base de datos, el
broker Redis, la respuesta de un worker, la página de acceso y las versiones
de los escáneres presentes en el proceso. Si la base de datos responde, también
informa los conteos de cola y los últimos cinco escaneos por ID y estado,
marcando si hay un error registrado. No incluye nombres de activos ni texto de
errores crudos. El estado de la cola es una instantánea de PostgreSQL, no una
comprobación de entrega al broker. El comando no muestra credenciales, aplica
migraciones, inicia escaneos ni activa Beat. En el contenedor temporal, las
versiones comprobadas son las de la imagen utilizada, no una prueba de que
todos los workers activos ejecuten esa imagen.

Por defecto exige 1024 MiB libres en el sistema de archivos del proceso; usa
`--min-free-mib <cantidad>` para adaptar el umbral. Esta medida no garantiza
espacio en el volumen de PostgreSQL ni en todos los directorios temporales.
Para el modo nativo, `--web-port <puerto>` permite comprobar otro puerto; en
Docker se utiliza por defecto el puerto interno 8000, aunque el puerto
publicado en el host sea distinto. `--json` produce resultados estructurados.
El comando devuelve un código distinto de cero si falla una comprobación
requerida. Si Django no puede cargar la configuración, se detiene antes del
diagnóstico: corrígela localmente sin compartir su contenido.
Para PostgreSQL se limita a tres segundos cada intento de conexión si no hay
un `connect_timeout` configurado. Este límite no cubre consultas bloqueadas:
si el diagnóstico se queda esperando, revisa PostgreSQL y el estado de Docker
sin reiniciar ni eliminar servicios o volúmenes en uso.

Cuando hay tareas periódicas configuradas, Beat aparece como **no verificado**,
no como activo ni detenido, y el diagnóstico muestra cómo comprobarlo según
el modo de ejecución. En Docker, consulta
`docker compose --profile scheduler ps beat` para comprobar el estado del
contenedor; que exista un proceso no demuestra que sus tareas programadas
hayan terminado correctamente. En modo nativo, comprueba el proceso y su
historial de sincronización por separado. Si no hay tareas periódicas
configuradas, Beat se informa como no necesario. El diagnóstico nunca lo
inicia. Si Redis está inaccesible, el estado del worker queda como desconocido;
si la base de datos falla, también el de migraciones.

Si la instalación o el diagnóstico fallan:

- **Daemon inaccesible:** comprueba `docker info` y el contexto activo de
  Docker. Arranca Docker Desktop o Engine si corresponde; no elimines datos
  para resolver un fallo de conexión al daemon.
- **Puerto ocupado:** identifica qué proceso lo utiliza antes de detener
  nada. Puedes elegir otro puerto en `.env`; comprueba también que las URL
  nativas de PostgreSQL o Redis apunten al puerto elegido. Repite la
  instalación solo cuando sea seguro recrear servicios.
- **PostgreSQL o Redis no disponibles:** consulta `docker compose ps` y los
  logs del servicio afectado. Recupera el servicio sin eliminar volúmenes y
  vuelve a ejecutar el diagnóstico. Revisa los logs localmente antes de
  compartirlos: podrían contener información sensible.

### 1.5 Actualizar o volver a una versión anterior

1. Revisa la versión, sus migraciones y la compatibilidad con los datos.
   Comprueba que no hay trabajos activos ni reservados y acuerda la ventana de
   mantenimiento; no reinicies un worker mientras analiza un activo.
2. Crea una copia protegida de la base de datos y de la configuración necesaria
   y ensaya su restauración en un entorno aislado. No publiques los archivos
   de credenciales. La copia local sin cifrar de una prueba anterior no es un
   procedimiento de backup de producción.
3. Conserva una copia o imagen identificada de la versión anterior. Prepara la
   nueva versión e instala sus dependencias mediante los scripts indicados
   arriba; aplica migraciones una sola vez. Comprueba el diagnóstico y el
   recorrido de inicio de sesión.
4. Si hay que volver atrás, evalúa primero la compatibilidad del esquema.
   Revertir la imagen no deshace migraciones; cuando sea necesario, restaura
   una copia probada mediante un procedimiento aprobado, sin sobrescribir la
   única copia ni eliminar volúmenes como método de recuperación.

Estos pasos son una guía local; falta validar un procedimiento automatizado,
cifrado y ensayado para producción.

### 1.6 Registrar un repositorio autorizado

La entrada `github.repositories` del YAML de ejemplo **no crea activos**. Los
activos y sus fuentes se registran en la base de datos desde la interfaz
autenticada o mediante la API.

El tipo de un activo existente no se puede cambiar desde la UI ni la API.
Las referencias de repositorio e imagen se validan al guardarlas, pero esto no
comprueba acceso, existencia ni autorización para un escaneo.

1. Añade a `.env` el token fino de GitHub que usará el worker:

   ```dotenv
   CICLOSEC_GITHUB_TOKEN=<token-local>
   ```

   Dale solo los permisos necesarios en el repositorio de prueba: **Contents:
   read** y **Dependabot alerts: read**. Si prefieres otro nombre de variable,
   usa ese nombre en `credential_env` al crear la fuente.
   En modo Docker, recrea el worker para que lea la nueva variable de entorno:

   ```powershell
   docker compose --profile app up -d --force-recreate worker
   ```

2. Inicia el servidor local y autentícate en el navegador; después puedes usar
   la API navegable de DRF en `/api/` o un cliente HTTP que mantenga la sesión
   autenticada.

   ```powershell
   uv run python manage.py runserver 127.0.0.1:8000
   ```

3. En **Activos → Registrar activo**, elige **Repositorio GitHub** y completa
   los datos del activo, propietario, repositorio, rama y, opcionalmente, el
   nombre de la variable del token. La interfaz guarda el activo y su fuente
   juntos; no introduzcas el valor del token en el formulario. También puedes
   editar los datos desde el detalle del activo.

   Como alternativa, crea un activo con `POST /api/assets/`. Ejemplo de cuerpo
   JSON:

   ```json
   {
     "name": "backend-prueba",
     "kind": "repository",
     "environment": "test",
     "exposure": "unknown",
     "enabled": true
   }
   ```

   Guarda el `id` de la respuesta.

4. Si utilizaste la API en el paso anterior, crea la fuente con
   `POST /api/repositories/`, usando el ID anterior y solo un repositorio
   autorizado:

   ```json
   {
     "asset": 1,
     "owner": "mi-organizacion",
     "repository_name": "repositorio-prueba",
     "ref": "main",
     "credential_env": "CICLOSEC_GITHUB_TOKEN"
   }
   ```

   Si omites `credential_env`, se usa el nombre definido por
   `github.token_env` (por defecto `CICLOSEC_GITHUB_TOKEN`). Guarda únicamente
   el **nombre** de la variable en la base; nunca el valor del token.

### 1.7 Habilitar y ejecutar escaneos

Los escaneos manuales están deshabilitados por defecto. Para la prueba local,
edita `config/ciclosec.yaml` y habilita:

```yaml
scanning:
  execution:
    allow_on_demand: true
```

Reinicia la web y el worker después de cambiar la configuración. En modo
nativo en Windows, arranca o reinicia ambos procesos y usa `solo` para el worker:

```powershell
uv run celery -A ciclosec.project.celery:app worker --loglevel INFO --pool solo
```

En Linux o macOS, usa el comando nativo sin `--pool solo`.

En modo Docker, reinicia la web y el worker para que vuelvan a leer el YAML
montado:

```powershell
docker compose --profile app restart web worker
```

Arranca el planificador de inteligencia en una tercera terminal en modo nativo:

```powershell
uv run celery -A ciclosec.project.celery:app beat --loglevel INFO
```

En modo Docker, Beat es opcional y no se inicia automáticamente:

```powershell
docker compose --profile scheduler up -d beat
```

Debe haber un worker conectado al mismo Redis/PostgreSQL que la aplicación.
Beat programa las sincronizaciones de inteligencia habilitadas; no inicies
varias instancias de Beat sobre la misma configuración.

En el dashboard (`http://127.0.0.1:8000/`), usa **Solicitar escaneo** para el
activo registrado. También puedes enviar `POST /api/scans/` con
`{"asset": <id>}`. La API valida que el activo esté habilitado y tenga su
fuente configurada antes de encolar el trabajo.

Si deshabilitas el activo antes de que empiece un trabajo en cola, el worker
lo registra como fallido sin acceder a su fuente. Si el trabajo ya se ha
iniciado, deshabilitar el activo no lo cancela; revisa su estado en Historial.

Solo se acepta una solicitud mientras no haya otro escaneo de ese activo en
cola o en ejecución. La API responde `409` con `scan_id` si ya existe uno;
el dashboard enlaza a su detalle. Una vez finalizado se puede solicitar otro.
En PostgreSQL las solicitudes concurrentes se coordinan mediante el bloqueo
del activo. SQLite no ofrece esa misma garantía de bloqueo.

Esta protección no recupera trabajos bloqueados tras una interrupción ni
confirma que una tarea en cola haya llegado al worker. Si falla el envío a
la cola, el resultado puede ser incierto: el broker podría haber recibido
la tarea. El dashboard enlaza al escaneo y, mientras siga en cola, muestra
un aviso. La API devuelve `503` con `scan_id` si el fallo se detecta antes
de responder; los metadatos de un trabajo que todavía esté en cola incluyen
`dispatch_uncertain: true`. No se guarda el mensaje interno del broker.

Si existe una transacción externa, la API puede responder `202` antes de que
se intente el envío tras la confirmación; consulta después el historial.
Un `202` no confirma que el worker haya recibido o iniciado la tarea. Si
falla el envío o una solicitud devuelve un error, revisa el escaneo y el
worker antes de actuar. No cambies manualmente el estado ni reintentes
automáticamente. Una interrupción antes del envío también puede dejar un
trabajo en cola sin este aviso; la recuperación automática sigue pendiente.

Para recuperar manualmente un trabajo que sigue **en cola y no ha empezado**,
abre su detalle en Historial, marca la confirmación y pulsa **Cancelar escaneo
en cola**. La API ofrece `POST /api/scans/<id>/cancel-queued/` con
`{"confirm": true}`. Se conserva el historial, la hora y el identificador
del usuario que lo canceló. Esta acción está disponible para cualquier usuario
autenticado, según la decisión local; los permisos por roles siguen pendientes.

La cancelación no borra el mensaje de Redis ni detiene un escaneo en curso.
Los workers actualizados descartarán cualquier entrega posterior de ese
trabajo. Si ya empezó o su estado es inconsistente, la cancelación se
rechaza; no cambies manualmente la base de datos. Para solicitar otro escaneo
hay que hacerlo explícitamente. Esta protección requiere que **todos** los
workers ejecuten la versión actual y que PostgreSQL coordine el bloqueo;
SQLite no ofrece la misma garantía concurrente. Este mecanismo no recupera
trabajos ya iniciados.

En PostgreSQL, los workers coordinan el inicio de escaneos para respetar
`scanning.execution.max_concurrent_scans`. Si no hay capacidad, el trabajo
permanece en cola y Celery vuelve a intentar reclamarlo cada diez segundos;
no se garantiza el orden de atención. Un trabajo interrumpido que siga en
ejecución ocupa capacidad hasta su recuperación. Si no se puede confirmar el
envío del reintento, se marca como entrega incierta, sin repetirlo a ciegas.
La garantía requiere que todos los workers usen la versión nueva, la misma
base PostgreSQL y el mismo límite. SQLite no ofrece el mismo bloqueo.

`scanning.execution.max_queued_scans` limita los escaneos registrados en
cola; su valor predeterminado es 50 y puede cambiarse a cualquier entero
positivo en la configuración. Los escaneos en ejecución no cuentan para
ese límite. Al llenarse, la API responde `429` y el dashboard explica que
no se creó ni envió la solicitud. Una cancelación o el inicio de un trabajo
libera capacidad; reducir el límite no elimina los pendientes existentes.

Esta protección coordina solicitudes mediante PostgreSQL; requiere que todas
las instancias web y los workers estén actualizados y compartan configuración.
SQLite no garantiza la misma coordinación. El límite cuenta registros de
escaneo, no mensajes físicos de Redis ni trabajos de inteligencia, por lo que
no constituye un límite de memoria del broker.

Historial muestra la capacidad global y los envíos sin confirmar, incluso
cuando se filtra por activo; cada trabajo afectado se señala mientras siga
en cola. La API autenticada `GET /api/scans/queue-status/` devuelve
`queued_count`, `queued_limit`, `running_count`, `running_limit`,
`delivery_uncertain_count` y `queue_full`, sin metadatos internos ni caché.
Se marca el envío inicial como pendiente desde la creación del trabajo hasta
que el broker acepta el mensaje; también se marca un error posterior de
entrega. Solo cuentan marcadores booleanos `true` en trabajos en cola.
Las cifras son una instantánea de registros de la base de datos,
no confirman la salud del broker ni del worker y pueden cambiar. Los límites
mostrados proceden de la configuración de la instancia web; todas las
instancias deben compartir la misma configuración.

Si Redis se interrumpe o reinicia, revisa **todos** los escaneos en cola,
incluso los que no tengan aviso: una aceptación anterior no demuestra que
el mensaje siga existiendo. La configuración Compose actual no garantiza
persistencia de los mensajes. Tras comprobar el estado de workers y broker,
un usuario puede cancelar un trabajo que siga en cola y solicitar otro
explícitamente; cancelar no elimina mensajes antiguos, que los workers
actualizados deben descartar. No repetir a ciegas trabajos iniciados.

Historial y el detalle distinguen la hora de solicitud de la hora de inicio;
un guion indica que no se registró inicio. El estado en curso y su antigüedad
no prueban que el worker siga activo ni que el escaneo se haya interrumpido.
Comprueba el worker y sus procesos antes de actuar.

#### Recuperar un escaneo iniciado durante mantenimiento

Este procedimiento es solo para un operador con acceso local a la base de
datos. **No detecta si un worker sigue vivo ni lo detiene**. Si un worker
antiguo o uno de sus procesos sigue activo o se reanuda, puede continuar
trabajando y sobrescribir los resultados: no ejecutes el comando hasta
comprobar la parada de todos los workers y sus procesos de escaneo en todos
los hosts. Coordina una ventana de mantenimiento; no confíes en la edad del
trabajo, el estado del broker o una única comprobación de contenedores.

1. Identifica el escaneo y la base de datos correctos; verifica que el
   trabajo realmente se interrumpió. Detén y comprueba todos los workers y
   procesos de escaneo, incluidos procesos huérfanos y workers fuera de
   Compose. Si no puedes comprobarlo, no continúes.
2. Desde una instalación actualizada y configurada para esa misma base,
   ejecuta el comando con el ID revisado y un nombre de operador, sin secretos:

   ```powershell
   uv run --no-sync python manage.py recover_interrupted_scan 123 --operator "operador" --confirm-all-workers-and-scanners-stopped
   ```

   En Compose puede usarse la imagen actualizada con
   `docker compose --profile app run --rm --no-deps -T worker python manage.py recover_interrupted_scan 123 --operator "operador" --confirm-all-workers-and-scanners-stopped`.
   Este contenedor ejecuta el comando, no un worker. No uses una imagen antigua.
3. Comprueba en Historial que el escaneo quedó fallido. La operación conserva
   su inicio y evidencia, registra la hora, el operador autodeclarado y la
   confirmación; no demuestra la causa, detiene procesos, elimina mensajes ni
   inicia otro escaneo. Rechaza estados o metadatos inconsistentes. El operador
   autodeclarado no sustituye un registro externo protegido.
4. Antes de reanudar, actualiza **todos** los workers y aplica las migraciones
   pendientes en la ventana acordada. Los workers actualizados descartarán
   reentregas de ese escaneo; un worker antiguo podría no hacerlo. Solo
   solicita otro escaneo explícitamente tras revisar la situación.

PostgreSQL serializa intentos concurrentes de recuperación; SQLite no ofrece
esa garantía. El bloqueo no protege frente a un worker que no se haya
detenido: es imprescindible la comprobación operativa anterior.

Si una tarea se entrega de nuevo después de haber reclamado el escaneo, el
worker no vuelve a acceder al activo y registra la entrega duplicada. El
resultado de esa tarea indica `disposition: already_claimed` y el estado
registrado; `running` no significa que el escaneo haya terminado. Consulta
el estado del escaneo en Historial o en la API, no solo el resultado de
Celery: una entrega duplicada puede figurar como exitosa mientras el escaneo
original aún está en curso, incluso con el mismo identificador de tarea.
La reentrega no recupera un trabajo cuyo worker se haya interrumpido:
puede permanecer en ejecución hasta que el operador realice el procedimiento
de mantenimiento anterior.

#### Programación optativa por activo

La programación está deshabilitada hasta que un usuario **staff** la autorice
para un activo. En su detalle, confirma la fuente y pulsa **Habilitar
programación**. Se solicita un primer escaneo de inmediato; se rechaza la
habilitación si el activo ya tiene uno en cola o en ejecución, si la cola
está llena o si la fuente no es válida. Para la API, consulta primero
`GET /api/assets/<id>/scan-schedule/` y revisa `source`; envía después
`POST` a la misma ruta con `{"enabled": true, "confirm": true,
"source_fingerprint": "<valor recibido>"}`. Si la fuente cambió desde la
consulta, la autorización se rechaza. La consulta requiere autenticación;
para deshabilitarla, usa `{"enabled": false}`. Solo staff puede cambiarla;
deshabilitar no cancela trabajos existentes.

Esta autorización es independiente de `allow_on_demand`: aunque los
escaneos manuales estén deshabilitados, un administrador puede autorizar
programación. Las fuentes y credenciales siguen necesitando la configuración
y permisos existentes. Beat consulta la programación cada minuto; los
intervalos `scanning.schedules.repositories` y `container_images` son
globales por tipo y se cuentan desde el último escaneo completado con éxito.
Si se omite una clave se usa `24h`. Se comparten los límites de cola y
concurrencia de los escaneos manuales. Un trabajo activo o una cola llena
aplaza la siguiente ejecución; tras una caída no se acumulan ejecuciones
atrasadas, y se admite como máximo una mientras el activo esté ocupado.

Un resultado fallido o parcial, incluso de un escaneo manual, pausa la
programación hasta que un administrador la reanude expresamente. Cancelar
el último escaneo programado también la pausa. Los cambios de fuente
realizados mediante la aplicación requieren nueva autorización, incluso si
se revierten. Los workers actualizados comparan la fuente autorizada antes
de acceder a ella; no modificues fuentes directamente en la base de datos.
Reanudar solicita de inmediato un nuevo escaneo y vuelve a rechazar si hay
otro activo o la cola está llena. Una respuesta `503` indica entrega
incierta, no un fallo seguro: consulta el historial antes de actuar.

Para utilizar esta función hay que aplicar las migraciones pendientes y
actualizar conjuntamente la web, Beat y **todos** los workers en una ventana
acordada. Un worker antiguo no garantiza la protección de la fuente.
SQLite no ofrece la misma coordinación concurrente que PostgreSQL. Las
pruebas locales con fuentes simuladas no sustituyen la aceptación en un
entorno real.

El detalle de un escaneo fallido o parcial muestra explicaciones fijas para
los diagnósticos conocidos, sin reproducir los errores o avisos internos. Las
ejecuciones antiguas y los códigos desconocidos muestran una explicación
genérica. Los registros locales pueden contener más detalles: revísalos con
cuidado antes de compartirlos. Esto no modifica las respuestas de la API.
La API de lectura de escaneos conserva su contrato anterior y puede incluir
errores, avisos y metadatos internos sin sanear. Trata sus respuestas como
sensibles y limita el acceso a usuarios de confianza.
El detalle también muestra la versión registrada de las herramientas o indica
que no está disponible; no se inventa una versión cuando no se pudo obtener.

Los procesos de escáner tienen un límite de tiempo por comando y límites
separados para stdout y stderr; las salidas normales usan un máximo de
16 MiB por flujo y algunas consultas usan límites menores. Si una salida
supera su límite, se interrumpe el proceso principal sin esperar a que
termine de llenar un bloque de lectura. Un error de lectura se informa sin
reproducir su detalle interno.

En Windows, el proceso se inicia mediante un intermediario dentro de un
Job Object antes de lanzar el escáner. Los procesos asociados se detienen
al superar el límite o al cerrar el trabajo, incluso si un hijo mantiene
abiertas las tuberías. Si Windows no permite crear o asignar el Job Object,
el escáner no se inicia. Esto no es un aislamiento de seguridad y no
controla servicios externos ni procesos ajenos al Job Object.

En Linux, cada comando comienza en una sesión y un grupo de procesos propios.
Al finalizar o superar un límite se termina ese grupo, incluidos los hijos
que permanezcan en él. Un hijo puede escapar creando otra sesión o grupo:
si conserva las tuberías, se limita la espera de limpieza y se informa el
error, pero no se garantiza su terminación. Las operaciones de grupo tampoco
son un sandbox ni controlan servicios externos.

Esta protección presupone que ningún otro componente del proceso worker
recolecta el proceso hijo del escáner. Si se detecta que ya fue recolectado,
no se envía la señal al grupo; una recolección concurrente entre la comprobación
y la señal no se puede descartar. El límite de tiempo se aplica a cada comando,
no al flujo completo, y la limpieza puede añadir espera. Supervisa los procesos
y sigue el procedimiento de mantenimiento antes de recuperar una ejecución
interrumpida.

La navegación incluye **Activos**, **Hallazgos**, **SBOM**, **Historial**,
**Inteligencia** y **API y MCP**. Desde el detalle de un activo o escaneo
puedes abrir el inventario o filtrar sus hallazgos. Un SBOM vacío no demuestra
que no existan dependencias. La página de inteligencia muestra la frescura y
los resultados registrados; no inicia sincronizaciones automáticamente.

La cobertura separa **Fuente modificada o ausente** e **Identidad desconocida**:
ninguna cuenta como escaneo reciente. Los escaneos históricos sin identidad
suficiente quedan como desconocidos; sus datos se conservan. Los trabajos en
cola, en curso o fallidos mantienen su estado correspondiente. Coincidir con
la referencia registrada no verifica que una rama o etiqueta móvil conserve
el mismo contenido. La API y MCP añaden `source_changed` y `source_unknown`
a los contadores de cobertura.

En el inventario SBOM se conserva la consulta de escaneos históricos. El
dashboard indica si la fuente de ese SBOM coincide con la actual, cambió o
es desconocida; la API y MCP devuelven respectivamente `source_status` como
`matched`, `changed` o `unknown`. Sin SBOM, el valor es `null`. Esta
comparación no confirma que la rama o etiqueta mantenga el mismo contenido.

Los hallazgos y sus conteos incluyen ejecuciones históricas. El dashboard
muestra la comparación de su fuente con la actual; la API y MCP la exponen
como `asset_source_status` (`matched`, `changed` o `unknown`). Una referencia
coincidente no prueba que el hallazgo siga vigente ni que se haya corregido.

Comprueba el resultado en:

- Dashboard: `/`
- Historial: `GET /api/scans/`
- Capacidad global de escaneos: `GET /api/scans/queue-status/`
- Hallazgos: `GET /api/findings/`
- SBOM normalizado: `GET /api/assets/<id>/sbom/`
- Cobertura, activos, escaneos, hallazgos y frescura: `GET /api/dashboard/`

El escaneo de repositorio usa Trivy y OSV-Scanner; Dependabot puede quedar
parcial si GitHub no está disponible o el token carece del permiso requerido.
La consulta de Dependabot rechaza redirecciones y enlaces de paginación ajenos
al endpoint esperado; el rechazo también deja el resultado parcial.
La descarga del repositorio acepta la redirección inicial solo a
`codeload.github.com`, sin reenviar el token, y rechaza redirecciones
posteriores; si esto ocurre, el checkout falla.
El flujo completo sigue necesitando red para descargar el repositorio y
consultar Dependabot. Con el modo de bases locales desactivado, la
documentación de OSV-Scanner 2.7.1 indica que puede enviar a `osv.dev` nombres,
versiones, ecosistemas y huellas de archivos; la resolución de dependencias
puede consultar `deps.dev` y registros de paquetes. OSV indica que no envía
código fuente. Trivy 0.76.2 puede descargar bases desde registros OCI,
consultar Maven Central para identificar paquetes Java y contactar
`check.trivy.dev` para telemetría y comprobaciones de versión. GitHub recibe
el token en sus peticiones API; la descarga desde `codeload.github.com` no
lo reenvía. Son destinos documentados, no una medición exhaustiva del tráfico.
Consulta la [privacidad de OSV-Scanner 2.7.1](https://github.com/google/osv-scanner/blob/v2.7.1/README.md#data-sources-and-privacy),
la [conectividad de Trivy 0.76.2](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/air-gap.md)
y su [documentación de telemetría](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/telemetry.md).

El worker exige autorización global explícita para escanear repositorios.
`scanning.execution.repository_scanner_use_local_databases` configura OSV-Scanner
en modo `--offline` y Trivy sin actualizaciones de base, consultas Maven,
comprobación de versiones ni telemetría. Hace falta haber preparado las bases
locales de antemano. CicloSec no valida su antigüedad y marca estos escaneos
como parciales. El checkout del repositorio y Dependabot aún acceden a GitHub;
no es un modo de red aislado.

La opción `scanning.execution.allow_repository_scanners_with_network` está
desactivada por defecto. Sin ella, un escaneo de repositorio falla antes del
checkout y de ejecutar los escáneres. Para habilitarla en la configuración
local, solo después de autorizar las posibles transmisiones para **todos** los
repositorios de ese worker:

```yaml
scanning:
  execution:
    allow_repository_scanners_with_network: true
```

No es un cortafuegos ni limita destinos o datos; no afecta a imágenes ni a
otras conexiones. Si falta la autorización en web, la API rechaza nuevas
solicitudes y activaciones con HTTP 403 y código
`repository_scanner_network_not_authorized`. Si falta en Beat, una
programación vencida se pausa y requiere reanudación explícita. El worker
comprueba independientemente los trabajos ya encolados y los rechaza antes del
checkout. Actualiza y configura web, Beat y todos los workers: cada proceso lee
su propia configuración y web no puede comprobar la del worker. Los procesos
ya iniciados no quedan aislados.
Si una respuesta de Trivy contiene tipos inválidos en las listas de
vulnerabilidades o secretos, se rechaza ese resultado: el escaneo de
repositorio queda parcial y conserva el SBOM y los demás hallazgos válidos.
El SBOM generado se valida antes de iniciar los escáneres opcionales o
consultar Dependabot. Si es inválido, el escaneo falla sin ejecutar esas
etapas; la propia generación del SBOM aún puede usar la red.
El historial de nuevas ejecuciones registra proveedor, propietario,
repositorio y ref originales, sin credenciales. Si al terminar la fuente ya
no coincide, el checkout y Dependabot siguen usando la configuración original
y el resultado queda parcial con un aviso en el detalle. No se detecta una
edición intermedia que se haya revertido antes de terminar.
La ref registrada puede ser móvil: no equivale a un SHA de commit verificado.
Las ejecuciones anteriores pueden carecer de esta identidad.
El SBOM de repositorio solicita a Trivy incluir dependencias de desarrollo en
los ecosistemas que admite. Trivy puede no identificar su alcance en el
CycloneDX; no interpretes un alcance desconocido como dependencia de
producción. Esto no modifica las opciones del escaneo de vulnerabilidades de
Trivy. Los manifiestos sin versiones resueltas pueden seguir sin generar un
inventario completo.
Un fallo al generar el SBOM requerido marca el escaneo como fallido. Un
escaneo completo con cero hallazgos no significa que el activo esté protegido
si la cobertura o la inteligencia están incompletas o atrasadas.

### 1.8 Sincronización de inteligencia

Beat ejecuta las tareas con sus cadencias configuradas. Para comprobar los
proveedores, consulta el panel o la respuesta de `GET /api/dashboard/`.
Un usuario activo con permisos de administrador puede solicitar la actualización
de todos desde **Inteligencia**, confirmando que se contactarán fuentes
externas. La API ofrece `POST /api/intelligence/sync/` con
`{"confirm": true}` y `GET /api/intelligence/sync/` para consultar la última
solicitud manual por proveedor. La respuesta `202` indica envío, `409` una
solicitud ya activa y `503` un estado no verificable o una entrega incierta;
comprueba los resultados individuales antes de repetir. La solicitud no
garantiza que las fuentes se actualicen ni que su cobertura sea completa.
También puede habilitarse expresamente la acción en MCP; consulta [MCP.md](MCP.md).
La escritura y los workers de inteligencia requieren PostgreSQL; SQLite no
ofrece esta coordinación. Aplica las migraciones y actualiza web, Beat y
**todos** los workers conjuntamente antes de habilitar estas acciones. Un
estado parcial manual puede corresponder al primer lote: consulta también las
sincronizaciones posteriores. Si un envío o continuación queda sin confirmar,
investiga antes de repetir; no se libera automáticamente por antigüedad.

Las entregas Celery coordinan cada proveedor mediante un bloqueo transaccional
en PostgreSQL. Las llamadas directas a funciones del proveedor o a `.run()`
no ofrecen la misma garantía; no las uses simultáneamente con workers. Si se
pierde la conexión, el proceso anterior podría seguir activo aunque su
transacción ya no pueda confirmar cambios.
También puedes solicitar una sincronización manual desde una consola con el
worker activo; por ejemplo:

```powershell
uv run celery -A ciclosec.project.celery:app call ciclosec.intelligence.tasks.sync_cisa_kev_task
```

Los proveedores consultan servicios externos y requieren salida de red. NVD y
GitHub tienen cobertura histórica reciente. EPSS descarga el catálogo público y
filtra localmente los CVE conocidos sin transmitir su lista; su integridad y
cobertura no están verificadas y las puntuaciones ausentes se conservan. Una
continuación puede leer otra versión diaria del catálogo. Los resultados no
representan un catálogo global completo. La reevaluación actualiza hallazgos
sobre SBOM guardados, sin volver a ejecutar escáneres.

#### Revisar y revertir equivalencias

Cuando un aviso OSV declara alias ya asociados a vulnerabilidades distintas,
CicloSec puede agruparlas sin borrar las identidades ni mover sus referencias.
La decisión registra el aviso, la ejecución, los integrantes y una instantánea
de sus alias, avisos y hallazgos. Si hay varios CVE distintos o se intenta
repetir una equivalencia previamente revertida, la importación se detiene para
revisión en lugar de fusionar automáticamente.

Con la migración aplicada, inspecciona el historial y sus dependencias:

```powershell
docker compose exec -T worker python manage.py vulnerability_merges
docker compose exec -T worker python manage.py vulnerability_merges --show 1
```

El detalle muestra como máximo 100 participantes, su número total y las
cantidades de referencias registradas y actuales. La información completa
permanece en la base de datos.

Para revertir una decisión revisada, usa su ID y proporciona operador y motivo:

```powershell
docker compose exec -T worker python manage.py vulnerability_merges --reverse 1 --operator "operador" --reason "motivo de la revision"
```

La reversión y la reevaluación de los hallazgos afectados son transaccionales.
Se rechaza si existen fusiones posteriores activas o si han cambiado las
referencias desde la instantánea, incluso si el cambio podría ser legítimo;
revisa esas dependencias antes de intervenir. No hay una opción de reversión
forzada. El nombre del operador es autodeclarado en la consola; el historial
local no sustituye un registro externo protegido contra manipulaciones.

### 1.9 Prueba opcional de imágenes Docker locales

Solo usa imágenes locales de prueba y habilita el acceso al daemon de Docker
explícitamente. No montes ni expongas el socket de Docker para hacer esta
prueba desde un contenedor.

1. Descarga o construye explícitamente una imagen de prueba autorizada y
   confirma que está presente localmente:

   ```powershell
   docker image inspect nginx:1.27
   ```

2. En `config/ciclosec.yaml`, configura el permiso general y la allowlist:

   ```yaml
   scanning:
     execution:
       allow_on_demand: true

   docker:
     enabled: true
     allow_local_daemon: true
     images:
       - reference: nginx:1.27
   ```

3. Registra un activo por `POST /api/assets/`:

   ```json
   {
     "name": "nginx-prueba",
     "kind": "container_image",
     "environment": "test",
     "exposure": "unknown",
     "enabled": true
   }
   ```

4. Crea la fuente por `POST /api/container-images/`, sustituyendo `asset` por
   el ID devuelto y usando la referencia exacta de la allowlist:

   ```json
   {
     "asset": 2,
     "image_reference": "nginx:1.27"
   }
   ```

5. Solicita el análisis desde el dashboard y confirma el resultado por digest.

CicloSec exige que la imagen esté ya en el daemon local y restringe Trivy a la
fuente Docker local. La configuración concede al proceso acceso al daemon, que
es una capacidad privilegiada; desactívala al terminar la prueba.

Al cambiar la referencia de imagen o reasignar su fuente a otro activo se
eliminan el digest y la fecha anteriores. Los escaneos históricos conservan su
referencia y digest originales. Si la fuente cambia durante un escaneo, este
queda parcial con una advertencia y no asigna su digest a la fuente modificada.
Un digest anterior a esta corrección no demuestra que la referencia no haya
cambiado: vuelve a verificarlo mediante un escaneo autorizado cuando proceda.
Para instalar esta versión, sigue el procedimiento de actualización de la
sección 1.5: detén trabajos activos, aplica la migración y actualiza web y
todos los workers juntos; un worker antiguo no incorpora esta protección.

### 1.10 Pruebas y diagnóstico

Desde la raíz:

```powershell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src/ciclosec
uv run mkdocs build --strict
```

Problemas habituales:

- **GitHub indica HTTP 404 al descargar el repositorio:** comprueba el
  repositorio, la ref y el acceso del token. GitHub también puede responder
  404 cuando oculta un repositorio privado; el código no identifica por sí
  solo cuál de estas causas se produjo.
- **GitHub indica un posible límite de API:** espera y revisa los límites de
  la cuenta antes de solicitar otra operación. No se reintenta automáticamente.
- **Dependabot indica HTTP 403:** comprueba por separado que las alertas estén
  habilitadas y que el token tenga acceso; el código no confirma la causa. Si
  el análisis del repositorio terminó, se conserva como parcial con su SBOM.
- **No se lee `config/ciclosec.yaml`:** copia el ejemplo y comprueba
  `CICLOSEC_CONFIG_PATH` si usas una ruta distinta.
- **Error al conectar a PostgreSQL/Redis:** revisa `docker compose ps`, la
  salud de los servicios y las URLs/puertos en `.env`.
- **El scan permanece en cola:** confirma que Celery worker está conectado al
  mismo Redis y que tiene Trivy y OSV-Scanner en su `PATH`.
- **GitHub responde 401/403:** revisa el nombre de variable configurado y los
  permisos del token en el repositorio; no copies el token a los logs o al
  ticket.
- **Imagen no encontrada:** la imagen debe existir localmente y la referencia
  debe coincidir exactamente con `docker.images`.

## 2. Producción en Linux con Docker Compose

### 2.1 Estado actual: todavía no desplegar públicamente

El repositorio **no incluye todavía un despliegue de aplicación listo para
producción**:

- `Dockerfile` y el perfil Compose `app` son solo para desarrollo local:
  ejecutan `runserver`, no incluyen proxy TLS ni un servidor WSGI de producción.
- El perfil `scheduler` ejecuta Beat localmente; no es una configuración de
  producción con límites, cierre ordenado ni supervisión.
- Django fija `ALLOWED_HOSTS` en `localhost` y `127.0.0.1`; no hay configuración
  de hosts de producción, `CSRF_TRUSTED_ORIGINS`, cookies seguras, HSTS ni
  directorio/flujo de publicación de estáticos.
- La autenticación es la de Django; no hay alta pública, MFA ni limitación de
  intentos integrada.
- No se ha implementado ni validado un procedimiento de backup/restauración
  de producción.

`application.environment: production` desactiva `DEBUG`, pero **no resuelve
estos bloqueos**. `runserver` es solo para desarrollo. No expongas el servidor
de desarrollo, PostgreSQL, Redis o el daemon Docker a Internet.

### 2.2 Pasos requeridos antes de un despliegue

1. **Preparar la aplicación para producción.** Crear una imagen endurecida
   distinta de la imagen local y fijar un servidor WSGI. Mantener versiones
   controladas de Trivy/OSV-Scanner. Separar servicios `web`, `worker` y una
   única instancia `beat`, con
   healthchecks, límites de recursos, cierre ordenado y logs operativos
   redactados.
2. **Completar la configuración de Django.** Hacer configurables y validables
   `ALLOWED_HOSTS` y los orígenes CSRF; habilitar cookies seguras y políticas
   HTTPS detrás de un proxy confiable; servir estáticos de forma explícita.
   Revisar `python manage.py check --deploy` y resolver sus avisos antes de
   publicar.
3. **Diseñar el Compose de producción.** Mantener PostgreSQL y Redis en una red
   interna, sin puertos publicados al host. Publicar solo el proxy inverso
   HTTPS (80 únicamente para redirección, si se decide). No reutilizar el
   Compose local sin revisar redes, volúmenes, imágenes, puertos y permisos.
4. **Restringir acceso y secretos.** Poner la aplicación detrás de VPN,
   allowlist de red o un mecanismo de identidad aprobado para usuarios
   internos. Provisionar `CICLOSEC_DJANGO_SECRET_KEY`, credenciales de DB/Redis
   y tokens GitHub fuera del repositorio, con acceso mínimo y rotación. Un
   archivo de variables local no debe quedar dentro de la imagen ni bajo
   control de versiones.
5. **Aislar los workers.** Aplicar límites de CPU/memoria/tiempo, espacio
   temporal y egress permitido a los escaneos. No montar el socket Docker del
   host por conveniencia: su acceso equivale a privilegios elevados. Definir
   un modelo explícito y aprobado antes de escanear imágenes en producción.
6. **Definir continuidad operativa.** Establecer retención y capacidad para
   SBOM/base de datos, copias cifradas de PostgreSQL, monitorización de colas y
   sincronizaciones, alertas, actualización de imágenes y restauraciones
   ensayadas. No considerar un backup válido hasta probar su restauración.
7. **Validar un entorno de staging.** Usar datos/secretos de staging,
   `DEBUG=False`, dominio de prueba y TLS; migrar con una única tarea
   controlada, ejecutar un recorrido de activo autorizado → scan → SBOM →
   hallazgo → reevaluación y ensayar backup/restore y rollback.
8. **Aprobar la salida a producción.** Confirmar controles de red/autenticación,
   `check --deploy`, migraciones, healthchecks, límites de escaneo, registros
   sin secretos, restauración probada y responsables operativos. Hasta completar
   estos criterios, el destino admisible es local o un staging aislado, no una
   instalación pública.

Cuando la imagen y el Compose de aplicación existan, documenta sus comandos
reales de build, migración y rollout aquí; no copies comandos de desarrollo
como procedimiento de producción.

## 3. Pendientes conocidos

- La aceptación end-to-end con GitHub privado y Dependabot sigue pendiente.
  Selecciona un repositorio autorizado y configura el token localmente.
- La cobertura histórica/global de NVD/GitHub y la cobertura global de EPSS
  son parciales.
- La fase de despliegue/operación de producción aún no está implementada ni
  validada.
