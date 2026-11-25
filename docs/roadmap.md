# Roadmap de CicloSec: de uso local completo a producción

## 1. Objetivo y forma de trabajo

Este es el **único roadmap activo**. La meta es que una persona autorizada
pueda instalar, configurar y utilizar CicloSec sin depender de operaciones
manuales ocultas: registrar activos, analizar lo autorizado, comprender y
gestionar los resultados, consultar la API y MCP, mantener los datos al día y
recuperarse de fallos. Después se preparará una operación de producción
controlada.

«100 % usable» significa que se cumplen los criterios de aceptación de este
documento **para el alcance aprobado**, no que el sistema detecte todas las
vulnerabilidades, cubra todos los ecosistemas o garantice seguridad absoluta.
Cada integración debe indicar qué soporta, qué no ha podido analizar y cuándo
sus datos están desactualizados.

- **Hito L — local:** Windows y Linux, instalación nativa soportada o Docker,
  una instalación de un solo equipo y activos autorizados.
- **Hito P — producción:** despliegue Linux/Compose endurecido, staging y
  operación multiusuario dentro del modelo de acceso que se apruebe.
- MCP es **local y de solo lectura** por defecto. Se aprobó únicamente la
  actualización de inteligencia con habilitación explícita y autenticación de
  administrador; un MCP remoto u otras escrituras requieren otra decisión.
- Infraestructura/SSH y registros remotos de imágenes no se prometen como
  incluidos: primero se debe aprobar su alcance y aislamiento. Los parámetros
  existentes en la configuración no demuestran que estén implementados.
- Un paso está **terminado** solo si pasa sus pruebas, cumple su aceptación,
  actualiza la documentación y registra evidencia saneada. Si falla, se
  detiene y se corrige antes de continuar con pasos dependientes.

**Prioridades:** P0 bloquea el hito correspondiente; P1 completa una
capacidad incluida y se aborda antes de aceptarlo; P2 es una ampliación
opcional, no un requisito escondido. Los límites de carga indicados abajo son
objetivos iniciales verificables, no garantías actuales: deben aprobarse o
ajustarse con mediciones antes de la aceptación.

**Orden y dependencias:** 01 fija el contrato; 02–07 construyen la operación
local; 08–12 completan datos, API, interfaz y MCP; 13–14 verifican el
recorrido completo. La puesta en producción 15–18 requiere el hito L y sus
propias puertas. Algunos pasos pueden desarrollarse en paralelo, pero no
aceptarse antes de sus dependencias.

## 2. Punto de partida conocido — 22/11/2026

| Área | Existe hoy | Falta comprobar o completar |
|---|---|---|
| Instalación | Scripts PowerShell/Bash, Docker local, PostgreSQL, Redis y escáneres verificados. | Repetibilidad multiplataforma, diagnóstico y recuperación ante fallos; producción no está preparada. |
| Activos y API | Activos, fuentes GitHub/imágenes, escaneos, hallazgos, SBOM y resumen autenticados. | Contratos completos, permisos adecuados, paginación/filtrado coherentes y automatización externa documentada. |
| Escáneres | Trivy y OSV-Scanner para repositorios; imágenes locales con opt-in y allowlist; Dependabot de lectura. | Aceptación de repositorio privado/Dependabot, límites y recuperación de trabajos, imágenes reales autorizadas y transparencia de cobertura. |
| Inventario | CycloneDX/SPDX, persistencia, componentes y relaciones; Trivy solicita dependencias de desarrollo admitidas. | Versiones no resueltas y alcance de desarrollo pueden ser desconocidos; contrastar inventario y exportación con casos reales. |
| Inteligencia y riesgo | CISA, OSV, GitHub, NVD y EPSS; riesgo explicable; agrupación OSV reversible en base de datos. | Cobertura y actualización parciales; optimizar OSV y validar recuperación, revisión y reversión con datos reales controlados. |
| Dashboard | Panel, activos, hallazgos, SBOM, historial, inteligencia e integraciones; alta/edición y escaneo bajo demanda. | Completar recorridos y acciones acordadas, estados de error, accesibilidad y pruebas de navegador. |
| MCP | Seis herramientas de consulta por stdio, límites de página y opt-in. | Aceptación con cliente real, calidad del contrato y tratamiento explícito de permisos, errores y datos. |
| Operación | Copia local de PostgreSQL restaurada de prueba; web/worker locales. | Backups cifrados, recuperación operativa, monitorización, aislamiento y despliegue de producción. |

Evidencia local: `SkyEvents@main` produjo en el escaneo 41 un SBOM de 74
componentes, de los que 73 eran paquetes npm; siete de once hallazgos se
asociaron a componentes. El resultado fue parcial: GitHub indicó que las
alertas Dependabot estaban deshabilitadas. El SBOM anterior de ese activo
estaba vacío porque Trivy omitía dependencias de desarrollo. Estos números
son una muestra, no una garantía de cobertura. El último lote real OSV
procesó 200 rutas y 198 avisos únicos; quedó parcial y no incluyó el conflicto
de alias que originó la implementación de fusión. No iniciar cadenas de
sincronización ni escaneos adicionales sin definir alcance.

La guía de uso actual está en [IMPLEMENTATION.md](IMPLEMENTATION.md); la
arquitectura en [ARCHITECTURE.md](ARCHITECTURE.md), el desarrollo en
[DEVELOPMENT.md](DEVELOPMENT.md) y MCP en [MCP.md](MCP.md).

## 3. Pasos para el hito L: uso local completo

### 01. Definir alcance, roles y recorrido de aceptación — P0

**Depende de:** ninguno.

**Hacer**
1. Acordar qué usuarios habrá en local, qué pueden leer o modificar y quién
   puede solicitar escaneos, sincronizaciones, reversión o exportaciones.
2. Fijar repositorio público y privado autorizados, refs, repositorio con
   lockfile y caso de Dependabot habilitado. Añadir una imagen local de prueba
   solo si se aprueba el acceso al daemon.
3. Decidir qué ecosistemas, plataformas y formatos se aceptan; distinguir
   capacidades soportadas, experimentales y fuera de alcance. Mantener por
   defecto las funciones de alto riesgo desactivadas.
4. Acordar si se necesitan gestión de hallazgos, notificaciones y
   sincronización manual desde UI; fijar su comportamiento y auditoría antes
   de implementarlos. El objetivo mínimo de este roadmap los contempla, pero
   cualquier exclusión debe quedar expresamente aprobada.

**Pruebas:** revisar una matriz usuario → acción → permiso y una matriz
activo/formato → resultado esperado, incluido acceso denegado.

**Errores y cautelas:** credenciales con permisos excesivos; confundir
configuración existente con funcionalidad; realizar escaneos o enviar datos a
proveedores sin autorización. No pedir ni registrar valores de secretos.

**Cierre:** alcance y criterios de L escritos, sin decisiones críticas
pendientes; las decisiones de P quedan separadas.

#### Decisiones del hito local — 22/11/2026

Las siguientes decisiones describen **comportamiento objetivo**, no permisos
ni capacidades ya implementados. Deben aplicarse y probarse en los pasos
correspondientes. El modelo multiusuario de producción se decidirá en el
paso 15.

**Roles y permisos previstos**

| Acción | Sin autenticar | Lector | Operador | Administrador |
|---|---|---|---|---|
| Iniciar sesión | Sí | Sí | Sí | Sí |
| Consultar panel, activos, historial, componentes, hallazgos y frescura | No | Sí | Sí | Sí |
| Crear, editar, habilitar o deshabilitar activos y fuentes | No | No | Sí | Sí |
| Solicitar escaneo o sincronización manual autorizada | No | No | Sí | Sí |
| Revisar, asignar o registrar decisiones sobre hallazgos | No | No | Sí | Sí |
| Exportar un SBOM completo | No | No | Sí | Sí |
| Administrar usuarios, credenciales y canales de notificación | No | No | No | Sí |
| Revertir una equivalencia de vulnerabilidades | No | No | No | Sí |

- Los permisos se comprobarán **en el servidor**, tanto en API como en UI.
  Ocultar botones no constituye control de acceso. Consultar componentes no
  concede automáticamente permiso para descargar el SBOM completo.
- La gestión de activos por el operador no incluye borrar historiales ni
  eliminar datos de forma irreversible; la política de borrado debe definirse
  y aprobarse en el paso 09.
- Las decisiones humanas sobre hallazgos conservarán usuario, fecha, motivo e
  historial; no cambiarán silenciosamente la evidencia técnica. Las
  reversiones requerirán motivo y conservarán los bloqueos de seguridad.
- El MCP actual funciona como proceso local por stdio y no implementa esta
  matriz de roles. Su control de acceso deberá diseñarse y verificarse en el
  paso 11; es de solo lectura por defecto salvo la actualización de
  inteligencia optativa y no se expone por red.
- **Estado actual:** la aplicación exige autenticación, pero esta matriz de
  roles aún no está implementada ni validada. No debe asumirse que un lector
  existente ya tenga estas restricciones.

**Activos y cobertura de aceptación**

| Caso | Objetivo para L | Estado y límites |
|---|---|---|
| Repositorio público con lockfile | `slopeztech/SkyEvents@main`; verificar componentes y hallazgos. | Ya se obtuvo un SBOM real; se deberá repetir el recorrido integral. |
| Repositorio privado | Uno autorizado con su ref definida antes de probarlo. | **Pendiente de elección**; registrar su identidad solo donde corresponda y no publicar tokens. |
| Dependabot | Repositorio de prueba con alertas habilitadas y token de lectura mínimo. | **Pendiente**; SkyEvents devolvió 403 porque las alertas estaban deshabilitadas. |
| Imagen local | Incluirla con opt-in, allowlist, daemon autorizado y digest inmutable. | Identidad y aprobación para una imagen de prueba aún pendientes; no acceder al daemon automáticamente. |
| Registro remoto / infraestructura SSH | Fuera del hito L salvo aprobación posterior de alcance y aislamiento. | No se consideran implementados por aparecer en la configuración. |

El usuario ha autorizado el análisis de sus repositorios. Esa autorización no
selecciona por sí sola el repositorio privado, la ref ni un alcance ilimitado
de trabajos. Cada prueba deberá identificar previamente qué se analiza; no
iniciar escaneos programados ni importaciones masivas por defecto.

**Ecosistemas mínimos que deberán probarse**, sin afirmar soporte actual:
npm, Python/PyPI, Maven/Java, NuGet/.NET, Go, Composer/PHP, RubyGems,
Cargo/Rust y paquetes del sistema operativo. Para cada uno se necesita al
menos un inventario con versiones resueltas, un caso de afectación y uno de
no afectación, identificación de cobertura y evidencia reproducible. Para
paquetes del sistema operativo se identificará distribución y versión; si
faltan datos, la afectación quedará pendiente, no confirmada por suposición.
La lista es un mínimo de aceptación ampliable; el soporte de versiones y
rangos se documentará por ecosistema.

**Formatos mínimos de importación y exportación para L:**

| Familia y formato | Objetivo verificable | Situación actual |
|---|---|---|
| CycloneDX JSON | Versiones 1.0–1.7; conservar la compatibilidad existente. | Soporte implementado; requiere aceptación de extremo a extremo. |
| CycloneDX XML | Al menos versiones 1.5–1.7. | Desarrollo y validación pendientes. |
| SPDX 2.x JSON | Versiones 2.2 y 2.3. | Soporte implementado; requiere aceptación de extremo a extremo. |
| SPDX 2.x tag-value | Versiones 2.2 y 2.3. | Desarrollo y validación pendientes. |
| SPDX 3 JSON-LD | Versión 3.0. | Desarrollo y validación pendientes; comprobar herramientas y esquema antes de elegir implementación. |

Para cada formato y versión aceptados se probarán archivos válidos e
inválidos, límites, importación, persistencia, exportación y preservación de
los datos y relaciones que el formato permita. No se prometerá una conversión
sin pérdida cuando los modelos no sean equivalentes: se deberán informar las
pérdidas o rechazar la operación. «Todos los posibles» se tratará como
cobertura ampliable y documentada; esta tabla fija el mínimo comprobable,
no una afirmación de soporte universal.

**Funciones operativas incluidas para L**

1. Gestión y revisión de hallazgos con historial, motivos y permisos; no
   borrar ni sobrescribir la evidencia de escaneo.
2. Sincronización manual desde UI y API, con selección de fuente, confirmación
   y límites explícitos; el operador podrá solicitarla y el administrador
   podrá configurar las integraciones. Una solicitud debe mostrar progreso,
   resultado parcial y errores. OSV requiere definir el presupuesto de lotes
   antes de ejecutarlo.
3. Notificaciones configurables en **interfaz, correo y webhook**. Para cada
   canal se definirán eventos, destinatarios, prueba, fallo y reintento; los
   canales externos estarán desactivados hasta configurarse y autorizarse.
   Estos son los canales mínimos, no todos los canales imaginables.
4. Instalación nativa soportada y Docker en Windows y Linux, con
   dependencias automáticas y límites de arquitectura documentados. No
   declarar soportada una combinación hasta probarla.
5. Se mantendrán confidenciales las credenciales, el código y los datos
   privados. Las integraciones externas deben indicar los metadatos que
   transmiten y respetar los límites de privacidad; si no pueden hacerlo,
   se desactivan y se muestra cobertura parcial.

**Revisión de matrices y condiciones de aceptación**

- Confirmar, por cada fila de la matriz de roles, un caso permitido y otro
  denegado en API y UI; comprobar acceso anónimo, CSRF, exportaciones y
  reversiones. Verificar que MCP no puede escribir salvo la actualización de
  inteligencia explícitamente habilitada y autorizada.
- Para cada activo y formato de la tabla, validar un caso válido y otro
  inválido o sin permiso, sin borrar datos ni exponer secretos. Para cada
  ecosistema, conservar evidencia de afectación y no afectación.
- El caso privado, el caso Dependabot habilitado y la imagen concreta siguen
  sin seleccionarse; deben fijarse antes de sus pruebas. La aprobación de
  formatos adicionales y del modelo de producción no se presupone.

**Estado del paso 01: en curso.** Las decisiones anteriores quedan
documentadas; no se puede marcar como cerrado mientras no se elijan el
repositorio privado/ref, el caso Dependabot habilitado y la imagen local
autorizada para aceptación, ni se revisen las matrices con esos casos.

### 02. Instalación, actualización y diagnóstico local — P0

**Depende de:** 01.

**Hacer**
1. Validar instalación limpia y repetida en Windows, Linux y Docker; documentar
   arquitecturas soportadas y prerrequisitos reales, incluido Docker.
2. Comprobar versiones y checksums, espacio, puertos, daemon y configuración;
   mostrar qué se instaló y cómo resolver cada fallo. La instalación no debe
   sobrescribir secretos ni datos existentes.
3. Añadir una comprobación de salud que diferencie web, base de datos, Redis,
   worker, escáneres, migraciones y Beat; ofrecer instrucciones sin exponer
   credenciales. Documentar actualización y rollback de versión.

**Pruebas:** instalación limpia y segunda ejecución; reinicio del PC;
dependencia ausente, descarga/checksum fallido, puerto ocupado, Redis o
PostgreSQL caído y configuración inválida. Ejecutar en cada plataforma
declarada y guardar versiones y resultados.

**Errores y cautelas:** no borrar volúmenes para arreglar contraseñas; no
confundir Docker instalado con daemon operativo; no afirmar soporte de
Windows ARM nativo sin validar binarios.

**Cierre:** una persona siguiendo la guía puede instalar, actualizar,
diagnosticar y reiniciar sin perder datos ni compartir secretos.

**Avance — 22/11/2026:** se ha añadido el comando de diagnóstico local
`ciclosec_doctor` para base de datos, migraciones, Redis, worker, web,
escáneres y espacio del sistema de archivos del proceso. No inicia trabajos;
el estado de Beat se informa como no verificado. La guía de
[implementación](IMPLEMENTATION.md#14-diagnostico-local-sin-iniciar-trabajos)
incluye su uso y pautas de actualización y rollback. El paso permanece en
curso: faltan las pruebas de instalación limpia y repetida en Windows, Linux
y Docker, recuperación ante fallos y verificación de reinicio del equipo.
Tras liberar espacio y reiniciar Docker, se restauraron los servicios y se
verificó el diagnóstico nativo en Windows y en un contenedor temporal de la
imagen reconstruida; ambas ejecuciones finalizaron correctamente. El worker
activo conserva su imagen anterior, por lo que la prueba de la imagen nueva
no confirma que se haya actualizado ese servicio. Beat no se verificó ni se
inició. Esto no sustituye las pruebas de instalación y recuperación pendientes.

**Prueba aislada — 22/11/2026:** el instalador PowerShell en modo Docker se
ejecutó dos veces en Windows con proyecto, puertos y volumen separados. Se
comprobó que la segunda ejecución conservó `.env`, la configuración y una
marca en PostgreSQL; el diagnóstico y la página de acceso respondieron. Una
configuración con placeholders se rechazó sin sobrescribirla. La construcción
usó caché, por lo que no demuestra una instalación sin caché ni valida Linux.
La segunda ejecución recreó web y worker de la prueba.

**Prueba nativa aislada — 22/11/2026:** se instaló y repitió el modo nativo
de Windows con Python 3.12 y PostgreSQL/Redis separados. Se conservaron
configuración, datos y binarios; se validó la página de acceso. El pool
Celery predeterminado falló en Windows. Con `solo` y PostgreSQL por IPv4 se
completó una tarea de reevaluación sobre la base vacía, sin escaneos ni
sincronizaciones. Se actualizó el valor para nuevas instalaciones y la guía;
las configuraciones existentes no se sobrescriben. Aún faltan pruebas de
escaneo autorizado y de recuperación real del worker nativo.

**Fallos del instalador — 23/11/2026:** se ha corregido la sustitución de
escáneres para verificar el nuevo binario antes de reemplazar el anterior y
prepararlo en el mismo sistema de archivos. Se probaron errores simulados de
descarga, checksum, ejecución, tiempo de espera y versión, además de
instalaciones reales de ambos escáneres en Windows y en un contenedor Linux
temporal. Esto último no valida el script completo de instalación en Linux.

**Recuperación aislada — 23/11/2026:** en Windows con proyecto y volumen
Docker independientes se comprobó que un puerto PostgreSQL ocupado aborta
la instalación y que, al liberarlo, una segunda ejecución conserva la
configuración y arranca correctamente. También se simuló un daemon
inaccesible sin detener el daemon real. Con PostgreSQL detenido, el
diagnóstico indicó base de datos fallida y migraciones desconocidas; con
Redis detenido, indicó Redis fallido y worker desconocido. Tras restaurarlos,
el diagnóstico pasó y una marca en la base persistió; no se expusieron las
credenciales de prueba. Quedan pendientes otras plataformas y reinicio del PC.

### 03. Activos, acceso a GitHub e imágenes — P0

**Depende de:** 01–02.

**Hacer**
1. Completar alta, edición, habilitación/deshabilitación y consulta de
   repositorios e imágenes, con validación consistente entre UI y API.
2. Comprobar acceso de solo lectura al repositorio y a Dependabot por
   separado; distinguir credencial ausente, ref inexistente, HTTP 401/403,
   alertas deshabilitadas y límite de API. Solo almacenar la referencia a la
   credencial, nunca su valor.
3. Para imágenes, mantener opt-in, allowlist e identidad inmutable; decidir
   y documentar explícitamente si se soportan registros remotos. No montar el
   socket Docker por conveniencia.

**Pruebas:** alta/edición, duplicados, ref incorrecta, token sin permiso,
repositorio privado autorizado, activo deshabilitado, imagen inexistente y
fuera de allowlist; revisar que errores y registros no revelen secretos.

**Errores y cautelas:** un 403 no identifica por sí solo si faltan permisos o
si Dependabot está deshabilitado; una etiqueta de imagen puede cambiar de
contenido.

**Cierre:** activo y fuente se ven y validan desde UI y API, sin credenciales
expuestas; prueba privada y Dependabot anotadas con resultado real.

**Avance:** la UI y la API validan las referencias de repositorio e imagen
con las mismas reglas usadas por los escáneres; la API ya no permite cambiar
el tipo de un activo existente. El detalle muestra la referencia de la imagen.
Al editar su referencia o reasignar su fuente se limpia el digest previo;
un escaneo que termina después de un cambio conserva su identidad histórica,
queda parcial y no actualiza el digest de la fuente modificada. La protección
requiere aplicar la nueva migración y actualizar conjuntamente web y workers.
Las pruebas aisladas usan SQLite y escáneres simulados; no sustituyen una
prueba concurrente con PostgreSQL ni la aceptación de una imagen real.
El paso continúa abierto, al igual que sus dependencias 01 y 02.

**Avance adicional:** se identifican por separado los errores HTTP del archivo
del repositorio y de Dependabot, con orientación para credenciales, permisos,
referencias y posibles límites de API, sin incorporar respuestas ni secretos
del proveedor. Un 403 o 404 no confirma la causa; Dependabot denegado mantiene
el escaneo parcial y conserva el SBOM. La verificación utiliza respuestas
simuladas; siguen pendientes las pruebas de acceso real autorizadas.

**Activos deshabilitados:** una nueva solicitud se rechaza; si se deshabilita
el activo mientras el trabajo está en cola, el worker registra el escaneo como
fallido sin consultar GitHub ni Docker. El inicio se coordina con la edición
del activo mediante bloqueo transaccional y el trabajo figura como ejecutándose
antes de acceder al repositorio. La deshabilitación no cancela un escaneo ya
iniciado. Se verificaron ambas rutas con dobles y el bloqueo con PostgreSQL
aislado; no sustituye la recuperación ni la cancelación segura del paso 04.

**Identidad del repositorio:** el checkout y Dependabot utilizan la misma
configuración capturada para la ejecución. El historial conserva proveedor,
propietario, nombre y ref sin credenciales, incluso si falla el checkout.
Si al finalizar la configuración ya no coincide con la original, se mantiene
la evidencia original y el resultado queda parcial; el detalle del dashboard
explica el cambio. No se detecta una edición intermedia que se haya revertido.
Las pruebas son simuladas y no prueban acceso real ni identifican el commit
inmutable al que apunta una ref móvil.

**Cobertura por fuente:** dashboard, API y MCP separan `source_changed`
(fuente registrada distinta o ausente) y `source_unknown` (identidad histórica
insuficiente), sin contarlos como cobertura vigente. En imágenes nuevas se
guarda la revisión de la configuración para detectar incluso cambios que se
deshacen. Un escaneo en cola, en curso o fallido conserva su estado propio.
La coincidencia de referencia no comprueba un commit ni el contenido actual
de una etiqueta de imagen; las pruebas con activos reales siguen pendientes.

**Inventario histórico:** el SBOM seleccionado conserva sus componentes y
expone en UI, API y MCP si su fuente coincide, cambió o no se puede verificar.
La comparación corresponde al escaneo seleccionado, no necesariamente al
último; una referencia coincidente no garantiza que el contenido siga igual.

**Hallazgos históricos:** los listados y el detalle indican si la fuente
registrada coincide, cambió o no se puede verificar. API y MCP exponen
`asset_source_status`; los conteos de severidad siguen incluyendo el historial.
La coincidencia no demuestra que un hallazgo continúe vigente ni resuelve la
gestión de estados prevista en pasos posteriores.

### 04. Trabajos de escaneo y recuperación — P0

**Depende de:** 02–03.

**Avance:** el detalle de escaneos parciales o fallidos muestra mensajes
predefinidos a partir de códigos persistidos, sin reproducir errores internos.
Los registros antiguos o códigos desconocidos reciben una explicación
genérica. Las pruebas usan escáneres simulados y bases SQLite y PostgreSQL
aisladas; no sustituyen la aceptación ni la recuperación de trabajos reales.
Este avance no cambia el contrato existente de la API y el paso sigue abierto.

**Solicitudes duplicadas:** API y dashboard rechazan una nueva solicitud si
el activo ya tiene un escaneo en cola o en ejecución; la API devuelve `409`
y su identificador. En PostgreSQL se bloquea el activo antes de comprobar y
crear el trabajo, y su envío se registra tras confirmar la transacción. Se
probaron solicitudes concurrentes, bloqueo y rollback con servicios simulados
y PostgreSQL aislado. SQLite no garantiza el mismo bloqueo. Esto no resuelve
trabajos atascados, entrega incierta al broker, reentregas ni recuperación:
un trabajo activo antiguo puede seguir impidiendo nuevas solicitudes.

**Envío incierto:** al crear el trabajo se registra que el envío inicial está
sin confirmar; el aviso se retira cuando el broker acepta el envío. Esto
también deja visible una interrupción tras confirmar la transacción y antes
de enviar. Ante errores de comunicación con el broker durante el
envío, se conserva el trabajo y se registra un aviso si aún está en cola;
el dashboard enlaza a su detalle y la API devuelve `503` con su identificador
si el fallo se detecta antes de responder. Si el worker ya inició el trabajo,
no se sobrescribe su estado. Un envío diferido por una transacción externa
puede fallar después de un `202`; se debe consultar el historial. Las pruebas
incluyen un broker local inaccesible, dobles y PostgreSQL aislado. No hay
recuperación automática. La aceptación del broker no garantiza que conserve
el mensaje tras una caída: incluso los trabajos sin aviso requieren revisión.

**Reentregas:** si una tarea vuelve a reclamar un escaneo ya iniciado o
finalizado, no vuelve a acceder a su fuente; registra la entrega duplicada y
devuelve el estado guardado con `disposition: already_claimed`. Los estados
inválidos y escaneos inexistentes siguen dando error. Se han probado dos
workers Celery en el mismo proceso con Redis y PostgreSQL aislados, usando
un checkout simulado y entregas con el mismo identificador de tarea. Esto
no recupera un worker interrumpido: un escaneo
puede quedar en ejecución y su reentrega no lo reinicia. El estado de la tarea
Celery no debe confundirse con la finalización del escaneo.

**Capacidad:** los workers nuevos coordinan en PostgreSQL el inicio de
escaneos para respetar `max_concurrent_scans`; si no hay capacidad, Celery
reintenta la reclamación cada diez segundos y conserva el estado en cola.
Un fallo de envío del reintento se señala como entrega incierta. Se ha
probado el bloqueo concurrente y la recuperación de capacidad con Redis,
PostgreSQL y workers aislados. Requiere migración, configuración uniforme y
actualizar todos los workers; SQLite no ofrece el mismo bloqueo. No limita
los mensajes físicos del broker ni recupera ejecuciones interrumpidas.

**Admisión de trabajos:** `max_queued_scans` es configurable y tiene un
valor inicial de 50. API y dashboard rechazan solicitudes nuevas con `429`
si se alcanza; no se crea ni envía el trabajo. PostgreSQL coordina solicitudes
simultáneas con el inicio de los workers. Se cuentan registros en cola, no
mensajes físicos de Redis ni tareas de inteligencia; no es un límite de
memoria del broker. Requiere instancias actualizadas y configuración común.

**Visibilidad de capacidad:** Historial y la API autenticada muestran
conteos globales de escaneos en cola y en ejecución, límites configurados y
envíos inciertos, incluso con filtros de activo. Se señala cada entrega
incierta aún en cola. Son instantáneas de la base de datos, no diagnósticos
de salud del broker o worker ni conteos de mensajes físicos. Los límites
proceden de la configuración web y requieren configuración uniforme.
Se han probado la capacidad y los marcadores booleanos en SQLite y
PostgreSQL aislados.

**Tiempos de ejecución:** Historial y detalle muestran por separado la
solicitud y el inicio real, si se registró. El detalle advierte que el estado
en curso no confirma que el worker siga activo. Esto facilita la inspección,
pero no detecta automáticamente interrupciones ni recupera trabajos.

**Salida de escáneres:** se detecta el exceso de stdout o stderr sin esperar
a llenar el búfer, incluso si el proceso sigue ejecutándose; un fallo de
lectura se informa de forma saneada. Se probaron ambos flujos y el límite
exacto en Windows y en un contenedor Linux aislado.

**Árbol de procesos en Windows:** cada escáner se inicia en un Job Object
mediante un intermediario que espera a ser asignado antes de lanzarlo.
Los procesos asociados se detienen al finalizar o superar un límite; si no
es posible asignar el trabajo, el escáner no se inicia. Las pruebas incluyen
hijos que heredan o cierran tuberías, un proceso ajeno y fallo de asignación.
No controla servicios externos y no sustituye un sandbox ni la verificación
operativa antes de recuperar escaneos.

**Grupo de procesos en Linux:** cada comando se inicia en una sesión propia y
se termina su grupo al completar o superar un límite. Se probaron hijos con
tuberías abiertas o cerradas y un proceso ajeno en un contenedor aislado.
Un hijo que escape del grupo no queda controlado; si retiene las tuberías,
la espera de limpieza es limitada y se informa el error. El control presupone
que ningún otro componente recolecte el hijo del escáner: se rechaza una
recolección ya detectada, pero existe una carrera entre comprobación y señal.
No es un sandbox ni sustituye la verificación operativa. Queda pendiente una
validación en un despliegue Linux real.

**Recuperación manual parcial:** un usuario autenticado puede confirmar la
cancelación de un escaneo en cola que no haya empezado, desde el detalle o la
API. El estado, la fecha y el usuario quedan registrados; la acción no elimina
mensajes del broker ni vuelve a lanzar el trabajo. El bloqueo en PostgreSQL
impide cancelar un trabajo ya reclamado y los workers actualizados descartan
entregas posteriores. Se probaron la carrera, CSRF, permisos y una entrega
pendiente en Redis aislado. Requiere actualizar todos los workers; no cancela
trabajos en ejecución ni resuelve la recuperación de workers interrumpidos.

**Recuperación sin workers:** un comando local permite marcar como fallido
un escaneo iniciado tras confirmar que todos los workers y procesos de
escaneo están detenidos. Conserva la evidencia y registra el operador
autodeclarado; no verifica ni detiene procesos, no elimina mensajes ni
relanza el trabajo. Solo es seguro durante mantenimiento verificado en
todos los hosts; antes de reanudar se deben actualizar todos los workers.
No detecta automáticamente interrupciones ni protege contra un proceso
antiguo que siga escribiendo. Se probaron operadores concurrentes y una
reentrega posterior con PostgreSQL y Redis aislados; no se ha validado la
parada real de workers ni de procesos huérfanos en un despliegue.
Una prueba adicional detiene un worker real de prueba durante una fuente
simulada, ejecuta la recuperación sin workers y comprueba que una entrega
publicada explícitamente tras el reinicio no vuelve a acceder a la fuente.
No demuestra la parada de procesos huérfanos de un despliegue real.

**Programación optativa:** solo un administrador puede habilitar o reanudar
un activo, confirmando su fuente y un primer escaneo inmediato. Se rechaza
si ya hay un escaneo activo o la cola está llena. Beat comprueba cada minuto
los activos autorizados; el intervalo se cuenta desde la finalización del
último escaneo completado. Tras una caída no acumula ejecuciones atrasadas.
Un resultado fallido o parcial pausa la programación, también si procede de
un escaneo manual; cancelar el último trabajo programado también la pausa.
Los cambios gestionados de fuente exigen nueva autorización, incluso si se
revierten; los workers actualizados no analizan una fuente distinta a la
autorizada para un trabajo en cola. Deshabilitar no cancela trabajos activos.
Requiere migraciones y actualizar web, Beat y todos los workers. Se probaron
PostgreSQL, Redis y Celery aislados con fuentes simuladas; quedan pendientes
las pruebas de aceptación reales y el paso sigue abierto.

Por indicación del usuario se posponen las pruebas de repositorio privado,
Dependabot e imagen real; no cuentan como aceptación superada.

**Pendiente de recursos y temporales:** se ha solicitado configuración
opcional de límites de CPU, memoria y disco con sugerencias detectadas por el
sistema. Aún no están implementados; los límites actuales no restringen todo
el consumo de los procesos ni el daemon Docker. También queda pendiente la
limpieza automática de restos tras interrupciones: solo debe actuar cuando
pueda verificarse que no están en uso. No se eliminan por antigüedad ni se
consideran controlados los procesos que escapen del grupo.
Por decisión del usuario se pospone este trabajo y se continúa con el paso 05;
el paso 04 permanece abierto y es una dependencia no satisfecha.

El comando `uv run python -m ciclosec.common.resource_advice --path .` ofrece
estimaciones locales inciertas: no configura, reserva ni impone límites. La
medición no incluye necesariamente otros workers ni límites ocultos.

**Reinicio del broker:** se comprobó en contenedores temporales que un
Redis sin persistencia pierde un mensaje encolado al reiniciarse mientras el
registro permanece en PostgreSQL. Un operador pudo cancelar ese trabajo sin
workers activos. La prueba no acredita recuperación automática ni garantiza
que la persistencia de otro Redis sea suficiente.

**API de escaneos:** se conserva el contrato existente por decisión del
usuario. Sus errores, avisos y metadatos pueden contener detalles internos;
la causa saneada ya se muestra en el detalle web, pero la sanitización de la
API queda pendiente de una migración compatible.

**Hacer**
1. Definir ciclo de vida visible: solicitado, en cola, ejecutándose y
   finalizado como completo, parcial, fallido o cancelado si se implementa
   cancelación segura. Persistir tiempos, herramienta, versión y causa
   saneada.
2. Evitar ejecuciones duplicadas del mismo activo, aplicar de verdad los
   límites de concurrencia configurados y hacer idempotentes los reintentos
   y la entrega de tareas. Definir recuperación tras reinicio y expiración.
3. Controlar tiempo, tamaño de salida y recursos; limpiar temporales al
   terminar o después de una interrupción. Encolar solo tras confirmar la
   transacción y explicar los errores al usuario.
4. Completar la validación operativa de la programación optativa de
   repositorios e imágenes, incluidos reinicios y fuentes autorizadas reales.

**Pruebas:** dos solicitudes simultáneas del mismo activo; dos workers;
reentrega, interrupción durante ejecución, reinicio de Redis/worker, timeout,
salida excesiva y cola llena. Verificar una sola ejecución efectiva,
transiciones válidas y ausencia de pérdida silenciosa.

**Errores y cautelas:** `acks_late` por sí solo no garantiza idempotencia;
una tarea en cola no es una tarea completada; no repetir una tarea sin revisar
su estado.

**Cierre:** límites y recuperación demostrados en PostgreSQL/Redis reales;
historial y estado observables desde UI y API.

### 05. Escáneres de repositorios y Dependabot — P0

**Depende de:** 03–04.

**Avance:** la consulta autenticada de Dependabot rechaza redirecciones y
enlaces de paginación fuera de la URL esperada; un error mantiene el resultado
parcial. Se comprobó con respuestas simuladas, sin consultar GitHub; no
sustituye las pruebas reales pendientes.

**Descarga del repositorio:** se valida la URL de `codeload.github.com` y se
rechazan redirecciones posteriores sin reenviar el token; el fallo se muestra
sin exponer la URL. La comprobación utiliza respuestas simuladas. El escaneo
actual no ofrece un modo sin red garantizado: OSV-Scanner puede enviar
metadatos de dependencias y Trivy puede consultar servicios externos.
El modo optativo de bases locales deshabilita las conexiones documentadas de
OSV-Scanner y Trivy, pero el checkout y Dependabot siguen dependiendo de GitHub.
No es un modo air-gap y los resultados se consideran parciales mientras no se
verifique la actualidad de las bases.

**Autorización global:** `scanning.execution.allow_repository_scanners_with_network`
está desactivada por defecto. Si la interfaz o API no la tienen habilitada,
rechazan nuevas solicitudes y activaciones con HTTP 403; si falta en Beat, una
programación vencida se pausa y requiere reanudación explícita. El worker
comprueba independientemente los trabajos ya encolados y los marca fallidos
antes del checkout o los escáneres si no está autorizado. Cada proceso lee su
propia configuración: actualiza y configura web, Beat y todos los workers.
Concederla habilita todos los repositorios de ese proceso, no solo uno. No
controla red ni demuestra qué datos se transmiten; faltan aislamiento y
alternativa offline. No afecta al escaneo de imágenes.

**Datos y destinos documentados:** las versiones instaladas son OSV-Scanner
2.7.1 y Trivy 0.76.2. La documentación de OSV-Scanner indica que envía a
`osv.dev` nombres, versiones, ecosistemas y huellas de archivos; para resolver
dependencias puede consultar `deps.dev` y registros de paquetes. Indica que no
se envía código fuente. Trivy puede consultar registros OCI para bases,
Maven Central para identificar paquetes Java y `check.trivy.dev` para
telemetría y actualizaciones. El cliente de GitHub usa API autenticada para
repositorio y Dependabot; la descarga de archivos se realiza aparte desde
`codeload.github.com` sin reenviar el token. Estos son destinos documentados,
no una garantía de que se haya medido todo el tráfico. El dashboard muestra
este aviso antes de las acciones de repositorio, incluso si la autorización
está desactivada.

Referencias: [privacidad OSV-Scanner 2.7.1](https://github.com/google/osv-scanner/blob/v2.7.1/README.md#data-sources-and-privacy),
[conectividad Trivy 0.76.2](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/air-gap.md)
y [telemetría Trivy 0.76.2](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/telemetry.md).

**Resultados Trivy:** los campos de vulnerabilidades y secretos con tipos
inválidos ya no se interpretan como listas vacías; el escaneo de repositorio
queda parcial y conserva el SBOM y los resultados de otras fuentes. Se ha
verificado con respuestas simuladas, no con repositorios reales.

**Resultados por fuente:** cada escaneo terminado registra en `source_results`
si el SBOM, OSV-Scanner, Trivy y GitHub Dependabot estuvieron disponibles y
cuántos hallazgos devolvieron. El detalle del escaneo muestra esa información;
un proveedor disponible con cero hallazgos se distingue de uno no disponible.
Este estado no certifica la actualidad de las bases de datos locales ni el
aislamiento de red.

**Bases locales de escáneres:** con
`scanning.execution.repository_scanner_use_local_databases: true`, OSV-Scanner
usa `--offline`; Trivy omite las actualizaciones de sus bases, llamadas de
identificación de paquetes, comprobaciones de versión y telemetría. La opción
es independiente de la autorización global, que sigue siendo necesaria para
consultar GitHub y descargar el repositorio. La falta de una base local deja su
fuente no disponible o puede hacer fallar el SBOM requerido; si está presente,
su frescura sigue sin verificarse y el resultado se marca parcial. Esto evita
presentar bases antiguas como cobertura completa, pero no ofrece aislamiento
de red.
Los directorios locales quedan configurables y el diagnóstico informa si existen
los archivos de caché OSV/Trivy. Falta demostrar la actualización mediante una
fecha o manifiesto firmado antes de poder contar una base como reciente.

**Validación operativa real realizada:** se levantaron PostgreSQL, Redis, web y
worker en Docker. Se verificaron Trivy 0.76.2 y OSV-Scanner 2.7.1 dentro del
worker. El repositorio público `slopeztech/PongWars@main` permitió generar SBOM
y ejecutar Trivy; OSV-Scanner informó que no encontró fuentes de paquetes
compatibles. El repositorio público `slopeztech/CashFlow@main` permitió
completar el SBOM y produjo 80 hallazgos normalizados de OSV-Scanner y cero
hallazgos de Trivy. Ambos resultados fueron visibles desde UI y API; Dependabot
quedó no disponible por HTTP 403 con el token configurado. El recorrido privado,
la presencia y permisos de Dependabot habilitado y la cobertura real de alertas
siguen pendientes.
El código distingue 401 como credencial, 403 como acceso/permisos y 429 como
límite de solicitudes; no interpreta HTTP 403 como ausencia de alertas ni
exhibe el token.

**SBOM requerido:** su validación se efectúa antes de iniciar los escáneres
opcionales o consultar Dependabot. Si es inválido, el escaneo falla sin
ejecutar esas etapas; la persistencia vuelve a validar el documento. Esto no
evita las posibles conexiones del propio Trivy al generar el SBOM si se
autorizan los escáneres.

**Hacer**
1. Validar checkout limitado y seguro de un repositorio público y uno privado
   autorizados, preservando ref y, si se implementa, commit real analizado.
2. Ejecutar Trivy y OSV-Scanner; distinguir error de herramienta, cobertura
   parcial y cero hallazgos. Conservar evidencia normalizada y versiones,
   nunca el secreto detectado ni el código completo.
3. Habilitar Dependabot en el repositorio de prueba y validar su lectura con
   token de permisos mínimos; explicar ausencia de alertas frente a ausencia
   de acceso. Evitar pedir o imprimir el token.
4. Documentar los metadatos de paquetes que cada proveedor externo recibe;
   exigir autorización para transmisiones externas y ofrecer una alternativa
   o estado incompleto cuando no se permita salir a la red.

**Pruebas:** repositorio con y sin dependencias, dependencia vulnerable y
control sin afectación, secreto sintético redactado, API 401/403/429,
Dependabot deshabilitado/habilitado, red caída y archivos malformados.

**Errores y cautelas:** no instalar ni ejecutar código del repositorio para
inventariarlo; un hallazgo de escáner no prueba por sí solo explotabilidad.

**Cierre:** recorrido privado y Dependabot verificados; resultados visibles,
parciales explicados y ningún secreto en respuestas o logs.

### 06. Inventario, SBOM e imágenes locales — P0

**Depende de:** 04–05.

**Hacer**
1. Contrastar CycloneDX/SPDX, importación/exportación, integridad, versiones
   resueltas y relaciones contra lockfiles representativos. Marcar los
   manifiestos sin resolver y los componentes cuyo alcance sea desconocido.
2. Mantener dependencias de desarrollo donde el escáner las soporte, sin
   presentarlas como producción si el origen no informa su alcance.
3. Permitir consultar por activo/escaneo y exportar el formato conservado;
   definir límites y permisos antes de exponer documentos completos.
4. Para imágenes locales aprobadas, validar digest real, SBOM, hallazgos,
   limpieza y aislamiento; no interpretar una imagen sin paquetes como fallo
   sin evidencia.

**Pruebas:** lockfile npm/Python y controles sin dependencias; desarrollo y
producción; checksum, grafo, versiones, formatos inválidos y límites;
imagen local de prueba y referencia no autorizada. Comparar componentes
esperados con los mostrados por API y dashboard.

**Errores y cautelas:** un SBOM vacío no demuestra ausencia de dependencias;
rangos no son versiones instaladas; exportaciones pueden contener metadatos
sensibles.

**Avance operativo realizado:** Docker Desktop y Compose están activos. Solo el
worker recibe el socket Docker y el usuario permanece como `ciclosec`; la
allowlist local contiene `bash:5.2`. La imagen fue resuelta al digest
`sha256:2cf7ddaf5f6369c16a0359e3bd48e54ada211a2e4e90d87532ad2958d642bdd5`,
generó un SBOM CycloneDX con 20 componentes y 11 hallazgos Trivy, sin warnings.
El detalle, el SBOM y la API coinciden en el escaneo #45; el directorio temporal
de la imagen quedó eliminado. Este recorrido no convierte el socket Docker en
acceso seguro sin allowlist ni valida todavía formatos SPDX, exportaciones
completas ni imágenes sin paquetes.

**Cierre:** SBOM verificable y recuperable para los formatos/ecosistemas
aprobados, con cobertura y alcance desconocido visibles.

### 07. Inteligencia, frescura y equivalencias — P0

**Depende de:** 04–06.

**Hacer**
1. Validar ventanas, límites, cadencia, puntos de reanudación, retiros y
   errores de CISA KEV, OSV, GitHub Advisories, NVD y EPSS; mostrar cobertura
   temporal y fuente, no solo una etiqueta de actualidad.
2. Medir el coste del índice OSV y diseñar una continuación limitada con
   presupuesto de tiempo/red y recuperación transaccional. No iniciar una
   importación completa sin acordar su alcance operativo.
3. Mantener fusiones automáticas solo para equivalencias OSV admitidas;
   exponer historial y mecanismo de revisión para conflictos ambiguos.
   Conservar IDs, referencias y evidencia; reversión transaccional
   bloqueada ante dependencias ambiguas o fusiones posteriores.
4. Definir un flujo controlado para validar la equivalencia real pendiente
   sin saltar el cursor ni aplicar relaciones ambiguas.

**Pruebas:** proveedor caído, 429, datos inválidos, cambio de índice,
interrupción antes/después del checkpoint, límite de lote y reanudación;
fusión, reversión, nuevas referencias y concurrencia en PostgreSQL.
Comprobar que no se pierden avisos ni hallazgos y que una reversión
rechazada no modifica datos.

**Errores y cautelas:** `aliases` no equivale a `related`; historial local no
es auditoría externa resistente a manipulación; EPSS solo cubre CVE
consultados y las ventanas NVD/GitHub no son históricas completas.

**Cierre:** sincronizaciones recuperables, cobertura visible y
equivalencias auditables; evidencia real del caso pendiente o limitación
aprobada explícitamente para L.

**Avance operativo realizado:** CISA KEV se sincronizó con éxito contra la
fuente real y registró 1792 registros activos, cobertura completa y catálogo
`2026.11.23`. El dashboard refleja el último intento y éxito y conserva el
historial de ejecución. NVD/GitHub aparecen recientes con cobertura parcial,
EPSS parcial/no verificado y OSV no disponible tras su última ejecución
parcial. Esta etiqueta no convierte esos estados en cobertura histórica
completa.

Las pruebas de checkpoints OSV y fusiones reversibles aprobaron 8 casos:
reanudación por cursor, retiros, feeds reordenados, rollback por fallo,
preservación de referencias y bloqueo de reversión ante cambios o fusiones
posteriores. Existe una fusión real OSV registrada con evidencia
GHSA/CVE/GO y referencias; no se ejecutó reversión sobre ella.

La suite de coordinación PostgreSQL no pudo iniciar porque ya existía la base
de pruebas `test_ciclosec`; no se eliminó ni modificó sin autorización de
limpieza. Este bloque impide declarar cerrado el paso 07 hasta repetir la
coordinación con una base de pruebas aislada disponible.

### 08. Correlación, riesgo y gestión de hallazgos — P0/P1

**Depende de:** 05–07.

**Hacer**
1. Validar asociación a componentes, interpretación de rangos por ecosistema
   y reevaluación sin reescanear. Lo no soportado debe permanecer potencial
   o pendiente, nunca confirmado por aproximación.
2. Mostrar origen, evidencia saneada, estado de afectación, confianza,
   frescura y factores de riesgo; diferenciar severidad del proveedor de
   prioridad calculada.
3. **P1:** definir e implementar flujo de revisión: asignación, aceptación de
   riesgo/falso positivo o cierre según permisos, motivo, responsable,
   historial y reapertura ante evidencia nueva. No sobrescribir el resultado
   técnico del escáner con una decisión humana.

**Pruebas:** versiones dentro/fuera/de límite, rangos no soportados,
ausencia de versión, datos envejecidos, referencias agrupadas, reevaluación y
decisiones humanas concurrentes; verificar explicación reproducible.

**Errores y cautelas:** ausencia de señal no significa riesgo bajo;
puntuar no equivale a confirmar explotación; una excepción no debe ocultar
una nueva ocurrencia.

**Cierre:** los estados técnicos y humanos se distinguen, las decisiones se
auditan y el riesgo es explicable en UI/API para los casos soportados.

**Avance operativo realizado:** la correlación de rangos/ecosistemas y el riesgo
explicable ya están implementados y tienen pruebas. Se añadió una decisión
humana separada del estado técnico, con estados abierto/asignado/aceptado
como riesgo/falso positivo/cerrado, responsable, motivo y actor. El historial
se conserva y una reevaluación automática no sobrescribe la decisión. La API
exige usuario administrador para cambiarla; el dashboard muestra el estado y
su historial. Tres pruebas dirigidas aprobaron permisos, requisitos de motivo
y aislamiento entre decisión técnica y humana.
La interfaz activa muestra el formulario solo a administradores y conserva
historial vacío hasta que se registre una decisión; no se creó ninguna decisión
sobre hallazgos reales durante esta implementación.

**Automatización API/MCP:** `POST /api/findings/{id}/decision/` permite a un
usuario staff registrar estado, responsable y motivo; conserva el resultado
técnico sin reescanear. El MCP registra la herramienta `review_finding`,
protegida por `mcp.allow_finding_decisions`, confirmación explícita y las
credenciales staff existentes. Está desactivada por defecto y no crea decisiones
sobre datos reales al habilitarse; `list_findings` incluye la decisión actual y
su historial limitado.

### 09. API completa y contratos — P0

**Depende de:** 03–08.

**Hacer**
1. Inventariar y documentar contrato versionado de activos, fuentes,
   escaneos, inventario, hallazgos, inteligencia, cobertura y operaciones
   de revisión aprobadas. Mantener compatibles los consumidores existentes
   o proporcionar migración/versionado.
2. Completar filtros, paginación estable y límites en todos los listados,
   validaciones, códigos HTTP y errores estructurados sin secretos.
   Definir explícitamente política de borrado y referencias históricas.
3. Definir autenticación de cliente automatizado y permisos por operación,
   además de la sesión web; implementar solo lo aprobado y proteger CSRF.
4. Publicar documentación interactiva o esquema y ejemplos ejecutables de
   alta → scan → estado → SBOM → hallazgo, incluidas respuestas parciales.

**Pruebas:** contrato, permisos por rol, usuario anónimo, CSRF, datos
inválidos, paginación con registros nuevos, límites y cliente automatizado.
Objetivo inicial: consultas paginadas sobre 10.000 hallazgos sin respuestas
no acotadas; registrar tiempos y consultas SQL.

**Errores y cautelas:** no exponer errores internos, tokens ni SBOM completos
sin autorización; no cambiar silenciosamente el significado de IDs.

**Avance realizado:** los listados REST de activos, fuentes, escaneos y
hallazgos aceptan filtros acotados y paginación `limit/offset` (máximo 100).
Sin parámetros se conserva la respuesta histórica de lista. Con parámetros se
devuelve `{total, limit, offset, items}` y orden estable. Se publicó
`/api/openapi.json` y `/api/docs/` con el contrato actual y ejemplos;
`docs/API.md` documenta compatibilidad, filtros y política sin borrado.
La autenticación adicional para clientes automatizados no se implementó:
continúa la autenticación Django aprobada y requiere decisión posterior.

**Cierre:** todos los recorridos incluidos se ejecutan sin acceder a la base
de datos ni usar autenticación de pruebas; contratos y límites documentados.

### 10. Dashboard y usabilidad — P0

**Depende de:** 03–09.

**Hacer**
1. Completar y conectar cada pantalla: panel y cobertura; activos y fuentes;
   escaneos y detalle; SBOM y exportación autorizada; hallazgos y revisión;
   inteligencia y sincronizaciones; API/MCP y configuración/diagnóstico
   aprobados. Hoy inteligencia e integraciones son principalmente
   informativas: no anunciar botones que todavía no existan.
2. Para cada acción mostrar permisos, confirmación cuando proceda, progreso,
   éxito, error y recuperación; distinguir vacío, cargando, parcial,
   desactualizado y sin acceso. Evitar acciones duplicadas.
3. Unificar navegación, filtros, paginación y enlaces entre activo,
   escaneo, componente y hallazgo; explicar estados y próximos pasos en
   lenguaje claro, en español.
4. Validar teclado, foco visible, etiquetas, contraste y lector de pantalla;
   probar móvil, tableta y escritorio sin pérdida de funcionalidad.

**Pruebas:** navegador real con login/logout, alta, un escaneo autorizado,
espera y revisión del resultado; errores de API/red, formularios inválidos,
tablas vacías y datos parciales. Ejecutar pruebas de accesibilidad y capturas
en al menos 375, 768 y 1440 px, más zoom al 200 %.

**Errores y cautelas:** una página cargada con datos de muestra no valida el
backend; gráficos sin datos no deben afirmar «sin vulnerabilidades».

**Cierre:** todos los recorridos aprobados funcionan en las resoluciones y
condiciones indicadas; no quedan botones o estados sin comportamiento.

**Avance operativo realizado:** 81 pruebas de integración del dashboard
aprobaron navegación, filtros, paginación y estados. Playwright verificó login
real, logout, panel, activos, hallazgos, historial e inteligencia en sesión
activa; el detalle del escaneo #45 y su navegación fueron accesibles. Los
anchos 375, 768 y 1440 px no mostraron desbordamiento horizontal. Se añadió el
tema compartido al login, el enlace de salto y foco visible.

**Actualización en vivo del panel (2026-11-24):** el resumen se sirve como
fragmento reutilizable y se consulta cada 10 segundos mientras la pestaña está
visible; al volver a ella se actualiza de inmediato. Filtros, paginación y
solicitudes de escaneo del panel funcionan sin recargar la página, conservando
el comportamiento normal de formularios fuera de esa interacción. Pasaron las
83 pruebas de integración del dashboard, Ruff, la comprobación de sintaxis
JavaScript y `manage.py check`. Se reconstruyó y recreó solo el servicio web.
En navegador se verificaron el refresco periódico y los filtros sin recarga
completa, simulando la pestaña visible porque el contexto automatizado la
reportaba oculta; también se verificó la recuperación tras un fallo temporal.
No se inició ningún escaneo real.

**Revalidación responsive (2026-11-24):** a 187 px y al 200 % de zoom real
(375 px de viewport, DPR 2), la hoja inyectada con las reglas fuente actuales
no produjo desbordamiento (`scrollWidth == clientWidth`). En esa validación
inicial, la aplicación activa sirvió una copia antigua de `dashboard.css`,
incluso al pedirla sin caché; esa copia sí desbordaba (235 px a 200 %). Se
ajustó la fuente para apilar encabezados y paginación estrechos, reducir el
gráfico y permitir que celdas y títulos largos se partan. El servicio web se
reconstruyó posteriormente; falta repetir la validación responsive con recarga
normal. El paso sigue abierto; también faltan Playwright persistido como suite
repetible y validación automatizada de contraste/lector de pantalla.

### 11. MCP e integraciones — P0/P1

**Depende de:** 06–09.

**Hacer**
1. Validar con un cliente MCP real las seis herramientas de solo lectura:
   activos, cobertura, historial, SBOM, hallazgos y frescura. Documentar
   arranque por stdio, configuración, límites y errores.
2. Mantener esquemas tipados y paginados, salida saneada y separación entre
   protocolo (`stdout`) y diagnóstico (`stderr`). Documentar permisos del
   proceso y datos a los que realmente puede acceder.
3. **P1:** añadir consultas faltantes solo si el alcance las requiere;
   compartir servicios/contratos con API y evitar duplicar lógica.
4. Cualquier acción de escritura o transporte remoto requiere aprobación
   independiente, autenticación, permisos, confirmación y auditoría; no
   habilitarla por defecto ni asumir que `allow_run_scan` ya la implementa.

**Pruebas:** cliente real lista y ejecuta cada herramienta; parámetros fuera
de rango, activo inexistente, servicio caído, límites, datos sensibles y
escritura deshabilitada por defecto; comprobar paridad con API. La auditoría
de la acción de inteligencia sigue pendiente.

**Errores y cautelas:** el servidor corre con los privilegios de su proceso;
los datos enviados a un cliente o modelo externo requieren autorización.

**Avance de protocolo:** dos pruebas del SDK oficial MCP pasan. Un cliente
`ClientSession` inicializa el proceso stdio y descubre las herramientas; el
cliente llama las seis herramientas de solo lectura sobre el protocolo con
servicios deterministas, y verifica límites, activo inexistente y escrituras
deshabilitadas. No se consultaron proveedores ni datos de repositorios reales.
La redacción y paridad de servicios/API se cubren en sus pruebas existentes.
La suite de protocolo está en `tests/integration/test_mcp_protocol.py`. Queda
pendiente validar la configuración real de un host MCP aprobado y completar la
auditoría de acciones con efectos externos.

**Cierre:** cliente aprobado obtiene resultados correctos y limitados sin
salida de secretos ni acciones no autorizadas.

### 12. Automatización, notificaciones y operación local — P1

**Depende de:** 04, 07–11.

**Hacer**
1. Implementar o retirar explícitamente cada opción expuesta de programación,
   concurrencia y notificaciones; mostrar si el servicio necesario está
   activo. Un parámetro configurado no debe aparentar una función operativa.
2. Para canales aprobados, definir eventos, destinatarios, deduplicación,
   reintentos y prueba de envío; no incluir secretos ni detalles privados por
   defecto. No activar envíos externos sin autorización.
3. Exponer diagnóstico seguro de cola, Beat, últimas ejecuciones y fallos;
   documentar reinicio, recuperación y desactivación.

**Pruebas:** un único scheduler, duplicado, servicio parado, proveedor lento,
canal caído, reintento y opt-out. Validar horarios/zona y que no se ejecutan
escaneos no autorizados.

**Errores y cautelas:** Beat duplicado puede crear trabajos repetidos;
perder una notificación no debe cambiar el resultado del escaneo.

**Cierre:** cada opción incluida tiene comportamiento real verificable o se
elimina/documenta como no soportada; operación sin intervención oculta.

**Avance — notificación y diagnóstico local:** el canal `console` está
conectado a resultados terminales de escaneos reclamados y registra únicamente
ID, estado y conteo de hallazgos. Respeta `notifications.enabled` y canales
vacíos; entregas duplicadas no vuelven a emitir el aviso. La guía de
[desarrollo](DEVELOPMENT.md#scan-completion-notifications) documenta su límite
best-effort: sin historial/reintentos durables ni canales externos.
`ciclosec_doctor` ahora informa conteos de cola y los últimos cinco escaneos
por ID/estado, sin nombres de activos ni errores crudos. La cola sigue siendo
una instantánea de la base de datos. El diagnóstico distingue si hay tareas
periódicas configuradas y sugiere cómo comprobar Beat sin iniciarlo; el
proceso sigue como no verificado. Las pruebas del diagnóstico verifican los
servicios caídos y que los fallos al leer cola/historial no exponen errores
internos. Siguen pendientes la verificación real de Beat y las pruebas de
operación extremo a extremo, por lo que el paso continúa en curso.

**Prueba local — 24/11/2026:** inicialmente no había contenedor Beat y web y
worker usaban una imagen anterior. Antes del reinicio se comprobó que Celery no
tenía tareas activas/reservadas y Redis tenía cero mensajes en cola. Tras la
autorización explícita para ejecutar tareas periódicas, se recreó el stack con
ambos perfiles (`app` y `scheduler`), manteniendo el volumen de PostgreSQL.
Migraciones terminaron correctamente; PostgreSQL, Redis, web, worker y Beat
quedaron activos. `/accounts/login/` respondió HTTP 200 y el diagnóstico de la
imagen nueva terminó con código 0; la cola estaba vacía y los escaneos
preexistentes seguían disponibles. Compose y los logs confirmaron Beat activo
con seis tareas configuradas; el comando doctor mantiene su estado como
`unknown` porque no inspecciona el proceso. Beat puede sincronizar proveedores
externos conforme a la configuración. Las pruebas extremo a extremo siguen
pendientes.

### 13. Seguridad, respaldo y recuperación local — P0

**Depende de:** 02–12.

**Hacer**
1. Revisar amenazas y límites de confianza: sesiones, roles, CSRF, datos
   sensibles, subprocesses, descarga/extracción de archivos, red de
   proveedores y daemon Docker. Corregir hallazgos dentro del alcance.
2. Implementar copias con cifrado, permisos, retención y procedimiento
   documentado para PostgreSQL y configuración necesaria; nunca incluir
   secretos sin protección ni sobrescribir datos al ensayar restauración.
3. Ensayar restauración en una base aislada, verificar integridad,
   usuarios/activos/hallazgos/SBOM y migraciones, y practicar rollback.
   Registrar responsable y objetivos de recuperación acordados.

**Pruebas:** backup/restauración real, backup corrupto, credencial ausente,
volumen lleno, interrupción y verificación de permisos; revisión de logs y
exportaciones; acceso no autorizado y cargas maliciosas controladas.

**Errores y cautelas:** un `pg_dump` exitoso no demuestra restauración;
no eliminar volúmenes ni restaurar sobre la única copia; copias locales sin
cifrar no cumplen el requisito de producción.

**Cierre:** restauración aislada repetible y política de secretos, backup y
recuperación aceptada; incidencias críticas cerradas.

### 14. Aceptación integral del hito L — P0

**Depende de:** 01–13.

**Hacer**
1. En instalación limpia, repetir dos veces el recorrido completo: login →
   activo autorizado → escaneo → SBOM → hallazgo → revisión →
   actualización de inteligencia → reevaluación → consulta API/MCP.
2. Incluir repositorio privado, Dependabot habilitado, lockfile representativo
   e imagen local si forma parte del alcance aprobado. Comprobar el resultado
   desde UI y clientes reales, no solo desde un cliente de pruebas.
3. Ejecutar las comprobaciones del proyecto, integración con
   PostgreSQL/Redis y pruebas de navegador en las plataformas aprobadas.
   Registrar versión, configuración sin secretos, resultados y limitaciones.

**Pruebas:** recorridos felices y fallos de acceso/red/worker, reinicio,
parcialidad y recuperación; accesibilidad y restauración del paso 13.

**Errores y cautelas:** no declarar validado el MVP si se omitió un caso P0;
no publicar código, tokens, SBOM privados o logs sin revisar.

**Cierre L:** todas las casillas P0/P1 incluidas están terminadas, pruebas
aprobadas sin regresiones nuevas, limitaciones aceptadas por el responsable y
guía local suficiente para una persona nueva.

## 4. Pasos para el hito P: producción controlada

### 15. Diseño de despliegue y amenazas — P0

**Depende de:** cierre L.

**Hacer:** aprobar usuarios, roles, red de acceso, dominios/TLS, datos,
volumen esperado, disponibilidad, RPO/RTO, aislamiento de escáneres y
responsables. Diseñar separación web/worker/Beat/PostgreSQL/Redis, gestión de
secretos y el modelo de acceso a Docker; documentar límites de confianza.

**Pruebas:** revisión de amenazas, privilegios y dependencias; validar que
cada requisito tiene responsable y criterio medible.

**Errores y cautelas:** una VPN o proxy por sí solos no sustituyen permisos;
no reutilizar `runserver` ni Compose local como producción.

**Cierre:** diseño y criterios de aceptación de P aprobados antes de
implementar o provisionar infraestructura.

### 16. Despliegue endurecido y seguridad — P0

**Depende de:** 15.

**Hacer:** construir imágenes mínimas y versionadas; WSGI, proxy HTTPS,
estáticos, hosts/CSRF/cookies seguros y políticas de sesión; servicios
internos no publicados, healthchecks, límites y apagado ordenado. Configurar
secretos fuera del código, privilegios mínimos, aislamiento y egress del
worker. Diseñar una única migración controlada y rollback de aplicación y
datos. Ejecutar y resolver `manage.py check --deploy`.

**Pruebas:** staging con TLS y `DEBUG=False`; autenticación/autorización,
CSRF, HTTPS, cabeceras, procesos no privilegiados, red y límites. Comprobar
que imágenes y logs no contienen secretos.

**Errores y cautelas:** no publicar PostgreSQL/Redis ni montar el socket
Docker sin modelo aprobado; migraciones irreversibles requieren plan y copia.

**Cierre:** configuración de producción reproducible y comprobaciones de
seguridad superadas en staging.

### 17. Observabilidad, continuidad y actualización — P0

**Depende de:** 15–16.

**Hacer:** monitorizar salud, cola, antigüedad de trabajos, fallos,
proveedores, capacidad, certificados y backups; alertas accionables y sin
secretos. Automatizar copias cifradas con retención y ensayos de restauración.
Documentar releases, parcheo de dependencias, rotación de credenciales,
respuesta a incidentes, upgrade/rollback y responsables de guardia.

**Pruebas:** simular caída de web, worker, Redis y proveedor; restaurar
backup en entorno aislado; probar actualización y reversión, pérdida de
conectividad, disco lleno y rotación. Medir RPO/RTO contra los valores
aprobados, sin suponer que ya se cumplen.

**Errores y cautelas:** una alerta sin responsable no es respuesta operativa;
no restaurar sobre producción para probar una copia.

**Cierre:** procedimientos ejecutados en staging, métricas y alertas
verificadas, recuperación dentro de los objetivos aprobados.

### 18. Staging, carga y aprobación de producción — P0

**Depende de:** 16–17.

**Hacer:** reproducir las dos vueltas del hito L en staging con usuarios y
credenciales de prueba; validar límites y permisos multiusuario. Ensayar
escalado y carga con un conjunto inicial de 10.000 hallazgos y 20 solicitudes
concurrentes, ajustando el objetivo si el responsable lo aprueba. Medir
latencia, recursos y ausencia de duplicados; fijar umbrales de aprobación
antes de medir.

**Pruebas:** recorrido UI/API/MCP incluido en el alcance, migración,
actualización, respaldo/restauración, fallos y revisión de seguridad.
Repetir con datos sanitizados y proveedores simulados cuando sea posible.

**Errores y cautelas:** no probar producción con repositorios ajenos o datos
reales sin autorización; no declarar capacidad a partir de una sola carga.

**Cierre P:** incidencias críticas cerradas, límites conocidos, evidencia
revisada, responsables designados y aprobación explícita para el despliegue.

## 5. Registro de avance

Para cada paso, registrar en el propio cambio o en el sistema de seguimiento:
fecha, responsable, alcance aprobado, versión/entorno, pruebas con resultado
y evidencias saneadas, errores, decisiones y limitaciones. No incluir
credenciales, contenido privado ni valores de secretos.

| Paso | Estado inicial | Dependencias |
|---|---|---|
| 01. Alcance y roles | En curso; casos de aceptación pendientes | — |
| 02. Instalación y diagnóstico | En curso; aceptación multiplataforma pendiente | 01 |
| 03. Activos y acceso | Parcial | 01–02 |
| 04. Trabajos | Parcial | 02–03 |
| 05. Repositorios y Dependabot | Parcial | 03–04 |
| 06. SBOM e imágenes | Parcial | 04–05 |
| 07. Inteligencia y equivalencias | Parcial | 04–06 |
| 08. Hallazgos y riesgo | Parcial | 05–07 |
| 09. API | Parcial | 03–08 |
| 10. Dashboard | Parcial | 03–09 |
| 11. MCP | Parcial | 06–09 |
| 12. Automatización y notificaciones | En curso (console y diagnóstico local) | 04, 07–11 |
| 13. Seguridad y recuperación | Parcial | 02–12 |
| 14. Aceptación local | Pendiente | 01–13 |
| 15–18. Producción | No iniciada | Cierre L y paso anterior |

**Siguiente trabajo recomendado:** terminar el paso 01 eligiendo los casos
privado, Dependabot e imagen local; después continuar con el paso 02 sin
iniciar trabajos automáticos.
