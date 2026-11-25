# CicloSec: roadmap de ejecución para el uso local

## 1. Objetivo y alcance

Completar los 14 ámbitos pendientes para que una persona autorizada pueda
instalar CicloSec, configurarlo, analizar activos permitidos, interpretar y
gestionar los resultados y recuperarse de fallos. Este documento desarrolla
operativamente el hito local del [roadmap vigente](docs/roadmap.md); no declara
terminadas sus puertas ni sustituye el plan de producción.

El orden propuesto respeta las dependencias, pero no exige ejecutar pruebas
externas anticipadamente: los casos reales que requieran autorización pueden
prepararse y quedar bloqueados hasta contar con ella. No se dará por aceptado
un hito si faltan sus pruebas o decisiones. Una ejecución parcial debe mostrar
qué funciona, qué no se ha probado y por qué.

**Fuera de alcance de este documento:** declarar listo el despliegue de
producción, exponer MCP por red, habilitar infraestructura SSH o registros
remotos, y prometer cobertura universal. Esas capacidades requieren alcance y
aprobación propios. El [roadmap vigente](docs/roadmap.md) conserva las fases de
producción.

## 2. Estado y reglas comunes

### Punto de partida

- Existe una base de persistencia, validación y auditoría de configuración y
  una sección parcial para superadministradores. Algunas opciones ya usan
  sobrescrituras; Beat carga su programa al arrancar e informa de señales por
  instancia, con límites explícitos. La sección permite configurar los
  programas de proveedores, pero no bloquea la sincronización manual ni los
  trabajos ya enviados. La verificación de los demás procesos y otras opciones
  siguen pendientes. Se ha probado la concurrencia de esa base con PostgreSQL.
- Las rutas web solicitadas se cambiaron al inglés; **la traducción completa
  y el selector de idioma siguen pendientes**. Revisar API y MCP sin cambiar
  sus claves ni valores contractuales.
- Hay dashboard, API, MCP local, escaneos y sincronizaciones parciales. Una
  función existente o una prueba simulada no equivale a aceptación completa.
- Se probó anteriormente una imagen local autorizada. Aún hay que acordar y
  comprobar los casos finales de aceptación, incluido el repositorio privado
  con Dependabot habilitado. No se asume que los casos anteriores sigan siendo
  adecuados o estén autorizados para una nueva ejecución.
- El canal de notificaciones `console` existe; interfaz, correo y webhook
  todavía no son canales operativos completos.
- La última entrega dejó Beat detenido. Comprobar su estado real antes de
  actuar: la presencia de tareas configuradas no demuestra que esté activo.

### Reglas para cada entrega

1. Identificar alcance, archivos y contratos afectados; conservar cambios
   existentes y no modificar datos reales para preparar pruebas.
2. Escribir pruebas focalizadas para el cambio y comprobar errores, permisos y
   efectos secundarios, además del caso correcto. Usar PostgreSQL cuando se
   dependa de transacciones y bloqueos; SQLite no demuestra esas garantías.
3. Simular proveedores, mensajería y escáneres en pruebas ordinarias. Antes de
   cualquier prueba real, identificar recurso, ref o digest, datos transmitidos,
   límites y autorización; no iniciar sincronizaciones masivas por defecto.
4. No incluir secretos, código privado, SBOM privados ni respuestas sensibles en
   ejemplos, registros, evidencias o servicios externos.
5. Documentar la funcionalidad y sus límites. Una opción sin comportamiento
   verificable no se presenta como operativa.
6. Después de cada cambio o funcionalidad validada, reconstruir y reiniciar los
   servicios Docker afectados para la prueba local. Antes, comprobar tareas
   activas y reservadas, mensajes en cola y escaneos en curso; si no es seguro,
   posponer el reinicio y comunicarlo. Aplicar migraciones de forma controlada y
   verificar respuesta de los servicios actualizados. No iniciar Beat si estaba
   detenido ni eliminar volúmenes o datos para resolver fallos.
7. El reinicio de servicios desde la futura sección de configuración será
   **manual**, con instrucciones y verificación de estado; no se dará acceso al
   daemon de Docker a la web para realizarlo.

### Condición general de cierre

Marcar una fase como completada solo cuando sus tareas estén implementadas,
pasen sus pruebas, se verifiquen sus criterios de aceptación y se actualicen la
documentación y la evidencia. Registrar fecha, entorno, versión, comandos,
resultado, limitaciones y pruebas no realizadas, sin datos sensibles. Si una
prueba falla, corregirla o dejar la fase explícitamente abierta.

## 3. Dependencias y orden sugerido

| Fase | Área | Dependencias principales | Estado |
|---|---|---|---|
| 01 | Configuración | Base persistente existente | En curso |
| 02 | Usuarios y permisos | 01 para su administración; matriz acordada | Pendiente |
| 03 | Idiomas | 01 para el selector y ajustes | Pendiente |
| 04 | Instalación | Migraciones y despliegue de 01–03 | Parcial |
| 05 | Escaneos | 01–02; infraestructura comprobada en 04 | Parcial |
| 06 | GitHub y Dependabot | 02, 05 y casos autorizados | Parcial |
| 07 | SBOM y ecosistemas | 05–06 | Parcial |
| 08 | Inteligencia | 01, 05 y 07 | Parcial |
| 09 | Hallazgos | 02, 07–08 | Parcial |
| 10 | API y MCP | 01–02 y contratos de 05–09 | Parcial |
| 11 | Dashboard | 01–03 y funciones de 05–10 | Parcial |
| 12 | Notificaciones | 01–02 y eventos fiables de 05, 08–09 | Parcial |
| 13 | Seguridad y copias | 01–12 | Parcial |
| 14 | Aceptación integral | 01–13 | Pendiente |

Las pruebas unitarias y de contratos pueden avanzar en paralelo cuando no
compartan archivos o datos. El cierre y la aceptación respetan la tabla. Si una
prueba en entorno real se pospone, continuar únicamente con trabajo independiente
y mantener su fase y cualquier aceptación dependiente abiertas.

## 4. Fases detalladas

### 01. Configuración

**Objetivo:** una sección segura y modular que administre las opciones
existentes y refleje qué configuración utiliza cada proceso.

**Pasos**
1. Completar el catálogo de opciones: tipo, validación, sensibilidad,
   categoría, proceso consumidor y si requiere reinicio. Distinguir opciones
   editables de configuración externa y capacidades aún no implementadas.
2. Conectar las sobrescrituras persistentes a web, API, workers, Beat y MCP;
   combinar con YAML y validar la configuración completa. Evitar consultas a
   tablas inexistentes durante migraciones o arranque inicial.
3. Aplicar comprobaciones de autorización antes de efectos sensibles. Ante un
   error de base de datos o validación, no recurrir silenciosamente a una
   configuración que pueda conceder permisos.
4. Añadir sección `/settings/` para idioma, cuentas, escaneos, inteligencia,
   MCP, notificaciones y opciones generales. Solo superadministradores pueden
   modificar opciones sensibles; exigir confirmación y registrar los cambios.
5. Mostrar revisión deseada y estado verificable de cada instancia: aplicada,
   pendiente, detenida cuando se pueda comprobar, o desconocida. Explicar cómo
   reiniciar manualmente los procesos afectados, incluido MCP fuera de Compose.
6. Mantener secretos y credenciales fuera de los formularios y de los eventos
   de auditoría. Documentar precedencia y recuperación.

**Fallos y cautelas:** versiones distintas entre procesos; Beat con programa
antiguo; un proceso desconocido no es uno detenido; pérdida de conexión a la
base; cambios concurrentes; valores incompatibles; cambios de permisos durante
un trabajo ya iniciado. No anunciar una revocación como aplicada si no puede
verificarse en los procesos pertinentes.

**Pruebas:** persistencia tras reinicios; validación y secreto no expuesto;
escrituras concurrentes en PostgreSQL; usuario anónimo, normal, staff y
superadministrador; CSRF y confirmación; migraciones desde una base sin tablas;
worker, Beat y MCP con revisiones distintas; estado desconocido y fallo de
aplicación. No iniciar Beat ni acciones externas durante estas pruebas.

**Cierre:** opciones admitidas operativas, permisos y auditoría verificados, y
ningún servicio presentado como actualizado sin evidencia.

### 02. Usuarios y permisos

**Objetivo:** administrar cuentas y aplicar de manera consistente la matriz de
acceso del hito local.

**Pasos**
1. Contrastar la matriz lector/operador/administrador del
   [roadmap vigente](docs/roadmap.md) con los permisos reales de Django y las
   decisiones recientes: la gestión de cuentas, activación y roles existentes
   queda restringida a superadministradores. Resolver explícitamente cualquier
   cambio de comportamiento necesario antes de retirar permisos actuales.
2. Diseñar la correspondencia de roles y permisos por operación, incluida
   exportación de SBOM, solicitudes de escaneo, sincronización, decisiones y
   reversión. Restringir en servidor tanto UI como API; ocultar botones no basta.
3. Implementar gestión de usuarios y roles con confirmación, auditoría y
   comprobación del actor dentro de la transacción. No permitir desactivar o
   degradar al último superadministrador activo, ni por cambios concurrentes.
4. Definir recuperación administrativa, sesiones de usuarios desactivados y
   protección contra escalada; no mostrar ni registrar contraseñas.

**Fallos y cautelas:** permisos antiguos más amplios; asignación indirecta de
privilegios mediante grupos; dos administradores modificándose simultáneamente;
sesiones vigentes tras desactivación; pérdida del último superadministrador.

**Pruebas:** matriz completa de operaciones permitidas y denegadas en UI y API,
anónimo, usuario inactivo, manipulación de parámetros, CSRF y confirmación;
cambios simultáneos con PostgreSQL; auditoría sin secretos; inicio y revocación
de sesión. Verificar efectos de cambios de rol sobre cuentas existentes.

**Cierre:** cada acción tiene permiso documentado y pruebas positivas y
negativas; ningún flujo permite escalada o deja el sistema sin administración.

### 03. Idiomas

**Objetivo:** interfaz completa en español e inglés mediante un mecanismo
estándar, modular y ampliable.

**Pasos**
1. Inventariar textos de plantillas, formularios, vistas, JavaScript,
   diagnósticos, ayudas, errores, etiquetas y datos generados persistidos.
2. Configurar internacionalización de Django, catálogos y selector visible.
   Guardar preferencia individual; usar el idioma compatible del navegador o
   sistema cuando no exista preferencia, con inglés como alternativa.
3. Traducir la interfaz completa, incluidos estados dinámicos y accesibilidad.
   Los datos externos se muestran como proporcionados y se identifica ese límite.
4. Mantener navegación y rutas en inglés. Fijar mensajes de API y MCP en inglés
   independientemente del idioma web, sin traducir claves ni valores contractuales.
5. Incluir y comprobar catálogos compilados en la imagen Docker; preservar y
   representar correctamente explicaciones históricas que no puedan traducirse.

**Fallos y cautelas:** cadenas sin marcar; plurales y fechas; traducción tardía
de JavaScript; HTML `lang`; rutas de redirección inseguras; catálogos ausentes
en la imagen; confundir datos de proveedores con textos de la aplicación.

**Pruebas:** negociación `es`, `en` y lenguaje no soportado; persistencia y
cambio de preferencia; CSRF; todas las páginas y errores en ambos idiomas;
fragmentos de actualización automática; pruebas de contratos API/MCP y de
catálogos desde el contenedor. Revisar manualmente las traducciones.

**Cierre:** inventario completo revisado, selector persistente y cobertura de
pantallas probada en los dos idiomas; limitaciones históricas explícitas.

### 04. Instalación y recuperación local

**Objetivo:** instalar, actualizar, diagnosticar y recuperar el entorno sin
perder datos en las plataformas declaradas.

**Pasos**
1. Definir matriz de Windows y Linux, instalación nativa y Docker, arquitectura,
   prerrequisitos y versiones realmente soportadas.
2. Ejecutar instalación limpia y segunda ejecución en entornos aislados;
   verificar que no sobrescribe configuración, secretos ni datos.
3. Probar actualización y migraciones, reinicio del equipo, diagnóstico,
   interrupciones y recuperación; documentar un rollback compatible con la base.
4. Verificar descargas y checksums, espacio, puertos y servicios. Registrar
   limitaciones de Windows ARM y del worker nativo cuando correspondan.

**Fallos y cautelas:** daemon caído, puertos ocupados, espacio insuficiente,
checksum incorrecto, dependencias ausentes, PostgreSQL o Redis inaccesible,
migración incompatible y recuperación destructiva.

**Pruebas:** instalación y repetición por combinación soportada; ejecución sin
caché donde sea posible; fallos controlados y recuperación; reinicio real del
equipo cuando esté autorizado; conservación de una marca sintética en base de
datos. No borrar volúmenes ni sobrescribir instalaciones ajenas.

**Cierre:** matriz de plataformas con evidencia y guía de instalación,
diagnóstico, actualización y rollback verificadas.

### 05. Escaneos y trabajos

**Objetivo:** ejecuciones autorizadas, limitadas, observables y recuperables sin
duplicaciones silenciosas.

**Pasos**
1. Revisar el ciclo de vida y la entrega al broker: en cola, en ejecución,
   completo, parcial, fallido, cancelado e incierto.
2. Diseñar recuperación de worker interrumpido, reentregas y reinicios de
   Redis sin afirmar que un estado o una antigüedad prueban la muerte del
   proceso. Evitar repetir acciones externas a ciegas.
3. Definir límites de CPU, memoria, disco, tiempo, salida y concurrencia;
   separar lo medido, lo sugerido y lo realmente impuesto por plataforma.
4. Diseñar limpieza de temporales solo cuando se pueda verificar que no están
   en uso; contemplar procesos huérfanos y procesos que escapen del grupo.
5. Validar programación optativa, confirmación de fuente, pausas y recuperación
   en workers actualizados; documentar cancelación y mantenimiento.

**Fallos y cautelas:** entrega incierta o perdida, worker vivo pero no
respondiente, reentrega, cola llena, Redis sin persistencia, caída durante
escritura, procesos escapados y eliminación de temporales aún usados. Docker
daemon y red requieren autorización y no constituyen un sandbox.

**Pruebas:** concurrencia y duplicados con PostgreSQL/Redis; dos workers;
reentrega, reinicio del broker y worker, límite de salida y timeout; ejecución
simulada que deja hijos y temporales; validación Windows y Linux; comprobación
de que un trabajo existente no es sobrescrito ni relanzado sin revisión.

**Cierre:** límites y recuperación documentados y demostrados en entornos
aislados, con estados y limitaciones visibles en UI y API.

### 06. GitHub y Dependabot

**Objetivo:** validar acceso mínimo y resultados para repositorios autorizados,
incluido un caso privado y alertas habilitadas.

**Pasos**
1. Acordar repositorio privado, ref, caso público y prueba Dependabot; precisar
   la autorización y los límites antes de cada ejecución real.
2. Configurar localmente credenciales de solo lectura sin introducir sus valores
   en formularios, documentación o evidencias.
3. Comprobar checkout, identidad de fuente, integridad del inventario y lectura
   de Dependabot por separado. Distinguir cero alertas de fuente no disponible.
4. Documentar destinos y metadatos transmitidos, restricciones de red y
   comportamiento parcial. Validar la referencia o commit real cuando esté
   soportado sin prometer inmutabilidad de una rama móvil.

**Fallos y cautelas:** 401, 403, 404, 429, ref inexistente, credencial sin
permiso, alertas deshabilitadas, red caída, redirecciones inseguras y cambio de
fuente. Un 403 o 404 no prueba por sí solo la causa.

**Pruebas:** casos simulados de errores y redirecciones; privado autorizado con
Dependabot habilitado y token mínimo; repositorio con y sin dependencias;
secreto sintético redactado; resultado parcial visible sin revelar código ni
credenciales. Registrar solo evidencia saneada.

**Cierre:** caso privado y Dependabot probados realmente, con resultados y
limitaciones visibles en UI y API. Sin caso autorizado, mantener fase abierta.

### 07. SBOM y ecosistemas

**Objetivo:** inventarios, exportaciones y evaluación de afectación verificables
para los formatos y ecosistemas comprometidos.

**Pasos**
1. Preservar CycloneDX JSON 1.0–1.7 y SPDX 2.2/2.3 JSON; completar el objetivo
   de CycloneDX XML 1.5–1.7, SPDX 2.2/2.3 tag-value y SPDX 3.0 JSON-LD.
   Investigar herramientas y esquemas antes de implementar cada formato.
2. Para npm, PyPI, Maven, NuGet, Go, Composer, RubyGems, Cargo y paquetes del
   sistema, preparar fixtures representativas con versiones resueltas.
3. Probar importación, persistencia, relaciones, checksum y exportación con
   permisos adecuados. Informar pérdidas o rechazar conversiones no equivalentes.
4. Distinguir alcance desconocido, dependencias de desarrollo, versiones no
   resueltas e inventario vacío de una cobertura completa.
5. Validar imagen local autorizada, digest inmutable y resultados sin asumir
   que pruebas anteriores sustituyen la aceptación final.

**Fallos y cautelas:** archivo malformado o excesivo, XML inseguro, grafo
cíclico, paquetes duplicados, pérdida de relaciones, rangos no resueltos,
datos sensibles en exportación y atribución incorrecta de versiones.

**Pruebas:** válidos e inválidos por formato y versión; límites; round-trip y
pérdidas informadas; afectado y no afectado por ecosistema; dependencia de
desarrollo; fuente modificada; permisos de exportación; imagen permitida y
fuera de allowlist. No ejecutar código del repositorio para inventariarlo.

**Cierre:** tabla de soporte y evidencia reproducible para cada formato y
ecosistema aprobado; cualquier limitación permanece visible.

### 08. Inteligencia

**Objetivo:** fuentes actualizables y recuperables con cobertura y frescura
explicadas, y equivalencias revisables.

**Pasos**
1. Revisar CISA KEV, OSV, GitHub Advisories, NVD y EPSS: ventanas, límites,
   frecuencia, cobertura real, retiros y fallos.
2. Mejorar reanudación, coordinación y presupuesto de lotes de OSV sin iniciar
   importaciones completas ni saltar cursores sin autorización.
3. Mostrar último intento, último éxito, frescura y cobertura temporal;
   distinguir fuentes locales y CVE relacionados con activos propios.
4. Revisar equivalencias automáticas, ambigüedades, historial y reversión con
   sus dependencias; mantener identidades y evidencia histórica.
5. Completar la solicitud manual por fuente, sus permisos, confirmación,
   progreso y estados parciales o inciertos.

**Fallos y cautelas:** proveedor caído o limitado, índice reordenado, lote
interrumpido, cursor inconsistente, alias ambiguos, datos desactualizados y
entrega incierta. Cobertura parcial no equivale a catálogo global completo.

**Pruebas:** 429, datos inválidos y redes simuladas; interrupciones antes y
después de checkpoints; reanudación sin omisiones; coordinación en PostgreSQL;
fusión, reversión y bloqueo ante cambios posteriores; revisión de un caso
real solo con alcance explícito.

**Cierre:** sincronización acotada y recuperable, estados fiables y
equivalencias auditables, con cobertura y límites documentados.

### 09. Hallazgos y riesgo

**Objetivo:** diferenciar evidencia técnica, afectación, severidad, riesgo y
decisiones humanas sin perder historial.

**Pasos**
1. Validar correlación por ecosistema y rangos; dejar como potencial o pendiente
   lo que no pueda determinarse.
2. Mantener orden por riesgo, desempate estable y prioridad desconocida visible;
   conservar filtros y paginación.
3. Completar permisos, asignación, motivo, historial y decisiones humanas sin
   sobrescribir evidencia técnica.
4. Definir comportamiento ante nueva evidencia o recurrencia, incluida
   reapertura cuando corresponda, antes de implementarlo.
5. Mantener tareas urgentes derivadas de datos existentes, explicando por qué
   requieren atención y sin crear tareas independientes implícitas.

**Fallos y cautelas:** versión ausente o límite ambiguo, datos obsoletos,
duplicados, evidencia nueva tras una excepción, actualización concurrente y
asumir que puntuación equivale a explotación confirmada.

**Pruebas:** dentro y fuera de rangos, versiones desconocidas, datos antiguos,
desempates y paginación, decisiones concurrentes, permisos por rol,
reapertura acordada y preservación de la evidencia previa.

**Cierre:** resultados y prioridades explicables, decisiones auditables y
comportamiento frente a nueva evidencia comprobado.

### 10. API y MCP

**Objetivo:** contratos documentados, consistentes, acotados y seguros para
clientes autorizados.

**Pasos**
1. Inventariar operaciones y contratos existentes, documentar campos y errores,
   permisos, filtros, orden y paginación; añadir lo que falte al esquema.
2. Diseñar autenticación de clientes automatizados antes de implementarla;
   preservar sesiones y CSRF donde corresponda.
3. Sanitizar datos internos de escaneos y errores mediante una migración o
   versión compatible, sin cambiar silenciosamente los consumidores existentes.
4. Validar MCP `stdio` con un host real aprobado, paridad de servicios y
   separación de protocolo y diagnósticos. Es de solo lectura por defecto.
   Las acciones existentes de sincronización de inteligencia y revisión de
   hallazgos son optativas: verificar sus controles, confirmación y auditoría.
   No habilitar escaneos por MCP ni transporte remoto sin aprobación específica.
5. Comprobar que mensajes de protocolo son ingleses y que identificadores,
   claves y valores permanecen estables.

**Fallos y cautelas:** respuestas no acotadas, paginación bajo escrituras,
exposición de metadatos, ruptura de clientes, credenciales en logs, proceso MCP
con privilegios excesivos y envíos a clientes externos no autorizados.

**Pruebas:** contratos y compatibilidad, matriz de roles y CSRF, límites y
parámetros inválidos, redacción, servicios caídos, clientes REST/MCP reales y
acciones optativas deshabilitadas por defecto. Medir consultas paginadas con
10.000 hallazgos; acordar umbrales antes de considerarla prueba de capacidad.

**Cierre:** recorridos documentados y probados con clientes reales, sin
regresiones de contrato ni exposición no autorizada.

### 11. Dashboard y accesibilidad

**Objetivo:** recorridos completos y comprensibles, con actualización
automática cuando sea posible.

**Pasos**
1. Revisar panel, activos, escaneos, SBOM, hallazgos, inteligencia,
   integraciones y configuración; conectar solo acciones disponibles.
2. Mantener panel con tareas urgentes, CVE locales y relacionados, fecha y
   frescura; explicar riesgo, severidad, afectación y datos incompletos.
3. Completar estados de carga, vacío, parcial, error, progreso y recuperación;
   evitar envíos duplicados y conservar filtros, paginación y foco.
4. Extender actualización sin recarga donde sea viable, conservando el
   comportamiento básico si falla JavaScript o la red.
5. Verificar navegación con teclado, lectores de pantalla, etiquetas, contraste,
   móvil y escritorio; integrar pruebas de navegador repetibles.

**Fallos y cautelas:** refresco que destruye el foco o formularios, datos
obsoletos aparentando actualidad, respuesta tardía que sobrescribe otra más
reciente, peticiones duplicadas y mensajes inaccesibles.

**Pruebas:** login/logout, filtros, paginación y solicitudes simuladas; caída y
recuperación de red; pestaña oculta; foco durante refresco; 375, 768 y 1440 px
y zoom al 200 %; teclado, contraste y lector de pantalla. No iniciar escaneos
reales sin autorización.

**Cierre:** recorridos acordados probados y accesibles; la interfaz distingue
errores, vacíos y cobertura incompleta sin depender de F5.

### 12. Notificaciones

**Objetivo:** completar los canales de interfaz, correo y webhook previstos,
además del canal de consola existente.

**Pasos**
1. Definir eventos, destinatarios, permisos, contenido mínimo, retención y
   tratamiento de información sensible para cada canal.
2. Diseñar entrega, deduplicación, historial, fallos y reintentos; separar el
   resultado de la operación original del resultado de su notificación.
3. Implementar notificaciones en interfaz y configurar correo y webhook como
   canales externos desactivados por defecto.
4. Incorporar en configuración solo controles funcionales y una prueba de envío
   explícita; mantener credenciales protegidas y fuera de logs y formularios.
5. Documentar destinos autorizados, límites y cómo deshabilitar cada canal.

**Fallos y cautelas:** mensajes duplicados, reintentos infinitos, pérdida de
entrega, destinatario incorrecto, filtración de datos privados y endpoints
webhook inseguros. Una notificación fallida no debe cambiar un escaneo.

**Pruebas:** cada evento y canal con transporte simulado; duplicados, fallo
transitorio y permanente, reintentos limitados, desactivación, permisos y
redacción. Los envíos reales requieren autorización y destinatario de prueba.

**Cierre:** canales previstos verificables y documentados, con fallos visibles
y sin envíos externos activados por defecto.

### 13. Seguridad, copias y recuperación

**Objetivo:** reducir riesgos conocidos y demostrar recuperación de datos sin
poner en peligro la instalación existente.

**Pasos**
1. Revisar sesiones, roles, CSRF, secretos, registros, cargas, procesos,
   extracción de archivos, red de proveedores y acceso al daemon Docker.
2. Priorizar y corregir los hallazgos relevantes; documentar los riesgos que
   no puedan eliminarse y la decisión sobre ellos.
3. Definir copia cifrada de PostgreSQL y configuración necesaria, permisos,
   retención, gestión de claves y responsables. No almacenar claves junto a
   las copias sin protección.
4. Ensayar restauración en una base y volumen aislados, comprobar migraciones,
   usuarios, activos, SBOM y hallazgos, y practicar rollback.
5. Establecer objetivos de recuperación acordados y registrar los resultados
   sin divulgar secretos ni datos privados.

**Fallos y cautelas:** copia corrupta o incompleta, clave ausente, disco lleno,
restauración sobre datos activos, privilegios excesivos, código malicioso y
exposición accidental de logs o exportaciones.

**Pruebas:** controles de acceso, entradas y archivos maliciosos controlados,
backup cifrado y restauración real aislada; backup corrupto, credencial
ausente e interrupción; comprobación de permisos y contenido saneado.

**Cierre:** incidencias críticas abordadas, procedimiento repetible y al menos
una restauración aislada verificada.

### 14. Aceptación integral

**Objetivo:** demostrar que el hito local funciona de extremo a extremo en el
alcance y las plataformas aprobados.

**Pasos**
1. Confirmar que las fases 01–13 cumplen sus cierres y que están seleccionados
   los activos, refs, imagen, usuarios, formatos y ecosistemas de aceptación.
2. En una instalación limpia, repetir dos veces: inicio de sesión → registro de
   activo autorizado → escaneo → SBOM → hallazgo → revisión → actualización de
   inteligencia → reevaluación → consulta API/MCP.
3. Incluir repositorio privado con Dependabot, imagen local autorizada y casos
   de permisos; realizar las operaciones externas solo con aprobación concreta.
4. Ejecutar pruebas de proyecto, PostgreSQL/Redis, navegador, accesibilidad,
   idioma, recuperación y restauración; registrar versiones y entorno.
5. Revisar limitaciones y evidencias saneadas con la persona responsable.

**Fallos y cautelas:** omitir un caso P0, confundir mocks con integración real,
usar credenciales excesivas, publicar evidencia privada o declarar cobertura
universal por un resultado concreto.

**Pruebas:** dos recorridos felices completos; fallos de acceso, red, worker y
proveedores; estados parciales y recuperación; permisos y seguridad; ambas
lenguas; casos y plataformas aprobados. Usar datos sintéticos cuando sea posible.

**Cierre:** todos los criterios incluidos satisfechos, incidencias bloqueantes
cerradas, limitaciones aceptadas y guía suficiente para una nueva instalación.
La aceptación local no implica que producción esté preparada.

## 5. Registro de ejecución

Para cada fase y entrega, anotar en el seguimiento correspondiente:

- Fecha, fase, alcance y versión.
- Estado: pendiente, en curso, bloqueada o completada.
- Cambios y migraciones aplicadas; servicios reconstruidos y reiniciados.
- Pruebas ejecutadas, número de casos y resultados; diferenciar pruebas
  simuladas, locales reales y externas autorizadas.
- Fallos, riesgos, limitaciones, decisiones y siguiente paso.
- Ubicación de evidencia saneada, sin credenciales ni datos privados.

No marcar una fase como terminada por completar únicamente su implementación;
deben cumplirse también sus pruebas, documentación y criterios de cierre.
