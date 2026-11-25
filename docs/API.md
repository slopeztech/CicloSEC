# API local

La API REST usa autenticación Django y no devuelve los valores de credenciales.
La matriz de roles aún no está implementada: actualmente los usuarios
autenticados pueden modificar activos y fuentes, solicitar o cancelar escaneos
autorizados y usar los métodos de borrado de los recursos de activos y fuentes.
Las restricciones relacionales de la base de datos pueden impedir algunos
borrados; no son una política completa de permisos. No compartas acceso con
usuarios no autorizados para estas operaciones.

## Paginación compatible

Los listados de activos, fuentes, escaneos y hallazgos siguen siendo listas
cuando no se incluyen parámetros. Para consultas acotadas, use `limit` y
`offset`:

- `limit`: entero entre 1 y 100.
- `offset`: entero mayor o igual que cero.

Con ambos mecanismos disponibles, la respuesta es:

```json
{"total": 10000, "limit": 100, "offset": 0, "items": []}
```

El orden es estable. Los filtros no modifican el significado de los IDs.

## Filtros

- Assets: `kind`, `enabled`, `search`.
- Repositories: `search`.
- Container images: `search`.
- Scans: `asset`, `status`.
- Findings: `asset`, `affected_status`, `source`, `search`.

## Operación de revisión

`POST /api/findings/{id}/decision/` requiere usuario staff. El cuerpo usa:

```json
{
  "status": "false_positive",
  "reason": "Verified as test fixture",
  "assignee": 1
}
```

Estados válidos: `open`, `assigned`, `accepted_risk`, `false_positive`, `closed`.
La decisión se audita y no modifica el estado técnico ni el riesgo calculado.

## Contrato

El contrato versionado está disponible en `/api/openapi.json` y su página de
ejemplos en `/api/docs/`. Los endpoints pueden cambiar solo mediante migración
compatible o nueva versión del contrato.
