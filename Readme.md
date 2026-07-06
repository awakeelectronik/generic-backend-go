# generic-backend-go

Plantilla de backend en Go (Clean Architecture) con auth, verificación por
correo/teléfono, refresh-token con rotación y revocación por `token_version`,
referidos opt-in, admin único y helpers transaccionales.

Pensado como base reusable: cada clonación parametriza su marca, MTA y
credenciales de admin por env y queda lista para añadir su dominio propio.

## Requisitos

- Go 1.21+
- MySQL 8.0+
- (Producción) Postfix u otro MTA local accesible vía `/usr/sbin/sendmail`

## Setup

```bash
git clone https://github.com/awakeelectronik/generic-backend-go.git
cd generic-backend-go
cp .env.example .env  # ajusta los valores
make install
make run
```

## Variables de entorno

### Server / DB / JWT

| Variable | Default | Notas |
|---|---|---|
| `ENVIRONMENT` | `development` | |
| `PORT` | `8080` | |
| `BASE_URL` | `http://localhost:8080` | |
| `CORS_ALLOWED_ORIGINS` | `*` | Orígenes permitidos, separados por coma. `*` = cualquiera **sin** credenciales (la combinación `*`+credentials es inválida); orígenes concretos se reflejan **con** `Allow-Credentials` + `Vary: Origin`. |
| `TRUSTED_PROXIES` | `` (vacío) | IPs/CIDR de proxies inversos de confianza, separados por coma. Solo se honra `X-Forwarded-For` proveniente de ellos. Vacío = se ignora XFF y se usa la IP del socket directo. Configurar **solo** detrás de proxy/LB: confiar en cualquier proxy deja spoofear la IP cliente y evadir el rate-limit. |
| `MAX_BODY_SIZE` | `1048576` (1 MiB) | Tope global del body para rutas JSON (mín. 1024). `/documents/upload` queda exenta: usa `MAX_FILE_SIZE` + holgura multipart. |
| `HSTS_ENABLED` | `false` | `true` emite `Strict-Transport-Security` (1 año, includeSubDomains). Activar solo cuando la app se sirve por HTTPS. |
| `BCRYPT_COST` | `12` | Work factor de bcrypt (rango válido 10–15). Cada +1 duplica el costo de hash/compare (afecta latencia de login y registro). |
| `RATE_LIMIT_FAIL_CLOSED` | `false` | Política ante Redis caído. `false` = fail-open (se sirve sin límite; disponibilidad). `true` = fail-closed (429 a todo; integridad — recomendado en fintech). Solo aplica con `REDIS_URL`. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `` (vacío) | Rutas de cert y key para HTTPS nativo (`ListenAndServeTLS`). Ambos o ninguno. Vacío = HTTP plano (TLS termina en el proxy). |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | — | |
| `DB_TLS` | `` (vacío) | TLS hacia MySQL: `""` (sin TLS, BD local), `preferred`, `true` (verificado) o `skip-verify`. Usar `true` cuando la BD no comparte host con la app. |
| `DB_MAX_CONN` | `25` | |
| `DB_IDLE_CONN` | `5` | |
| `JWT_SECRET` | — (obligatorio) | mín. 32 bytes; el arranque falla si es más corto |
| `JWT_SECRET_PREVIOUS` | `` (vacío) | Secreto anterior durante una rotación de `JWT_SECRET`: los tokens ya emitidos siguen validando mientras esté puesto; lo nuevo se firma con el vigente. Retirarlo al terminar la rotación. Mín. 32 bytes y distinto de `JWT_SECRET`. |
| `JWT_EXPIRATION` | `1` (hora) | access token corto: un token robado vale poco. La sesión larga vive en el refresh (rotado en cada uso). |
| `JWT_REFRESH` | `8760` (horas, 1 año) | refresh rota en cada uso |
| `STORAGE_PATH` | `./uploads` | |
| `MAX_FILE_SIZE` | `5242880` (5 MiB) | |
| `MAX_DOCS_PER_USER` | `200` | Cuota de documentos por cuenta (evita llenar disco). `0` = sin límite. |
| `STORAGE_ENC_KEY` | `` (vacío) | Clave hex de 64 chars (32 bytes) para cifrado at-rest AES-256-GCM de los archivos subidos. Generar con `openssl rand -hex 32`. Vacío = sin cifrado. Los archivos previos a activarlo se siguen sirviendo. |
| `REDIS_URL` | `` (vacío) | `redis://...` activa store **compartido y restart-safe** para rate-limit, códigos de verificación y lockout de login (necesario al correr varias instancias). Vacío = store **in-memory**: válido para una sola instancia, se pierde al reiniciar y no se comparte entre réplicas. |

### Branding (parametriza cada clonación)

| Variable | Default | Notas |
|---|---|---|
| `APP_NAME` | `MyApp` | aparece en `From`, asunto y `<h2>` del HTML del correo |
| `APP_BRAND_COLOR` | `#000000` | hex usado como acento en el HTML |

### Email

| Variable | Default | Notas |
|---|---|---|
| `SMTP_FROM` | `noreply@app.local` | usado como envelope sender y header `From` |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `25` | informativos; el envío real lo hace el MTA local vía `sendmail` |
| `EMAIL_NOOP` | `false` | `true` desactiva el envío (tests, dev sin MTA) |

### Admin (opcional)

Si los tres están configurados, se siembra un usuario admin (idempotente). Si
falta cualquiera, no se siembra y solo se loguea un warning. **No hay hash por
defecto** — generá el tuyo con `htpasswd` o equivalente.

| Variable | Default |
|---|---|
| `ADMIN_EMAIL` | `""` |
| `ADMIN_PHONE` | `""` |
| `ADMIN_NAME` | `Admin` |
| `ADMIN_PASSWORD_HASH` | `""` (bcrypt; ej. `htpasswd -nbBC 10 "" "tu_password"`) |

### Referidos (opt-in)

| Variable | Default | Notas |
|---|---|---|
| `REQUIRE_REFERRAL` | `false` | `true`: `referral_code` obligatorio en `/auth/register`. Las tablas `user_referral_codes` y `user_referrals` se crean siempre. |

## Endpoints

Todas las rutas viven bajo `/api/v1`. Las rutas marcadas como protegidas
requieren `Authorization: Bearer <token>`.

### Auth (públicas)

| Método | Ruta | Notas |
|---|---|---|
| POST | `/auth/register` | acepta `email` y/o `phone`; `referral_code` opcional o requerido según `REQUIRE_REFERRAL` |
| POST | `/auth/login` | si el usuario no está verificado responde 403 con `data: { user_id, email }`. Lockout por cuenta: 429 tras 10 fallos en 15 min |
| POST | `/auth/refresh` | rota el refresh token y revisa `token_version` |
| POST | `/auth/check-availability` | rate-limited 10/min |
| POST | `/auth/check-referral` | rate-limited 10/min |
| POST | `/auth/verify-code` | rate-limited 20/min |
| POST | `/auth/resend-verification-code` | exige `user_id+password`; 429 si excede |
| POST | `/auth/forgot-password` | rate-limited 5/min |
| POST | `/auth/reset-password` | re-emite tokens con `token_version+1` |

### Auth (protegidas)

| Método | Ruta | Notas |
|---|---|---|
| POST | `/auth/change-password` | bumpea `token_version`; devuelve nuevos tokens |
| POST | `/auth/logout` | revocación real: bumpea `token_version`, invalida todos los tokens (access y refresh) |

### Users (protegidas)

| Método | Ruta |
|---|---|
| GET | `/users/profile` |
| GET | `/users/:id` |
| PUT | `/users/:id` |
| DELETE | `/users/:id` |

### Documents (protegidas)

| Método | Ruta |
|---|---|
| POST | `/documents/upload` |
| GET | `/documents` |

### Admin (protegidas + AdminChecker)

Gate por **rol persistido** (`users.role == 'admin'`, asignado solo por el seed;
nunca por la API pública), con fallback legacy por email+teléfono para bases
previas a la columna `role`.

| Método | Ruta |
|---|---|
| GET | `/admin/users` (paginado, `q`, summary global) |
| GET | `/admin/audit-logs` (paginado; trail de toda mutación con status, IP y request_id) |

### Health

| Método | Ruta |
|---|---|
| GET | `/health` |

## Arquitectura

```
internal/
  application/      use cases + ports (interfaces)
    auth/           register, login, refresh, verify, forgot/reset/change password, resend, check-referral
    user/           list (admin)
    document/       upload, list, get
  domain/           entidades sin dependencias externas
  config/           Config + Dependencies (composition root)
  infrastructure/
    http/           handlers, middleware, routes
    persistence/    mysql repos, transaction_runner, local_storage
    security/       JWT, bcrypt, AdminChecker, VerificationService
    email/          SMTPSender (sendmail), NoopSender
pkg/
  errors/           AppError con Data + sentinels
  httptime/         RFC3339 en America/Bogota
test/
  integration/      tests con MySQL real (TEST_DB_*)
  unit/             tests sin BD
```

### Atomicidad

`mysql.TransactionRunner` (interfaz `application.TransactionRunner`) abre una
transacción y la inyecta en `context.Context`. Los repos leen la tx con
`dbFrom`/`execContextFrom`, así que un caso de uso compone llamadas de
varios repos bajo una misma transacción sin tocar la implementación de los
repos:

```go
err := txRunner.WithTransaction(ctx, func(txCtx context.Context) error {
    if err := userRepo.Update(txCtx, u); err != nil { return err }
    return otherRepo.Insert(txCtx, x)
})
```

### Revocación de sesión

Cada usuario tiene un `token_version`. Los JWT lo embeben como claim; el
middleware lo compara contra el valor en BD en cada request. `change-password`
y `reset-password` lo incrementan via `UpdatePasswordAndBumpTokenVersion`,
revocando todos los tokens emitidos antes.

### Verificación de contacto

`VerificationService` genera un código de 6 dígitos con `crypto/rand`,
lo entrega a email y/o teléfono (mismo código a ambos si el usuario tiene los
dos), aplica rate limit (5/h con 8s mínimo entre envíos) y cae a logging del
código en consola para SMS no implementado. La plantilla HTML usa
`APP_NAME` y `APP_BRAND_COLOR`.

### Store compartido (Redis opt-in)

Tanto el rate-limiter HTTP como los códigos de verificación se respaldan en un
`Store` con dos implementaciones (patrón estrategia):

- **In-memory** (por defecto): estado en el proceso. Simple y sin infra, pero se
  pierde al reiniciar y **no** se comparte entre instancias.
- **Redis** (si `REDIS_URL` está seteada): contadores y códigos viven en Redis
  con operaciones atómicas (scripts Lua), por lo que el límite es consistente y
  un código emitido por una réplica se verifica en otra. El rate-limiter es
  *fail-open* si Redis cae (sirve la petición y registra un warning, en vez de
  tumbar el endpoint).

La selección se hace una sola vez en `BuildDependencies` según `REDIS_URL`.

## Desarrollo

```bash
make test       # corre tests
make lint       # vet + linting si está configurado
make build      # binario en ./generic-backend-go
make run        # arranca con go run
```

Para tests de integración con MySQL real:

```bash
TEST_DB_HOST=127.0.0.1 TEST_DB_USER=root TEST_DB_PASS=password \
TEST_DB_NAME=generictest \
go test ./test/integration/...
```

## Notas

- Las fechas en respuestas se formatean en `America/Bogota` (RFC3339) por
  convención del autor; cambiar `pkg/httptime` si tu deployment vive en otra zona.
- Los archivos subidos se guardan en `STORAGE_PATH/<userID>/<UUID>.<ext>`.
- Los logs salen a stdout en JSON estructurado.
- Las contraseñas se hashean con bcrypt.
- Los códigos de verificación viven en memoria; reemplazar por Redis/DB para
  multi-instancia o tolerancia a reinicios.

## Licencia

MIT.
