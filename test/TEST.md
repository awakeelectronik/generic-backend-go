# 🧪 Guía de Testing - Sumabitcoin Backend

## Resumen Rápido

Para ejecutar todos los tests y ver un resumen:

```bash
make test-summary
```

## 📋 Tests Implementados

Actualmente hay **8 test functions** con **25 subtests** de integración:

### 1. **TestAuthRegister** (5 subtests)
Valida el flujo de registro de nuevos usuarios.

- ✅ `Register successful` - Registro con email + phone
- ✅ `Register with only email` - Registro solo con email
- ✅ `Register with only phone` - Registro solo con phone
- ✅ `Register missing email and phone` - Validación: requiere al menos uno
- ✅ `Register duplicate email` - No permite duplicar email

**Validaciones:**
- Email opcional, phone opcional, pero **al menos uno obligatorio**
- Password hasheado con bcrypt
- Retorna 201 Created con datos del usuario
- Retorna 409 Conflict si email ya existe

---

### 2. **TestAuthLogin** (3 subtests)
Valida el flujo de autenticación.

- ✅ `Login successful` - Autenticación correcta
- ✅ `Login invalid credentials` - Contraseña incorrecta
- ✅ `Login user not found` - Usuario no existe

**Validaciones:**
- Verifica email + password correctos
- Retorna JWT token + refresh token
- Retorna 401 Unauthorized si credenciales inválidas
- Tokens vienen en envelope `data.token` y `data.refresh_token`

---

### 3. **TestGetUserProfile** (3 subtests)
Obtiene perfil del usuario autenticado.

- ✅ `Get profile with valid token` - Token válido
- ✅ `Get profile without token` - Sin autenticación
- ✅ `Get profile with invalid token` - Token inválido

**Validaciones:**
- Requiere JWT token válido
- Retorna 200 con datos del usuario
- Retorna 401 Unauthorized si no hay token o es inválido
- Endpoint: `GET /api/v1/users/profile`

---

### 4. **TestGetUserByID** (3 subtests)
Obtiene datos de un usuario específico.

- ✅ `Get own profile (authorized)` - Usuario accede a su propio perfil
- ✅ `Get other's profile (forbidden)` - No puede ver otro usuario
- ✅ `Get non-existent user` - Usuario no existe

**Validaciones:**
- Usuarios solo pueden ver su propio perfil
- Retorna 403 Forbidden si intenta acceder a otro
- Retorna 404 Not Found si usuario no existe
- Endpoint: `GET /api/v1/users/{userID}`

---

### 5. **TestUpdateUserProfile** (2 subtests)
Actualiza datos del usuario autenticado.

- ✅ `Update own profile` - Actualización exitosa
- ✅ `Update with missing required field` - Validación de campos requeridos

**Validaciones:**
- Requiere autenticación
- Name es obligatorio (min 2 caracteres)
- Retorna 200 si actualización es exitosa
- Retorna 400 Bad Request si faltan campos obligatorios
- Endpoint: `PUT /api/v1/users/profile`

---

### 6. **TestDocumentUpload** (3 subtests)
Valida carga de documentos.

- ✅ `Upload document successful` - Carga exitosa
- ✅ `Upload without authentication` - Sin token JWT
- ✅ `Upload without file` - Sin archivo en request

**Validaciones:**
- Requiere autenticación (JWT token)
- Valida tamaño máximo del archivo
- Genera UUID único para cada documento
- Almacena en `documents/uploads/{userID}/{fileID}`
- Retorna 201 Created con info del documento
- Retorna 401 Unauthorized si no hay token
- Retorna 400 Bad Request si no hay archivo
- Endpoint: `POST /api/v1/documents/upload`

---

### 7. **TestDocumentUploadSameFileMultipleTimes** (3 subtests)
Valida carga del mismo archivo múltiples veces.

- ✅ `Upload same file - attempt 1` - Primer upload
- ✅ `Upload same file - attempt 2` - Segundo upload
- ✅ `Upload same file - attempt 3` - Tercer upload

**Validaciones:**
- Cada carga genera UUID diferente
- Mismo archivo se puede subir múltiples veces
- Cada instancia se almacena por separado
- No hay duplicación ni sobreescritura

---

### 8. **TestListDocuments** (2+ subtests)
Lista documentos del usuario autenticado.

- ✅ `List documents with auth` - Con autenticación
- ✅ `List documents without auth` - Sin autenticación

**Validaciones:**
- Requiere autenticación
- Retorna listado de documentos del usuario
- Retorna 401 Unauthorized si no hay token
- Endpoint: `GET /api/v1/documents`

---

## 🛠️ Comandos de Testing

### Tests Rápidos

```bash
# Resumen corto con contador de tests (RECOMENDADO)
make test-summary

# Todos los tests con output detallado
make test

# Solo tests de integración
make test-integration

# Tests con output muy detallado
make test-verbose
```

### Tests Avanzados

```bash
# Tests con coverage report (HTML)
make test-coverage
# → Genera: coverage.html

# Tests con race detector (detecta condiciones de carrera)
make test-race

# Limpiar archivos de test generados
make clean
```

### Calidad de Código

```bash
# Formatear código (go fmt)
make fmt

# Análisis estático (go vet)
make vet

# Lint (golangci-lint)
make lint
```

---

## 📊 Ver Todos los Targets

```bash
make help
```

---

## 🏗️ Estructura de Tests

```
test/integration/
├── auth_test.go           # TestAuthRegister, TestAuthLogin
├── users_test.go          # TestGetUserProfile, TestGetUserByID, TestUpdateUserProfile
├── documents_test.go      # TestDocumentUpload, TestDocumentUploadSameFileMultipleTimes, TestListDocuments
├── setup_test.go          # Utilidades: SetupTestDB, SetupTestServer, InsertTestUser
└── uploads-test/          # Archivos temporales para tests de upload
```
