
```markdown
#  Clean Architecture Backend

## Instalación

### Requisitos
- Go 1.21+
- MySQL 8.0+

### Pasos

1. **Clonar y configurar**
```bash
git clone https://github.com/awakeelectronik/sumabitcoin-backend.git
cd sumabitcoin-backend
nano .env
```

```bash
# Environment
ENVIRONMENT=development
PORT=8080
BASE_URL=http://localhost:8080

# Database
DB_HOST=
DB_PORT=3306
DB_USER=
DB_PASSWORD=
DB_NAME=
DB_MAX_CONN=3
DB_IDLE_CONN=5

# JWT
JWT_SECRET=
JWT_EXPIRATION=24
JWT_REFRESH=168

# Storage
STORAGE_PATH=./uploads-suma
MAX_FILE_SIZE=5242880
```


2. **Instalar dependencias**
```bash
make install
```

3. **Configurar BD**
```bash
# Crear base de datos MySQL
mysql -u root -p
> CREATE DATABASE sumabitcoin;
```

4. **Ejecutar**
```bash
make run
```

## API Endpoints

**Login**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -d '{ "email": "user@example.com",  "password": "SecurePass123!" }'
```

**Refresh Token**

```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh -H "Content-Type: application/json" -d '{ "refresh_token":  "token" }'
```


### Usuarios (Protegidos)

**Obtener perfil**

```bash
curl -v -X GET http://localhost:8080/api/v1/users/402e59cb-cfe0-4c8a-8634-3614d29cf450   -H "Authorization: Bearer token"
```

**Actualizar perfil**
```bash
PUT /api/v1/users/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Nuevo Name",
  "phone": "+573009876543"
}
```

**Eliminar cuenta**
```bash
DELETE /api/v1/users/:id
Authorization: Bearer <token>
```

### Documentos (Protegidos)

**Subir documento**
```bash
POST /api/v1/documents/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

Form Data:
- document: <archivo.jpg>
```

**Listar documentos**
```bash
GET /api/v1/documents?limit=10&offset=0
Authorization: Bearer <token>
```

**Obtener documento**
```bash
GET /api/v1/documents/:id
Authorization: Bearer <token>
```

## Testing con cURL

```bash
# Health check
curl http://localhost:8080/health

# Registrarse
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "name": "Test User",
    "phone": "+573001234567"
  }'

# Login
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "phone": "+573001234567",
    "password": "SecurePass123!"
  }'

# Subir documento
curl -X POST http://localhost:8080/api/v1/documents/upload -H "Authorization: Bearer token" -F "document=@a.jpeg"

# Listar documentos
curl -X GET "http://localhost:8080/api/v1/documents?limit=10&offset=0" \
-H "Authorization: Bearer token"
```


## Desarrollo

```bash
# Ejecutar tests
make test

# Linting
make lint

# Compilar
make build

# Ejecutar binario compilado
./sumabitcoin
```

## Notas

- Los archivos se guardan en `./uploads`
- Los logs se muestran en stdout
- Las contraseñas se hashean con bcrypt
- Los tokens JWT expiran en 24 horas
- Los refresh tokens expiran en 7 días


Creado con ❤️ usando Go y Clean Architecture


**Instalar dependencias:**
```bash
go mod download
go mod tidy
```

**Configurar .env:**
```bash
cp .env.example .env
# Editar .env con tus datos
```

**Ejecutar:**
```bash
go run ./cmd/main.go
```

