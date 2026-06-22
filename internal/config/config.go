package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Storage  StorageConfig
	Email    EmailConfig
	Brand    BrandConfig
	Admin    AdminConfig
	Auth     AuthConfig
}

// AuthConfig toggles auth-flow behaviors that vary across deployments.
type AuthConfig struct {
	// RequireReferral makes the referral_code field mandatory in /auth/register.
	// false → optional (validated only if provided).
	RequireReferral bool
}

// AdminConfig holds the credentials of the single admin user. If any of these
// are empty, the admin is NOT seeded and AdminChecker.IsAdmin always returns
// false. Each clone of this template fills these in via .env. There is no
// hardcoded default password — keep it that way to avoid baking known
// credentials into a public repo.
type AdminConfig struct {
	Email        string
	Phone        string
	Name         string
	PasswordHash string // bcrypt hash; NEVER store plaintext here.
}

// BrandConfig holds the per-deployment identity used in emails and other
// user-facing strings. Each clone of this template fills these in.
type BrandConfig struct {
	AppName  string // shown in From header, subjects and email headings
	BrandHex string // hex color (e.g. #f7931a) for accents in HTML emails
}

// EmailConfig wires the SMTPSender to a local MTA. Noop=true skips real
// delivery (tests, local dev without sendmail).
type EmailConfig struct {
	From string
	Host string
	Port string
	Noop bool
}

type ServerConfig struct {
	Port        string
	Environment string
	BaseURL     string
	// AllowedOrigins son los orígenes permitidos por CORS (env
	// CORS_ALLOWED_ORIGINS, separados por coma). "*" habilita cualquier origen
	// pero SIN credenciales (combinación inválida según la spec). Para usar
	// credenciales, lista orígenes concretos.
	AllowedOrigins []string
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	MaxConn  int
	IdleConn int
	MaxLife  time.Duration
}

type JWTConfig struct {
	Secret          string
	ExpirationHours int
	RefreshHours    int
	IssuerName      string
}

type StorageConfig struct {
	Type         string
	LocalPath    string
	MaxFileSize  int64
	AllowedMimes []string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Port:           getEnv("PORT", "8080"),
			Environment:    getEnv("ENVIRONMENT", "development"),
			BaseURL:        getEnv("BASE_URL", "http://localhost:8080"),
			AllowedOrigins: getEnvCSV("CORS_ALLOWED_ORIGINS", []string{"*"}),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "3306"),
			User:     getEnv("DB_USER", "root"),
			Password: getEnv("DB_PASSWORD", ""),
			Name:     getEnv("DB_NAME", "identity_db"),
			MaxConn:  getEnvInt("DB_MAX_CONN", 25),
			IdleConn: getEnvInt("DB_IDLE_CONN", 5),
			MaxLife:  time.Hour,
		},
		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", ""),
			ExpirationHours: getEnvInt("JWT_EXPIRATION", 24),
			// 8760h = 1 año. Como /auth/refresh rota el refresh en cada uso,
			// la sesión se mantiene viva mientras el usuario abra la app
			// al menos una vez al año.
			RefreshHours: getEnvInt("JWT_REFRESH", 8760),
			IssuerName:   "identity-api",
		},
		Storage: StorageConfig{
			Type:         "local",
			LocalPath:    getEnv("STORAGE_PATH", "./uploads"),
			MaxFileSize:  int64(getEnvInt("MAX_FILE_SIZE", 5*1024*1024)),
			AllowedMimes: []string{"image/jpeg", "image/jpg"},
		},
		Email: EmailConfig{
			From: getEnv("SMTP_FROM", "noreply@app.local"),
			Host: getEnv("SMTP_HOST", "localhost"),
			Port: getEnv("SMTP_PORT", "25"),
			Noop: getEnvBool("EMAIL_NOOP", false),
		},
		Brand: BrandConfig{
			AppName:  getEnv("APP_NAME", "MyApp"),
			BrandHex: getEnv("APP_BRAND_COLOR", "#000000"),
		},
		Admin: AdminConfig{
			Email:        getEnv("ADMIN_EMAIL", ""),
			Phone:        getEnv("ADMIN_PHONE", ""),
			Name:         getEnv("ADMIN_NAME", "Admin"),
			PasswordHash: getEnv("ADMIN_PASSWORD_HASH", ""),
		},
		Auth: AuthConfig{
			RequireReferral: getEnvBool("REQUIRE_REFERRAL", false),
		},
	}

	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET not configured")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getEnvCSV lee una variable separada por comas y devuelve los valores no
// vacíos ya trimmeados. Si la variable no está, devuelve defaultValue.
func getEnvCSV(key string, defaultValue []string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return defaultValue
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return defaultValue
	}
	return out
}

func getEnvBool(key string, defaultValue bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return defaultValue
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}
