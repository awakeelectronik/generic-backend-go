package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Storage  StorageConfig
}

type ServerConfig struct {
	Port        string
	Environment string
	BaseURL     string
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
			Port:        getEnv("PORT", "8080"),
			Environment: getEnv("ENVIRONMENT", "development"),
			BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),
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
			RefreshHours:    getEnvInt("JWT_REFRESH", 168),
			IssuerName:      "identity-api",
		},
		Storage: StorageConfig{
			Type:         "local",
			LocalPath:    getEnv("STORAGE_PATH", "./uploads"),
			MaxFileSize:  int64(getEnvInt("MAX_FILE_SIZE", 5*1024*1024)),
			AllowedMimes: []string{"image/jpeg", "image/jpg"},
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
