package integration

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/config"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/http"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/infrastructure/persistence/mysql"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// TestDB maneja la BD de prueba
type TestDB struct {
	DB *sql.DB
}

// TestServer contiene router y dependencias
type TestServer struct {
	Router        *gin.Engine
	DB            *TestDB
	Logger        *logrus.Logger
	TokenProvider application.TokenProvider
	TestToken     string // Token JWT válido
}

func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

// SetupTestDB crea una BD de prueba (fija, usando TEST_DB_NAME)
func SetupTestDB(t *testing.T) *TestDB {
	user := getenvDefault("TEST_DB_USER", "root")
	pass := getenvDefault("TEST_DB_PASS", "password")
	host := getenvDefault("TEST_DB_HOST", "127.0.0.1")
	port := getenvDefault("TEST_DB_PORT", "3306")
	name := getenvDefault("TEST_DB_NAME", "sumabitcointest")

	t.Logf("Using test DB: user=%s host=%s port=%s name=%s", user, host, port, name)

	// Conexión sin BD para crearla si no existe
	rootDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/", user, pass, host, port)
	rootDB, err := sql.Open("mysql", rootDSN)
	if err != nil {
		t.Fatalf("Failed to connect to MySQL (root DSN): %v", err)
	}
	defer rootDB.Close()

	if _, err := rootDB.Exec("CREATE DATABASE IF NOT EXISTS " + name); err != nil {
		t.Fatalf("Failed to create test database %s: %v", name, err)
	}

	// Conectar a la BD de prueba
	testDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", user, pass, host, port, name)
	testDB, err := sql.Open("mysql", testDSN)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Crear tablas (usa las mismas migraciones)
	if err := mysql.RunMigrations(testDB); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return &TestDB{DB: testDB}
}

// TeardownTestDB limpia la BD de prueba (solo cierra conexión)
func TeardownTestDB(t *testing.T, testDB *TestDB) {
	if testDB.DB != nil {
		_ = testDB.DB.Close()
	}
}

// SetupTestServer configura el servidor para pruebas
func SetupTestServer(t *testing.T, testDB *TestDB) *TestServer {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	gin.SetMode(gin.TestMode)

	router := gin.New()

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Host:     getenvDefault("TEST_DB_HOST", "127.0.0.1"),
			Port:     getenvDefault("TEST_DB_PORT", "3306"),
			User:     getenvDefault("TEST_DB_USER", "root"),
			Password: getenvDefault("TEST_DB_PASS", "password"),
			Name:     getenvDefault("TEST_DB_NAME", "sumabitcointest"),
		},
	}

	deps, err := config.BuildDependencies(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to build dependencies: %v", err)
	}

	http.SetupRoutes(router, deps, logger)

	testToken, err := deps.TokenProvider.GenerateToken("test-user-123", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	return &TestServer{
		Router:        router,
		DB:            testDB,
		Logger:        logger,
		TokenProvider: deps.TokenProvider,
		TestToken:     testToken,
	}
}

// ClearTables limpia todas las tablas entre tests
func (ts *TestServer) ClearTables() error {
	tables := []string{"documents", "users", "audit_logs"}
	for _, table := range tables {
		if _, err := ts.DB.DB.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			return err
		}
	}
	return nil
}

// InsertTestUser crea un usuario de prueba
func (ts *TestServer) InsertTestUser(userID, email, password string) error {
	query := `
        INSERT INTO users (id, email, password, name, verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, true, NOW(), NOW())
    `
	_, err := ts.DB.DB.Exec(query, userID, email, password, "Test User")
	return err
}
