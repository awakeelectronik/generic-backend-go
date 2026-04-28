package mysql

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// DatabaseConfig se define AQUÍ (local), no importado desde config
// Esto rompe el ciclo: mysql ya no importa el paquete config
type DatabaseConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	Name     string
	MaxConn  int
	IdleConn int
	MaxLife  time.Duration
}

func NewConnection(user, password, host, port, name string, maxConn, idleConn int, maxLife time.Duration) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true",
		user,
		password,
		host,
		port,
		name,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(maxConn)
	db.SetMaxIdleConns(idleConn)
	db.SetConnMaxLifetime(maxLife)

	return db, nil
}

func RunMigrations(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(36) PRIMARY KEY,
			email VARCHAR(255) UNIQUE NULL,
			password VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			phone VARCHAR(20),
			verified BOOLEAN DEFAULT false,
			token_version INT NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			INDEX idx_email (email),
			INDEX idx_deleted_at (deleted_at)
		)`,
		// Backward-compatible adjustments for existing DBs:
		// allow phone-only registration by making email nullable, and normalize empty strings -> NULL.
		`ALTER TABLE users MODIFY email VARCHAR(255) NULL`,
		`ALTER TABLE users MODIFY phone VARCHAR(20) NULL`,
		`UPDATE users SET email = NULL WHERE email = ''`,
		`UPDATE users SET phone = NULL WHERE phone = ''`,
		`CREATE TABLE IF NOT EXISTS documents (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) NOT NULL,
			file_name VARCHAR(255) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			file_size BIGINT NOT NULL,
			mime_type VARCHAR(50) NOT NULL,
			status VARCHAR(50) DEFAULT 'pending',
			metadata JSON,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_user_id (user_id),
			INDEX idx_status (status),
			INDEX idx_created_at (created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36),
			action VARCHAR(255) NOT NULL,
			resource VARCHAR(255),
			resource_id VARCHAR(36),
			changes JSON,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_user_id (user_id),
			INDEX idx_action (action),
			INDEX idx_created_at (created_at)
		)`,
		// Referral tables: always created so the feature can be toggled at runtime
		// (REQUIRE_REFERRAL). Cost is two empty tables when unused.
		`CREATE TABLE IF NOT EXISTS user_referral_codes (
			user_id VARCHAR(36) PRIMARY KEY,
			code VARCHAR(6) UNIQUE NOT NULL,
			max_referrals INT NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			INDEX idx_referral_code (code)
		)`,
		`CREATE TABLE IF NOT EXISTS user_referrals (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(36) UNIQUE NOT NULL,
			referrer_user_id VARCHAR(36) NOT NULL,
			code_used VARCHAR(6) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (referrer_user_id) REFERENCES users(id) ON DELETE RESTRICT,
			INDEX idx_referrer_user_id (referrer_user_id)
		)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return err
		}
	}

	// Idempotent column adds for existing DBs.
	if err := ensureUsersTokenVersionColumn(db); err != nil {
		return err
	}

	return nil
}

// ensureUsersTokenVersionColumn adds users.token_version on existing DBs. Idempotent.
func ensureUsersTokenVersionColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 1`)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "duplicate") || strings.Contains(msg, "1060") {
		return nil
	}
	return fmt.Errorf("ensure users.token_version: %w", err)
}
