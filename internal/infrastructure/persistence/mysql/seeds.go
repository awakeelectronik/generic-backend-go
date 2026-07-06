package mysql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SeedAdminUser inserts an admin user with the given email/phone if no user with
// that email or phone already exists. passwordHash must be a precomputed bcrypt
// hash; this function does NOT hash a plaintext. Returns true if a row was
// inserted, false if an existing user matched (idempotent).
//
// Required: email, phone and passwordHash. If any is empty, returns
// (false, nil) without touching the DB so callers can opt out simply by
// leaving the env vars unset.
func SeedAdminUser(db *sql.DB, email, phone, name, passwordHash string) (bool, error) {
	if email == "" || phone == "" || passwordHash == "" {
		return false, nil
	}

	var existingID string
	err := db.QueryRow(`
		SELECT id FROM users
		WHERE (email = ? OR phone = ?) AND deleted_at IS NULL
		LIMIT 1
	`, email, phone).Scan(&existingID)

	if err == nil {
		// Backfill idempotente del rol: bases creadas antes de la columna `role`
		// tienen al admin con role='user'; sin esto perdería acceso admin al
		// pasar el AdminChecker a estar basado en rol.
		if _, err := db.Exec(`UPDATE users SET role = 'admin' WHERE id = ? AND role <> 'admin'`, existingID); err != nil {
			return false, fmt.Errorf("backfill admin role: %w", err)
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, fmt.Errorf("check existing admin: %w", err)
	}

	now := time.Now()
	id := uuid.NewString()
	_, err = db.Exec(`
		INSERT INTO users (id, email, password, name, phone, role, verified, token_version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'admin', TRUE, 1, ?, ?)
	`, id, email, passwordHash, name, phone, now, now)
	if err != nil {
		return false, fmt.Errorf("insert admin user: %w", err)
	}

	return true, nil
}
