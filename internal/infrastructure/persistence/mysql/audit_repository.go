package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/google/uuid"
)

// AuditRepository persiste el trail de auditoría en la tabla audit_logs
// (creada por las migraciones desde el inicio del template, ahora en uso).
type AuditRepository struct {
	db *sql.DB
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// Record inserta un evento. El caller (middleware) decide qué hacer ante un
// error — la petición auditada NUNCA debe fallar por un fallo del trail.
func (r *AuditRepository) Record(ctx context.Context, e *application.AuditEntry) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	changesJSON, err := json.Marshal(e.Changes)
	if err != nil {
		changesJSON = []byte("{}")
	}

	var userID sql.NullString
	if e.UserID != "" {
		userID = sql.NullString{String: e.UserID, Valid: true}
	}
	var resourceID sql.NullString
	if e.ResourceID != "" {
		resourceID = sql.NullString{String: e.ResourceID, Valid: true}
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO audit_logs (id, user_id, action, resource, resource_id, changes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, e.ID, userID, e.Action, e.Resource, resourceID, changesJSON, e.CreatedAt)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error registrando auditoría", 500, err)
	}
	return nil
}

// List devuelve eventos paginados (más recientes primero) y el total global.
func (r *AuditRepository) List(ctx context.Context, limit, offset int) ([]*application.AuditEntry, int, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, action, resource, resource_id, changes, created_at
		FROM audit_logs
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listando auditoría", 500, err)
	}
	defer rows.Close()

	var entries []*application.AuditEntry
	for rows.Next() {
		var e application.AuditEntry
		var userID, resource, resourceID sql.NullString
		var changesJSON []byte
		if err := rows.Scan(&e.ID, &userID, &e.Action, &resource, &resourceID, &changesJSON, &e.CreatedAt); err != nil {
			return nil, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error leyendo auditoría", 500, err)
		}
		e.UserID = userID.String
		e.Resource = resource.String
		e.ResourceID = resourceID.String
		_ = json.Unmarshal(changesJSON, &e.Changes)
		entries = append(entries, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listando auditoría", 500, err)
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&total); err != nil {
		return nil, 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error contando auditoría", 500, err)
	}

	return entries, total, nil
}
