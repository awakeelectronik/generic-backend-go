package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

type DocumentRepository struct {
	db *sql.DB
}

func NewDocumentRepository(db *sql.DB) *DocumentRepository {
	return &DocumentRepository{db: db}
}

func (r *DocumentRepository) Create(ctx context.Context, doc *domain.Document) error {
	metadataJSON, _ := json.Marshal(doc.Metadata)

	query := `
		INSERT INTO documents (id, user_id, file_name, file_path, file_size, mime_type, status, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := execContextFrom(ctx, r.db).ExecContext(ctx, query,
		doc.ID, doc.UserID, doc.FileName, doc.FilePath, doc.FileSize,
		doc.MimeType, doc.Status, metadataJSON,
	)

	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error saving document", 500, err)
	}

	return nil
}

func (r *DocumentRepository) GetByID(ctx context.Context, id string) (*domain.Document, error) {
	query := `
		SELECT id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at
		FROM documents WHERE id = ?
	`

	var doc domain.Document
	var metadataJSON []byte

	err := dbFrom(ctx, r.db).QueryRowContext(ctx, query, id).Scan(
		&doc.ID, &doc.UserID, &doc.FileName, &doc.FilePath, &doc.FileSize,
		&doc.MimeType, &doc.Status, &metadataJSON, &doc.CreatedAt, &doc.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, appErrors.NewNotFoundError("Document")
	}
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching document", 500, err)
	}

	json.Unmarshal(metadataJSON, &doc.Metadata)
	return &doc, nil
}

func (r *DocumentRepository) GetByUserID(ctx context.Context, userID string, limit, offset int) ([]*domain.Document, error) {
	query := `
		SELECT id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at
		FROM documents 
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := dbFrom(ctx, r.db).QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error listing documents", 500, err)
	}
	defer rows.Close()

	var documents []*domain.Document
	for rows.Next() {
		var doc domain.Document
		var metadataJSON []byte

		err := rows.Scan(
			&doc.ID, &doc.UserID, &doc.FileName, &doc.FilePath, &doc.FileSize,
			&doc.MimeType, &doc.Status, &metadataJSON, &doc.CreatedAt, &doc.UpdatedAt,
		)
		if err != nil {
			return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error scanning document", 500, err)
		}

		json.Unmarshal(metadataJSON, &doc.Metadata)
		documents = append(documents, &doc)
	}

	return documents, nil
}

// CountByUserID returns the total document count for a user (for pagination metadata).
func (r *DocumentRepository) CountByUserID(ctx context.Context, userID string) (int, error) {
	var count int
	err := dbFrom(ctx, r.db).QueryRowContext(ctx,
		`SELECT COUNT(*) FROM documents WHERE user_id = ?`, userID,
	).Scan(&count)
	if err != nil {
		return 0, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error counting documents", 500, err)
	}
	return count, nil
}

func (r *DocumentRepository) Update(ctx context.Context, doc *domain.Document) error {
	metadataJSON, _ := json.Marshal(doc.Metadata)

	query := `
		UPDATE documents 
		SET status = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, doc.Status, metadataJSON, time.Now(), doc.ID)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error updating document", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("Document")
	}

	return nil
}

func (r *DocumentRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM documents WHERE id = ?`

	result, err := execContextFrom(ctx, r.db).ExecContext(ctx, query, id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting document", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("Document")
	}

	return nil
}
