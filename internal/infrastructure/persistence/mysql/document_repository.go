package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
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
		INSERT INTO documents (id, user_id, file_name, file_path, file_size, mime_type, status, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		doc.ID, doc.UserID, doc.FileName, doc.FilePath, doc.FileSize,
		doc.MimeType, doc.Status, metadataJSON, doc.CreatedAt, doc.UpdatedAt,
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

	err := r.db.QueryRowContext(ctx, query, id).Scan(
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

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
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
			continue
		}

		json.Unmarshal(metadataJSON, &doc.Metadata)
		documents = append(documents, &doc)
	}

	return documents, nil
}

func (r *DocumentRepository) Update(ctx context.Context, doc *domain.Document) error {
	metadataJSON, _ := json.Marshal(doc.Metadata)

	query := `
		UPDATE documents 
		SET status = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query, doc.Status, metadataJSON, time.Now(), doc.ID)
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

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return appErrors.NewAppErrorWithInternal("DB_ERROR", "Error deleting document", 500, err)
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return appErrors.NewNotFoundError("Document")
	}

	return nil
}
