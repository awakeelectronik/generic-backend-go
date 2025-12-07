package document

import (
	"context"
	"fmt"
	"io"

	apperrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UploadDocumentUseCase struct {
	documentRepo application.DocumentRepository
	fileStorage  application.FileStorage
	maxFileSize  int64
	logger       *logrus.Logger
}

func NewUploadDocumentUseCase(
	documentRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	maxFileSize int64,
	logger *logrus.Logger,
) *UploadDocumentUseCase {
	return &UploadDocumentUseCase{
		documentRepo: documentRepo,
		fileStorage:  fileStorage,
		maxFileSize:  maxFileSize,
		logger:       logger,
	}
}

func (u *UploadDocumentUseCase) Execute(
	ctx context.Context,
	userID string,
	fileName string,
	file io.Reader,
	fileSize int64,
	mimeType string,
) (*domain.Document, error) {
	// Validaciones
	if fileSize > u.maxFileSize {
		return nil, fmt.Errorf("file size exceeds maximum: %d > %d", fileSize, u.maxFileSize)
	}

	// ✅ CAMBIO: Pasar userID al Save
	storedPath, originalName, err := u.fileStorage.Save(
		ctx,
		userID, // ← Nueva carpeta por usuario
		fileName,
		file,
		fileSize,
	)
	if err != nil {
		u.logger.WithError(err).Error("Failed to save file")
		return nil, fmt.Errorf("failed to save file: %w", err)
	}

	// Crear documento
	doc := &domain.Document{
		ID:       uuid.NewString(),
		UserID:   userID,
		FileName: originalName, // ← Nombre original para el usuario
		FilePath: storedPath,   // ← Path único en disco
		FileSize: fileSize,
		MimeType: mimeType,
		Status:   "pending",
	}

	// Guardar en BD
	if err := u.documentRepo.Create(ctx, doc); err != nil {
		u.logger.WithError(err).Error("Failed to create document record")
		// Limpiar archivo si falla el registro BD
		// Si el error de la aplicación contiene un error interno (por ejemplo MySQL),
		// envolver y devolver ese error interno para que la consola muestre el detalle.
		if appErr, ok := err.(*apperrors.AppError); ok {
			if appErr.Internal != nil {
				return nil, fmt.Errorf("failed to create document: %w", appErr.Internal)
			}
		}
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	u.logger.WithFields(logrus.Fields{
		"document_id":   doc.ID,
		"user_id":       userID,
		"original_name": originalName,
		"stored_path":   storedPath,
	}).Info("Document uploaded successfully")

	return doc, nil
}
