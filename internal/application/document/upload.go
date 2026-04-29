package document

import (
	"context"
	"io"
	"strings"

	apperrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	"github.com/sirupsen/logrus"
)

type UploadDocumentUseCase struct {
	documentRepo application.DocumentRepository
	fileStorage  application.FileStorage
	maxFileSize  int64
	allowedMimes []string
	logger       *logrus.Logger
}

// NewUploadDocumentUseCase wires the upload flow.
//
// allowedMimes restricts accepted MIME types. Empty/nil disables the check
// (every type accepted). Matching is exact and case-insensitive.
func NewUploadDocumentUseCase(
	documentRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	maxFileSize int64,
	allowedMimes []string,
	logger *logrus.Logger,
) *UploadDocumentUseCase {
	normalized := make([]string, 0, len(allowedMimes))
	for _, m := range allowedMimes {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "" {
			normalized = append(normalized, m)
		}
	}
	return &UploadDocumentUseCase{
		documentRepo: documentRepo,
		fileStorage:  fileStorage,
		maxFileSize:  maxFileSize,
		allowedMimes: normalized,
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
	if strings.TrimSpace(userID) == "" {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "userID es obligatorio", 400)
	}
	if strings.TrimSpace(fileName) == "" {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "fileName es obligatorio", 400)
	}
	if file == nil {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "file es obligatorio", 400)
	}
	if fileSize <= 0 {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "fileSize debe ser mayor a 0", 400)
	}
	if fileSize > u.maxFileSize {
		return nil, apperrors.NewAppError(
			"FILE_TOO_LARGE",
			"El archivo excede el tamaño máximo permitido",
			413,
		)
	}
	if !u.isMimeAllowed(mimeType) {
		return nil, apperrors.NewAppError(
			"UNSUPPORTED_MEDIA_TYPE",
			"Tipo de archivo no permitido",
			415,
		)
	}

	storedPath, originalName, err := u.fileStorage.Save(ctx, userID, fileName, file, fileSize)
	if err != nil {
		u.logger.WithError(err).Error("Failed to save file")
		return nil, apperrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error guardando archivo", 500, err)
	}

	doc, err := domain.NewDocument(userID, originalName, storedPath, mimeType, fileSize)
	if err != nil {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", err.Error(), 400)
	}

	if err := u.documentRepo.Create(ctx, doc); err != nil {
		u.logger.WithError(err).Error("Failed to create document record")
		return nil, err
	}

	u.logger.WithFields(logrus.Fields{
		"document_id":   doc.ID,
		"user_id":       userID,
		"original_name": originalName,
		"stored_path":   storedPath,
	}).Info("Document uploaded successfully")

	return doc, nil
}

func (u *UploadDocumentUseCase) isMimeAllowed(mimeType string) bool {
	if len(u.allowedMimes) == 0 {
		return true
	}
	got := strings.ToLower(strings.TrimSpace(mimeType))
	if got == "" {
		return false
	}
	// El navegador puede mandar "image/jpeg; charset=binary" o similar; comparar por prefijo del tipo principal.
	if i := strings.IndexByte(got, ';'); i >= 0 {
		got = strings.TrimSpace(got[:i])
	}
	for _, allowed := range u.allowedMimes {
		if got == allowed {
			return true
		}
	}
	return false
}
