package document

import (
	"context"
	"io"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DownloadDocumentUseCase resolves a document by id, enforces ownership, and
// opens its underlying file for streaming. The handler is responsible for
// closing the returned ReadCloser and writing the proper response headers.
type DownloadDocumentUseCase struct {
	docRepo     application.DocumentRepository
	fileStorage application.FileStorage
	logger      *logrus.Logger
}

func NewDownloadDocumentUseCase(
	docRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	logger *logrus.Logger,
) *DownloadDocumentUseCase {
	return &DownloadDocumentUseCase{
		docRepo:     docRepo,
		fileStorage: fileStorage,
		logger:      logger,
	}
}

// Execute returns the document metadata and an open reader to its bytes.
// Caller MUST close the returned reader.
func (uc *DownloadDocumentUseCase) Execute(ctx context.Context, documentID, userID string) (*domain.Document, io.ReadCloser, error) {
	if strings.TrimSpace(documentID) == "" {
		return nil, nil, appErrors.NewAppError("VALIDATION_ERROR", "documentID es obligatorio", 400)
	}
	if strings.TrimSpace(userID) == "" {
		return nil, nil, appErrors.ErrUnauthorized
	}

	doc, err := uc.docRepo.GetByID(ctx, documentID)
	if err != nil {
		return nil, nil, err
	}
	if doc.UserID != userID {
		uc.logger.WithFields(logrus.Fields{
			"document_id": documentID,
			"user_id":     userID,
		}).Warn("Unauthorized document download attempt")
		return nil, nil, appErrors.ErrForbidden
	}

	reader, err := uc.fileStorage.Get(ctx, doc.FilePath)
	if err != nil {
		return nil, nil, err
	}
	return doc, reader, nil
}
