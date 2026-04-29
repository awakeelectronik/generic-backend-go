package document

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type GetDocumentOutput struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	Status    string `json:"status"`
	// FilePath is the server-side relative path. To download, hit
	// GET /api/v1/documents/:id/download (which streams the file behind auth).
	FilePath  string `json:"file_path"`
	CreatedAt string `json:"created_at"`
}

type GetDocumentUseCase struct {
	docRepo application.DocumentRepository
	logger  *logrus.Logger
}

func NewGetDocumentUseCase(
	docRepo application.DocumentRepository,
	logger *logrus.Logger,
) *GetDocumentUseCase {
	return &GetDocumentUseCase{
		docRepo: docRepo,
		logger:  logger,
	}
}

func (uc *GetDocumentUseCase) Execute(ctx context.Context, documentID, userID string) (*GetDocumentOutput, error) {
	if strings.TrimSpace(documentID) == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "documentID es obligatorio", 400)
	}
	if strings.TrimSpace(userID) == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "userID es obligatorio", 400)
	}

	uc.logger.WithFields(logrus.Fields{
		"document_id": documentID,
		"user_id":     userID,
		"action":      "get_document",
	}).Info("Fetching document")

	doc, err := uc.docRepo.GetByID(ctx, documentID)
	if err != nil {
		uc.logger.WithError(err).Warn("Document not found")
		return nil, appErrors.NewNotFoundError("Document")
	}

	if doc.UserID != userID {
		uc.logger.WithFields(logrus.Fields{
			"document_id": documentID,
			"user_id":     userID,
		}).Warn("Unauthorized access to document")
		return nil, appErrors.ErrForbidden
	}

	return &GetDocumentOutput{
		ID:        doc.ID,
		FileName:  doc.FileName,
		FileSize:  doc.FileSize,
		Status:    string(doc.Status),
		FilePath:  doc.FilePath,
		CreatedAt: doc.CreatedAt.String(),
	}, nil
}
