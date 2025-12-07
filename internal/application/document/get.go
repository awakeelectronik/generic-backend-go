package document

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type GetDocumentOutput struct {
	ID        string `json:"id"`
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	Status    string `json:"status"`
	FileURL   string `json:"file_url"`
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
		FileURL:   doc.FilePath,
		CreatedAt: doc.CreatedAt.String(),
	}, nil
}
