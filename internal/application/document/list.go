package document

import (
	"context"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ListDocumentsOutput struct {
	Documents []GetDocumentOutput `json:"documents"`
	Total     int                 `json:"total"`
}

type ListDocumentsUseCase struct {
	docRepo application.DocumentRepository
	logger  *logrus.Logger
}

func NewListDocumentsUseCase(
	docRepo application.DocumentRepository,
	logger *logrus.Logger,
) *ListDocumentsUseCase {
	return &ListDocumentsUseCase{
		docRepo: docRepo,
		logger:  logger,
	}
}

func (uc *ListDocumentsUseCase) Execute(ctx context.Context, userID string, limit, offset int) (*ListDocumentsOutput, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, appErrors.NewAppError("VALIDATION_ERROR", "userID es obligatorio", 400)
	}
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100 // tope para evitar páginas gigantes / abuso de recursos
	}
	if offset < 0 {
		offset = 0
	}

	uc.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"limit":   limit,
		"offset":  offset,
		"action":  "list_documents",
	}).Info("Listing documents")

	docs, err := uc.docRepo.GetByUserID(ctx, userID, limit, offset)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to list documents")
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error fetching documents", 500, err)
	}

	total, err := uc.docRepo.CountByUserID(ctx, userID)
	if err != nil {
		uc.logger.WithError(err).Error("Failed to count documents")
		return nil, err
	}

	documents := make([]GetDocumentOutput, 0, len(docs))
	for _, doc := range docs {
		documents = append(documents, GetDocumentOutput{
			ID:        doc.ID,
			FileName:  doc.FileName,
			FileSize:  doc.FileSize,
			Status:    string(doc.Status),
			FilePath:  doc.FilePath,
			CreatedAt: doc.CreatedAt.String(),
		})
	}

	return &ListDocumentsOutput{
		Documents: documents,
		Total:     total,
	}, nil
}
