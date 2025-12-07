package document

import (
	"context"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
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

	documents := make([]GetDocumentOutput, 0)
	for _, doc := range docs {
		documents = append(documents, GetDocumentOutput{
			ID:        doc.ID,
			FileName:  doc.FileName,
			FileSize:  doc.FileSize,
			Status:    string(doc.Status),
			FileURL:   doc.FilePath,
			CreatedAt: doc.CreatedAt.String(),
		})
	}

	return &ListDocumentsOutput{
		Documents: documents,
		Total:     len(documents),
	}, nil
}
