package document

import (
	"context"
	"fmt"
	"io"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/awakeelectronik/sumabitcoin-backend/internal/domain"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/sirupsen/logrus"
)

type UploadDocumentInput struct {
	UserID   string
	FileName string
	File     io.Reader
	FileSize int64
	MimeType string
}

type UploadDocumentOutput struct {
	DocumentID string `json:"document_id"`
	FileName   string `json:"file_name"`
	Status     string `json:"status"`
}

type UploadDocumentUseCase struct {
	docRepo     application.DocumentRepository
	fileStorage application.FileStorage
	maxFileSize int64
	logger      *logrus.Logger
}

func NewUploadDocumentUseCase(
	docRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	maxFileSize int64,
	logger *logrus.Logger,
) *UploadDocumentUseCase {
	return &UploadDocumentUseCase{
		docRepo:     docRepo,
		fileStorage: fileStorage,
		maxFileSize: maxFileSize,
		logger:      logger,
	}
}

func (uc *UploadDocumentUseCase) Execute(ctx context.Context, input UploadDocumentInput) (*UploadDocumentOutput, error) {
	uc.logger.WithFields(logrus.Fields{
		"user_id":   input.UserID,
		"file_name": input.FileName,
		"file_size": input.FileSize,
		"mime_type": input.MimeType,
		"action":    "upload_document",
	}).Info("Document upload started")

	// Validate file size
	if input.FileSize > uc.maxFileSize {
		err := appErrors.NewValidationError("file_size", fmt.Sprintf("Max %d bytes", uc.maxFileSize))
		uc.logger.WithError(err).Warn("File size validation failed")
		return nil, err
	}

	// Validate MIME type
	if input.MimeType != "image/jpeg" && input.MimeType != "image/jpg" {
		err := appErrors.NewValidationError("mime_type", "Only JPG files allowed")
		uc.logger.WithError(err).Warn("MIME type validation failed")
		return nil, err
	}

	// Save file
	fileName := fmt.Sprintf("%s_%s", input.UserID, input.FileName)
	filePath, err := uc.fileStorage.Save(ctx, fileName, input.File, input.FileSize)
	if err != nil {
		uc.logger.WithError(err).Error("File storage failed")
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error saving document", 500, err)
	}

	// Create database record
	doc := domain.NewDocument(input.UserID, input.FileName, filePath, input.MimeType, input.FileSize)
	if err := uc.docRepo.Create(ctx, doc); err != nil {
		_ = uc.fileStorage.Delete(ctx, filePath)
		uc.logger.WithError(err).Error("Failed to save document record")
		return nil, appErrors.NewAppErrorWithInternal("DB_ERROR", "Error saving document reference", 500, err)
	}

	uc.logger.WithFields(logrus.Fields{
		"document_id": doc.ID,
		"user_id":     input.UserID,
	}).Info("Document uploaded successfully")

	return &UploadDocumentOutput{
		DocumentID: doc.ID,
		FileName:   doc.FileName,
		Status:     string(doc.Status),
	}, nil
}
