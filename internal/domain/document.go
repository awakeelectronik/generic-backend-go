package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DocumentStatus string

const (
	StatusPending  DocumentStatus = "pending"
	StatusVerified DocumentStatus = "verified"
	StatusRejected DocumentStatus = "rejected"
)

var (
	ErrDocumentEmptyUserID   = errors.New("document userID is required")
	ErrDocumentEmptyFileName = errors.New("document fileName is required")
	ErrDocumentEmptyFilePath = errors.New("document filePath is required")
	ErrDocumentInvalidSize   = errors.New("document fileSize must be greater than 0")
)

type Document struct {
	ID        string
	UserID    string
	FileName  string
	FilePath  string
	FileSize  int64
	MimeType  string
	Status    DocumentStatus
	Metadata  map[string]interface{}
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewDocument(userID, fileName, filePath, mimeType string, fileSize int64) (*Document, error) {
	userID = strings.TrimSpace(userID)
	fileName = strings.TrimSpace(fileName)
	filePath = strings.TrimSpace(filePath)

	if userID == "" {
		return nil, ErrDocumentEmptyUserID
	}
	if fileName == "" {
		return nil, ErrDocumentEmptyFileName
	}
	if filePath == "" {
		return nil, ErrDocumentEmptyFilePath
	}
	if fileSize <= 0 {
		return nil, ErrDocumentInvalidSize
	}

	now := time.Now()
	return &Document{
		ID:        uuid.New().String(),
		UserID:    userID,
		FileName:  fileName,
		FilePath:  filePath,
		MimeType:  mimeType,
		FileSize:  fileSize,
		Status:    StatusPending,
		Metadata:  make(map[string]interface{}),
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (d *Document) Verify() {
	d.Status = StatusVerified
	d.UpdatedAt = time.Now()
}

func (d *Document) Reject() {
	d.Status = StatusRejected
	d.UpdatedAt = time.Now()
}
