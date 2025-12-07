package domain

import (
	"time"

	"github.com/google/uuid"
)

type DocumentStatus string

const (
	StatusPending  DocumentStatus = "pending"
	StatusVerified DocumentStatus = "verified"
	StatusRejected DocumentStatus = "rejected"
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

func NewDocument(userID, fileName, filePath, mimeType string, fileSize int64) *Document {
	return &Document{
		ID:        uuid.New().String(),
		UserID:    userID,
		FileName:  fileName,
		FilePath:  filePath,
		MimeType:  mimeType,
		FileSize:  fileSize,
		Status:    StatusPending,
		Metadata:  make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (d *Document) Verify() {
	d.Status = StatusVerified
	d.UpdatedAt = time.Now()
}

func (d *Document) Reject() {
	d.Status = StatusRejected
	d.UpdatedAt = time.Now()
}
