package domain

import (
	"errors"
	"testing"
)

func TestNewDocument_valid(t *testing.T) {
	d, err := NewDocument(" u1 ", " a.jpg ", " documents/uploads/u1/x.jpg ", "image/jpeg", 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.UserID != "u1" || d.FileName != "a.jpg" || d.FilePath != "documents/uploads/u1/x.jpg" {
		t.Fatalf("fields not trimmed: %+v", d)
	}
	if d.Status != StatusPending {
		t.Fatalf("a new document should be pending, got %q", d.Status)
	}
	if d.Metadata == nil {
		t.Fatalf("metadata should be a non-nil map")
	}
	if d.ID == "" {
		t.Fatalf("expected a generated ID")
	}
}

func TestNewDocument_validations(t *testing.T) {
	cases := []struct {
		name                     string
		userID, file, path, mime string
		size                     int64
		want                     error
	}{
		{"no userID", "", "a.jpg", "p", "image/jpeg", 1, ErrDocumentEmptyUserID},
		{"no fileName", "u1", "", "p", "image/jpeg", 1, ErrDocumentEmptyFileName},
		{"no filePath", "u1", "a.jpg", "", "image/jpeg", 1, ErrDocumentEmptyFilePath},
		{"zero size", "u1", "a.jpg", "p", "image/jpeg", 0, ErrDocumentInvalidSize},
		{"negative size", "u1", "a.jpg", "p", "image/jpeg", -5, ErrDocumentInvalidSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewDocument(c.userID, c.file, c.path, c.mime, c.size); !errors.Is(err, c.want) {
				t.Fatalf("expected %v, got %v", c.want, err)
			}
		})
	}
}

func TestDocument_verifyAndReject(t *testing.T) {
	d, _ := NewDocument("u1", "a.jpg", "p", "image/jpeg", 1)
	d.Verify()
	if d.Status != StatusVerified {
		t.Fatalf("Verify should set verified, got %q", d.Status)
	}
	d.Reject()
	if d.Status != StatusRejected {
		t.Fatalf("Reject should set rejected, got %q", d.Status)
	}
}
