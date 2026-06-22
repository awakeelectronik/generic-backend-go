package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalStorage_saveThenGetRoundTrips is the regression test for the
// write/return path mismatch: Save must store bytes where the path it returns
// (and Get) will look for them.
func TestLocalStorage_saveThenGetRoundTrips(t *testing.T) {
	ls := NewLocalStorage(t.TempDir(), "http://example.test")
	content := "hello-bytes"

	stored, original, err := ls.Save(context.Background(), "user-1", "a.jpg", strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if original != "a.jpg" {
		t.Fatalf("original name = %q, want a.jpg", original)
	}

	rc, err := ls.Get(context.Background(), stored)
	if err != nil {
		t.Fatalf("get the just-saved path %q: %v", stored, err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != content {
		t.Fatalf("round-trip mismatch: got %q want %q", got, content)
	}
}

// TestLocalStorage_getRejectsPathTraversal ensures a "../" path cannot escape
// basePath even when the target file exists.
func TestLocalStorage_getRejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	secret := filepath.Join(filepath.Dir(base), "traversal-secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0600); err != nil {
		t.Fatalf("setup secret: %v", err)
	}
	defer os.Remove(secret)

	ls := NewLocalStorage(base, "http://example.test")
	if _, err := ls.Get(context.Background(), "../traversal-secret.txt"); err == nil {
		t.Fatalf("expected a traversal path to be rejected, but Get succeeded")
	}
}

func TestLocalStorage_getMissingReturnsError(t *testing.T) {
	ls := NewLocalStorage(t.TempDir(), "http://example.test")
	if _, err := ls.Get(context.Background(), "documents/uploads/user-1/nope.jpg"); err == nil {
		t.Fatalf("expected an error for a missing file")
	}
}

func TestLocalStorage_saveGivesUniquePaths(t *testing.T) {
	ls := NewLocalStorage(t.TempDir(), "http://example.test")
	p1, _, err := ls.Save(context.Background(), "u", "a.jpg", strings.NewReader("x"), 1)
	if err != nil {
		t.Fatalf("save 1: %v", err)
	}
	p2, _, err := ls.Save(context.Background(), "u", "a.jpg", strings.NewReader("y"), 1)
	if err != nil {
		t.Fatalf("save 2: %v", err)
	}
	if p1 == p2 {
		t.Fatalf("two saves of the same filename must yield distinct stored paths")
	}
}
