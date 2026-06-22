package domain

import (
	"errors"
	"testing"
)

func TestNewUser_validEmailOnly(t *testing.T) {
	u, err := NewUser("  a@b.com ", "hashed", " Alice ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Email != "a@b.com" || u.Name != "Alice" {
		t.Fatalf("fields not trimmed: email=%q name=%q", u.Email, u.Name)
	}
	if u.ID == "" {
		t.Fatalf("expected a generated ID")
	}
	if u.TokenVersion != 1 {
		t.Fatalf("expected TokenVersion 1, got %d", u.TokenVersion)
	}
	if u.Verified {
		t.Fatalf("a new user must start unverified")
	}
}

func TestNewUser_validPhoneOnly(t *testing.T) {
	if _, err := NewUser("", "hashed", "Bob", "3001234567"); err != nil {
		t.Fatalf("phone-only user should be valid: %v", err)
	}
}

func TestNewUser_requiresContact(t *testing.T) {
	if _, err := NewUser("", "hashed", "Bob", ""); !errors.Is(err, ErrUserNoContact) {
		t.Fatalf("expected ErrUserNoContact, got %v", err)
	}
}

func TestNewUser_requiresName(t *testing.T) {
	if _, err := NewUser("a@b.com", "hashed", "  ", ""); !errors.Is(err, ErrUserEmptyName) {
		t.Fatalf("expected ErrUserEmptyName, got %v", err)
	}
}

func TestNewUser_requiresPassword(t *testing.T) {
	if _, err := NewUser("a@b.com", "", "Alice", ""); !errors.Is(err, ErrUserEmptyPassword) {
		t.Fatalf("expected ErrUserEmptyPassword, got %v", err)
	}
}

func TestUser_isActiveAndDelete(t *testing.T) {
	u, _ := NewUser("a@b.com", "hashed", "Alice", "")
	if !u.IsActive() {
		t.Fatalf("a fresh user should be active")
	}
	u.Delete()
	if u.IsActive() {
		t.Fatalf("a deleted user must not be active")
	}
	if u.DeletedAt == nil {
		t.Fatalf("Delete must set DeletedAt")
	}
}
