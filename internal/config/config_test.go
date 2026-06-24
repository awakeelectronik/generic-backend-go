package config

import (
	"strings"
	"testing"
)

// withCleanEnv aísla cada caso: limpia las variables que Load() lee para JWT y
// las restaura al terminar, evitando contaminación cruzada entre tests (y con un
// .env presente en el árbol de trabajo).
func withCleanEnv(t *testing.T, secret string) {
	t.Helper()
	t.Setenv("JWT_SECRET", secret)
}

func TestLoad_RejectsEmptyJWTSecret(t *testing.T) {
	withCleanEnv(t, "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for empty JWT_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected 'not configured' error, got %v", err)
	}
}

func TestLoad_RejectsShortJWTSecret(t *testing.T) {
	// 31 bytes: justo por debajo del mínimo de 32.
	withCleanEnv(t, strings.Repeat("a", minJWTSecretBytes-1))

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short JWT_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "too weak") {
		t.Fatalf("expected 'too weak' error, got %v", err)
	}
}

func TestLoad_AcceptsStrongJWTSecret(t *testing.T) {
	withCleanEnv(t, strings.Repeat("a", minJWTSecretBytes))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error for 32-byte secret, got %v", err)
	}
	if cfg.JWT.Secret == "" {
		t.Fatal("expected secret to be loaded")
	}
}
