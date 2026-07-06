package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEncryptedStorage(t *testing.T) (*EncryptedStorage, *LocalStorage, string) {
	t.Helper()
	dir := t.TempDir()
	local := NewLocalStorage(dir, "http://localhost")
	key := bytes.Repeat([]byte{0x42}, 32)
	enc, err := NewEncryptedStorage(local, key)
	require.NoError(t, err)
	return enc, local, dir
}

func TestEncryptedStorageRoundtrip(t *testing.T) {
	enc, _, dir := newTestEncryptedStorage(t)
	ctx := context.Background()
	plain := []byte("contenido super sensible KYC")

	storedPath, _, err := enc.Save(ctx, "user-1", "doc.jpg", bytes.NewReader(plain), int64(len(plain)))
	require.NoError(t, err)

	// En disco NO debe estar el plaintext y debe llevar el magic de cifrado.
	onDisk, err := os.ReadFile(filepath.Join(dir, storedPath))
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(onDisk, encMagic), "el blob debe llevar el magic GBGE1")
	assert.NotContains(t, string(onDisk), "sensible", "el plaintext no debe tocar el disco")

	// La lectura vía Get devuelve el plaintext original.
	rc, err := enc.Get(ctx, storedPath)
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

func TestEncryptedStorageRejectsTamperedBlob(t *testing.T) {
	enc, _, dir := newTestEncryptedStorage(t)
	ctx := context.Background()

	storedPath, _, err := enc.Save(ctx, "user-1", "doc.jpg", bytes.NewReader([]byte("datos")), 5)
	require.NoError(t, err)

	// Voltear un byte del ciphertext: GCM debe rechazar la autenticación.
	full := filepath.Join(dir, storedPath)
	blob, err := os.ReadFile(full)
	require.NoError(t, err)
	blob[len(blob)-1] ^= 0xFF
	require.NoError(t, os.WriteFile(full, blob, 0o600))

	_, err = enc.Get(ctx, storedPath)
	assert.Error(t, err, "un blob manipulado no debe servirse jamás")
}

func TestEncryptedStorageServesLegacyPlaintext(t *testing.T) {
	enc, local, _ := newTestEncryptedStorage(t)
	ctx := context.Background()

	// Archivo guardado ANTES de activar el cifrado (directo al storage interno).
	plain := []byte("archivo legacy sin cifrar")
	storedPath, _, err := local.Save(ctx, "user-1", "old.jpg", bytes.NewReader(plain), int64(len(plain)))
	require.NoError(t, err)

	rc, err := enc.Get(ctx, storedPath)
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, plain, got, "los archivos previos al cifrado deben seguir sirviéndose")
}
