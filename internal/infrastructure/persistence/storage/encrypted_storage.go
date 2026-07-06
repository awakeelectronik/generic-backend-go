package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

// encMagic prefija los archivos cifrados. Permite: (a) reconocer en disco que
// un blob está cifrado, y (b) convivir con archivos subidos ANTES de activar
// el cifrado (sin magic → se sirven tal cual, sin romper descargas antiguas).
var encMagic = []byte("GBGE1")

// EncryptedStorage envuelve un FileStorage cifrando el contenido at-rest con
// AES-256-GCM (confidencialidad + integridad: un blob manipulado en disco
// falla la autenticación al descifrar, no se sirve corrupto/alterado).
//
// El formato en disco es: magic || nonce (12B) || ciphertext+tag.
// Los archivos del template son ≤ MAX_FILE_SIZE (5 MiB default), así que
// sellar/abrir en memoria es aceptable; para archivos grandes habría que
// migrar a cifrado por chunks.
//
// La clave (32 bytes) viene de STORAGE_ENC_KEY (hex). La rotación de clave no
// está soportada aún: cambiar la clave deja ilegibles los archivos anteriores.
type EncryptedStorage struct {
	inner application.FileStorage
	aead  cipher.AEAD
}

// NewEncryptedStorage construye el decorador de cifrado sobre otro storage.
// key debe tener exactamente 32 bytes (AES-256).
func NewEncryptedStorage(inner application.FileStorage, key []byte) (*EncryptedStorage, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EncryptedStorage{inner: inner, aead: aead}, nil
}

func (es *EncryptedStorage) Save(
	ctx context.Context,
	userID string,
	fileName string,
	file io.Reader,
	size int64,
) (string, string, error) {
	plain, err := io.ReadAll(file)
	if err != nil {
		return "", "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error leyendo archivo para cifrar", 500, err)
	}

	nonce := make([]byte, es.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error generando nonce", 500, err)
	}

	sealed := make([]byte, 0, len(encMagic)+len(nonce)+len(plain)+es.aead.Overhead())
	sealed = append(sealed, encMagic...)
	sealed = append(sealed, nonce...)
	sealed = es.aead.Seal(sealed, nonce, plain, nil)

	return es.inner.Save(ctx, userID, fileName, bytes.NewReader(sealed), int64(len(sealed)))
}

func (es *EncryptedStorage) Get(ctx context.Context, filePath string) (io.ReadCloser, error) {
	rc, err := es.inner.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	blob, err := io.ReadAll(rc)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error leyendo archivo cifrado", 500, err)
	}

	// Archivos previos a activar el cifrado no llevan magic: passthrough.
	if !bytes.HasPrefix(blob, encMagic) {
		return io.NopCloser(bytes.NewReader(blob)), nil
	}

	rest := blob[len(encMagic):]
	if len(rest) < es.aead.NonceSize() {
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Archivo cifrado corrupto", 500, nil)
	}
	nonce, ct := rest[:es.aead.NonceSize()], rest[es.aead.NonceSize():]

	plain, err := es.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		// Tag inválido: clave equivocada o blob manipulado en disco. NUNCA servir
		// el contenido; error opaco al cliente, detalle al log vía Internal.
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error descifrando archivo", 500, err)
	}
	return io.NopCloser(bytes.NewReader(plain)), nil
}

func (es *EncryptedStorage) GetURL(filePath string) string {
	return es.inner.GetURL(filePath)
}
