package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/google/uuid"
)

type LocalStorage struct {
	basePath string
	baseURL  string
}

func NewLocalStorage(basePath, baseURL string) *LocalStorage {
	os.MkdirAll(basePath, 0755)
	return &LocalStorage{
		basePath: basePath,
		baseURL:  baseURL,
	}
}

// Save guarda un archivo con carpeta por usuario y nombre único
//
// Parámetros:
//   - ctx: contexto
//   - userID: ID del usuario (para carpeta única)
//   - fileName: nombre original del archivo (a2.jpeg)
//   - file: contenido del archivo
//   - size: tamaño del archivo
//
// Retorna:
//   - storedPath: ruta relativa única en disco (para BD)
//   - originalName: nombre original (para mostrar)
//   - error
func (ls *LocalStorage) Save(
	ctx context.Context,
	userID string,
	fileName string,
	file io.Reader,
	size int64,
) (storedPath string, originalName string, err error) {
	// Guardar el nombre original (sin manipular)
	originalName = filepath.Base(fileName)

	// Extraer extensión del archivo original (.jpg, .png, etc)
	ext := filepath.Ext(originalName)

	// Generar nombre único: {UUID}.{extensión}
	uniqueName := uuid.NewString() + ext

	// Crear carpeta por usuario si no existe: uploads/{userID}/
	userDir := filepath.Join(ls.basePath, "uploads", userID)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", "", appErrors.NewAppErrorWithInternal(
			"STORAGE_ERROR",
			"Error creating user directory",
			500,
			err,
		)
	}

	// Path completo en disco: /basePath/uploads/{userID}/{UUID}.{ext}
	fullPath := filepath.Join(userDir, uniqueName)

	// Crear el archivo en disco
	outFile, err := os.Create(fullPath)
	if err != nil {
		return "", "", appErrors.NewAppErrorWithInternal(
			"STORAGE_ERROR",
			"Error creating file",
			500,
			err,
		)
	}
	defer outFile.Close()

	// Copiar contenido
	if _, err := io.Copy(outFile, file); err != nil {
		os.Remove(fullPath) // Limpiar si falla
		return "", "", appErrors.NewAppErrorWithInternal(
			"STORAGE_ERROR",
			"Error writing file",
			500,
			err,
		)
	}

	// Ruta relativa para guardar en BD (lo que se devuelve)
	// Ej: documents/uploads/{userID}/{UUID}.jpg
	relativeStoredPath := filepath.Join("documents", "uploads", userID, uniqueName)

	return relativeStoredPath, originalName, nil
}

// Delete elimina un archivo usando su stored path
func (ls *LocalStorage) Delete(ctx context.Context, filePath string) error {
	fullPath := filepath.Join(ls.basePath, filePath)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return appErrors.NewAppErrorWithInternal(
			"STORAGE_ERROR",
			"Error deleting file",
			500,
			err,
		)
	}
	return nil
}

// Get abre un archivo para lectura
func (ls *LocalStorage) Get(ctx context.Context, filePath string) (io.ReadCloser, error) {
	fullPath := filepath.Join(ls.basePath, filePath)
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, appErrors.NewNotFoundError("File")
	}
	return file, nil
}

// GetURL retorna la URL pública completa de un archivo
func (ls *LocalStorage) GetURL(filePath string) string {
	return fmt.Sprintf("%s/%s", ls.baseURL, filePath)
}
