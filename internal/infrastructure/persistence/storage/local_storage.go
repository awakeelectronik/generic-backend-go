package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
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

	// Crear carpeta por usuario: documents/uploads/{userID}/. DEBE coincidir con
	// relativeStoredPath de abajo: Get() une la ruta guardada sobre basePath, así
	// que si escribimos en otra carpeta la descarga falla con NotFound.
	userDir := filepath.Join(ls.basePath, "documents", "uploads", userID)
	if err := os.MkdirAll(userDir, 0755); err != nil {
		return "", "", appErrors.NewAppErrorWithInternal(
			"STORAGE_ERROR",
			"Error creating user directory",
			500,
			err,
		)
	}

	// Path completo en disco: {basePath}/documents/uploads/{userID}/{UUID}.{ext}
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

// Get abre un archivo para lectura.
//
// Defensa contra path traversal: aunque hoy filePath suele provenir de la BD
// (escrito por el servidor), si en el futuro alguna ruta lo deja influenciar
// por entrada externa, segmentos "../" no pueden escapar de basePath. Tras
// resolver con filepath.Abs, el path final debe estar dentro de basePath.
func (ls *LocalStorage) Get(ctx context.Context, filePath string) (io.ReadCloser, error) {
	// Normalizar separadores (por si en BD se guardó con \).
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	absBase, err := filepath.Abs(ls.basePath)
	if err != nil {
		return nil, appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error resolviendo storage base", 500, err)
	}

	fullPath := filepath.Join(ls.basePath, filePath)
	absFull, err := filepath.Abs(fullPath)
	if err != nil {
		return nil, appErrors.NewNotFoundError("File")
	}

	// El path resuelto debe estar dentro de basePath. Si tras filepath.Join
	// el "../" lo saca a /etc o cualquier otro lado, lo tratamos como NotFound.
	if absFull != absBase && !strings.HasPrefix(absFull, absBase+string(os.PathSeparator)) {
		return nil, appErrors.NewNotFoundError("File")
	}

	file, err := os.Open(absFull)
	if err != nil {
		return nil, appErrors.NewNotFoundError("File")
	}
	return file, nil
}

// GetURL retorna la URL pública completa de un archivo
func (ls *LocalStorage) GetURL(filePath string) string {
	return fmt.Sprintf("%s/%s", ls.baseURL, filePath)
}
