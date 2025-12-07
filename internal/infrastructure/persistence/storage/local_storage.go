package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
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

func (ls *LocalStorage) Save(ctx context.Context, fileName string, file io.Reader, size int64) (string, error) {
	fileName = filepath.Base(fileName)
	filePath := filepath.Join(ls.basePath, fileName)

	outFile, err := os.Create(filePath)
	if err != nil {
		return "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error creating file", 500, err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, file); err != nil {
		os.Remove(filePath)
		return "", appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error writing file", 500, err)
	}

	return filepath.Join("documents", fileName), nil
}

func (ls *LocalStorage) Delete(ctx context.Context, filePath string) error {
	fullPath := filepath.Join(ls.basePath, filePath)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return appErrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error deleting file", 500, err)
	}
	return nil
}

func (ls *LocalStorage) Get(ctx context.Context, filePath string) (io.ReadCloser, error) {
	fullPath := filepath.Join(ls.basePath, filePath)
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, appErrors.NewNotFoundError("File")
	}
	return file, nil
}

func (ls *LocalStorage) GetURL(filePath string) string {
	return fmt.Sprintf("%s/%s", ls.baseURL, filePath)
}
