package document

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	apperrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	"github.com/sirupsen/logrus"
)

// sniffLen es la ventana que http.DetectContentType inspecciona (512 bytes,
// como define la spec de MIME sniffing del WHATWG).
const sniffLen = 512

type UploadDocumentUseCase struct {
	documentRepo application.DocumentRepository
	fileStorage  application.FileStorage
	maxFileSize  int64
	allowedMimes []string
	logger       *logrus.Logger
}

// NewUploadDocumentUseCase wires the upload flow.
//
// allowedMimes restricts accepted MIME types. Empty/nil disables the check
// (every type accepted). Matching is exact and case-insensitive.
func NewUploadDocumentUseCase(
	documentRepo application.DocumentRepository,
	fileStorage application.FileStorage,
	maxFileSize int64,
	allowedMimes []string,
	logger *logrus.Logger,
) *UploadDocumentUseCase {
	normalized := make([]string, 0, len(allowedMimes))
	for _, m := range allowedMimes {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "" {
			normalized = append(normalized, m)
		}
	}
	return &UploadDocumentUseCase{
		documentRepo: documentRepo,
		fileStorage:  fileStorage,
		maxFileSize:  maxFileSize,
		allowedMimes: normalized,
		logger:       logger,
	}
}

// Execute valida y persiste la subida. El tipo MIME NO se toma del cliente: se
// infiere de los bytes reales del archivo (http.DetectContentType), porque el
// Content-Type y la extensión los controla quien sube. El tipo inferido es a la
// vez el filtro de seguridad y lo que se guarda, así la descarga sirve el tipo
// verificado.
func (u *UploadDocumentUseCase) Execute(
	ctx context.Context,
	userID string,
	fileName string,
	file io.Reader,
	fileSize int64,
) (*domain.Document, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "userID es obligatorio", 400)
	}
	if strings.TrimSpace(fileName) == "" {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "fileName es obligatorio", 400)
	}
	if file == nil {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "file es obligatorio", 400)
	}
	if fileSize <= 0 {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", "fileSize debe ser mayor a 0", 400)
	}
	if fileSize > u.maxFileSize {
		return nil, apperrors.NewAppError(
			"FILE_TOO_LARGE",
			"El archivo excede el tamaño máximo permitido",
			413,
		)
	}

	// Leemos los primeros bytes para inferir el MIME real. ReadFull tolera
	// archivos más cortos que sniffLen (EOF/ErrUnexpectedEOF no son fallo).
	head := make([]byte, sniffLen)
	n, err := io.ReadFull(file, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		u.logger.WithError(err).Error("Failed to read upload for MIME sniffing")
		return nil, apperrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error leyendo archivo", 500, err)
	}
	head = head[:n]

	detectedMime := http.DetectContentType(head)
	if !u.isMimeAllowed(detectedMime) {
		return nil, apperrors.NewAppError(
			"UNSUPPORTED_MEDIA_TYPE",
			"Tipo de archivo no permitido",
			415,
		)
	}

	// Re-anteponemos los bytes ya leídos para que Save escriba el archivo completo.
	full := io.MultiReader(bytes.NewReader(head), file)

	storedPath, originalName, err := u.fileStorage.Save(ctx, userID, fileName, full, fileSize)
	if err != nil {
		u.logger.WithError(err).Error("Failed to save file")
		return nil, apperrors.NewAppErrorWithInternal("STORAGE_ERROR", "Error guardando archivo", 500, err)
	}

	doc, err := domain.NewDocument(userID, originalName, storedPath, detectedMime, fileSize)
	if err != nil {
		return nil, apperrors.NewAppError("VALIDATION_ERROR", err.Error(), 400)
	}

	if err := u.documentRepo.Create(ctx, doc); err != nil {
		u.logger.WithError(err).Error("Failed to create document record")
		return nil, err
	}

	u.logger.WithFields(logrus.Fields{
		"document_id":   doc.ID,
		"user_id":       userID,
		"original_name": originalName,
		"stored_path":   storedPath,
	}).Info("Document uploaded successfully")

	return doc, nil
}

func (u *UploadDocumentUseCase) isMimeAllowed(mimeType string) bool {
	if len(u.allowedMimes) == 0 {
		return true
	}
	got := strings.ToLower(strings.TrimSpace(mimeType))
	if got == "" {
		return false
	}
	// El navegador puede mandar "image/jpeg; charset=binary" o similar; comparar por prefijo del tipo principal.
	if i := strings.IndexByte(got, ';'); i >= 0 {
		got = strings.TrimSpace(got[:i])
	}
	for _, allowed := range u.allowedMimes {
		if got == allowed {
			return true
		}
	}
	return false
}
