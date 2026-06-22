package handlers

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/application/document"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type DocumentHandler struct {
	uploadUC   *document.UploadDocumentUseCase
	listUC     *document.ListDocumentsUseCase
	downloadUC *document.DownloadDocumentUseCase
	logger     *logrus.Logger
}

func NewDocumentHandler(
	uploadUC *document.UploadDocumentUseCase,
	listUC *document.ListDocumentsUseCase,
	downloadUC *document.DownloadDocumentUseCase,
	logger *logrus.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		uploadUC:   uploadUC,
		listUC:     listUC,
		downloadUC: downloadUC,
		logger:     logger,
	}
}

// Upload accepts a multipart "document" field and persists the file.
func (h *DocumentHandler) Upload(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "No autorizado")
		return
	}

	file, err := c.FormFile("document")
	if err != nil {
		h.logger.WithError(err).Warn("Missing file in request")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Archivo 'document' es obligatorio")
		return
	}

	src, err := file.Open()
	if err != nil {
		h.logger.WithError(err).Error("Failed to open uploaded file")
		ErrorResponse(c, http.StatusInternalServerError, "STORAGE_ERROR", "No se pudo leer el archivo")
		return
	}
	defer src.Close()

	// El cliente puede no enviar Content-Type por parte (e.g. multipart simple).
	// Inferimos desde la extensión para que la validación de MIME en el use
	// case tenga algo concreto contra qué chequear.
	mimeType := strings.TrimSpace(file.Header.Get("Content-Type"))
	if mimeType == "" || mimeType == "application/octet-stream" {
		if guessed := mime.TypeByExtension(strings.ToLower(filepath.Ext(file.Filename))); guessed != "" {
			mimeType = guessed
		}
	}

	doc, err := h.uploadUC.Execute(
		c.Request.Context(),
		userID,
		file.Filename,
		src,
		file.Size,
		mimeType,
	)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, gin.H{
		"document_id": doc.ID,
		"file_name":   doc.FileName,
		"file_path":   doc.FilePath,
		"status":      doc.Status,
	})
}

// List returns the authenticated user's documents, paginated via ?page=&page_size=.
func (h *DocumentHandler) List(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "No autorizado")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > application.MaxPageSize {
		pageSize = application.MaxPageSize
	}
	offset := (page - 1) * pageSize

	out, err := h.listUC.Execute(c.Request.Context(), userID, pageSize, offset)
	if err != nil {
		HandleError(c, err)
		return
	}
	SuccessResponse(c, http.StatusOK, out)
}

// Download streams a document's bytes back to the client. Ownership is
// enforced inside the use case; non-owners get 403 even if they guess the id.
func (h *DocumentHandler) Download(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		ErrorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", "No autorizado")
		return
	}

	doc, reader, err := h.downloadUC.Execute(c.Request.Context(), c.Param("id"), userID)
	if err != nil {
		HandleError(c, err)
		return
	}
	defer reader.Close()

	contentType := strings.TrimSpace(doc.MimeType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, doc.FileName))
	c.Header("Content-Length", strconv.FormatInt(doc.FileSize, 10))
	c.Status(http.StatusOK)

	if _, err := io.Copy(c.Writer, reader); err != nil {
		// Headers ya salieron; no podemos cambiar el status. Solo dejamos rastro.
		h.logger.WithError(err).WithField("document_id", doc.ID).Warn("Document stream interrupted")
	}
}
