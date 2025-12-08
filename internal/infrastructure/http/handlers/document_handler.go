package handlers

import (
	"net/http"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/document"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type DocumentHandler struct {
	uploadUC *document.UploadDocumentUseCase
	listUC   *document.ListDocumentsUseCase
	logger   *logrus.Logger
}

func NewDocumentHandler(
	uploadUC *document.UploadDocumentUseCase,
	logger *logrus.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		uploadUC: uploadUC,
		logger:   logger,
	}
}

func NewDocumentHandlerWithList(
	uploadUC *document.UploadDocumentUseCase,
	listUC *document.ListDocumentsUseCase,
	logger *logrus.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		uploadUC: uploadUC,
		listUC:   listUC,
		logger:   logger,
	}
}

// Upload maneja la subida de documentos
func (h *DocumentHandler) Upload(c *gin.Context) {
	// Obtener userID del middleware
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDInterface.(string)

	// Obtener archivo del form
	file, err := c.FormFile("document")
	if err != nil {
		h.logger.WithError(err).Warn("Missing file in request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file"})
		return
	}

	// Abrir archivo
	src, err := file.Open()
	if err != nil {
		h.logger.WithError(err).Error("Failed to open uploaded file")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}
	defer src.Close()

	// ✅ Ejecutar use case (ahora con userID)
	doc, err := h.uploadUC.Execute(
		c.Request.Context(),
		userID, // ← Pasar userID para carpeta única
		file.Filename,
		src,
		file.Size,
		file.Header.Get("Content-Type"),
	)
	if err != nil {
		h.logger.WithError(err).Error("Failed to upload document")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload document"})
		return
	}

	// Respuesta exitosa
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"document_id": doc.ID,
			"file_name":   doc.FileName, // ← Nombre original
			"file_path":   doc.FilePath, // ← Path único
			"status":      doc.Status,
		},
	})
}

// List devuelve los documentos del usuario autenticado
func (h *DocumentHandler) List(c *gin.Context) {
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	userID := userIDInterface.(string)

	// Defaults
	limit := 10
	offset := 0

	out, err := h.listUC.Execute(c.Request.Context(), userID, limit, offset)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list documents")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list documents"})
		return
	}

	SuccessResponse(c, http.StatusOK, out)
}
