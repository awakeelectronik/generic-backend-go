package handlers

import (
	"net/http"
	"strconv"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/document"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type DocumentHandler struct {
	uploadUC *document.UploadDocumentUseCase
	getUC    *document.GetDocumentUseCase
	listUC   *document.ListDocumentsUseCase
	logger   *logrus.Logger
}

func NewDocumentHandler(
	uploadUC *document.UploadDocumentUseCase,
	getUC *document.GetDocumentUseCase,
	listUC *document.ListDocumentsUseCase,
	logger *logrus.Logger,
) *DocumentHandler {
	return &DocumentHandler{
		uploadUC: uploadUC,
		getUC:    getUC,
		listUC:   listUC,
		logger:   logger,
	}
}

func (h *DocumentHandler) Upload(c *gin.Context) {
	userID := c.GetString("user_id")

	file, header, err := c.Request.FormFile("document")
	if err != nil {
		h.logger.WithError(err).Warn("File form error")
		ErrorResponse(c, http.StatusBadRequest, "INVALID_FILE", "No file provided")
		return
	}
	defer file.Close()

	mimeType := header.Header.Get("Content-Type")
	if mimeType != "image/jpeg" && mimeType != "image/jpg" {
		ErrorResponse(c, http.StatusBadRequest, "INVALID_MIME", "Only JPG files allowed")
		return
	}

	input := document.UploadDocumentInput{
		UserID:   userID,
		FileName: header.Filename,
		File:     file,
		FileSize: header.Size,
		MimeType: mimeType,
	}

	output, err := h.uploadUC.Execute(c.Request.Context(), input)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusCreated, output)
}

func (h *DocumentHandler) Get(c *gin.Context) {
	documentID := c.Param("id")
	userID := c.GetString("user_id")

	output, err := h.getUC.Execute(c.Request.Context(), documentID, userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *DocumentHandler) List(c *gin.Context) {
	userID := c.GetString("user_id")

	limitStr := c.DefaultQuery("limit", "10")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	output, err := h.listUC.Execute(c.Request.Context(), userID, limit, offset)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
