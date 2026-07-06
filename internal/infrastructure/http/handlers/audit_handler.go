package handlers

import (
	"net/http"
	"strconv"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/pkg/httptime"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// AuditHandler expone el trail de auditoría al administrador (solo lectura).
type AuditHandler struct {
	audit  application.AuditLogger
	logger *logrus.Logger
}

func NewAuditHandler(audit application.AuditLogger, logger *logrus.Logger) *AuditHandler {
	return &AuditHandler{audit: audit, logger: logger}
}

type auditEntryOutput struct {
	ID         string         `json:"id"`
	UserID     string         `json:"user_id,omitempty"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource,omitempty"`
	ResourceID string         `json:"resource_id,omitempty"`
	Changes    map[string]any `json:"changes,omitempty"`
	CreatedAt  string         `json:"created_at"`
}

// List devuelve eventos de auditoría paginados (?page=&page_size=), más
// recientes primero. Ruta admin: el trail contiene IPs y user_ids.
func (h *AuditHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > application.MaxPageSize {
		pageSize = application.MaxPageSize
	}
	offset := (page - 1) * pageSize

	entries, total, err := h.audit.List(c.Request.Context(), pageSize, offset)
	if err != nil {
		HandleError(c, err)
		return
	}

	out := make([]auditEntryOutput, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditEntryOutput{
			ID:         e.ID,
			UserID:     e.UserID,
			Action:     e.Action,
			Resource:   e.Resource,
			ResourceID: e.ResourceID,
			Changes:    e.Changes,
			CreatedAt:  httptime.FormatRFC3339(e.CreatedAt),
		})
	}

	SuccessResponse(c, http.StatusOK, gin.H{
		"entries": out,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     total,
		},
	})
}
