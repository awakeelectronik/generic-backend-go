package handlers

import (
	"net/http"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/auth"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
	registerUC *auth.RegisterUseCase
	loginUC    *auth.LoginUseCase
	refreshUC  *auth.RefreshUseCase
	logger     *logrus.Logger
}

func NewAuthHandler(
	registerUC *auth.RegisterUseCase,
	loginUC *auth.LoginUseCase,
	refreshUC *auth.RefreshUseCase,
	logger *logrus.Logger,
) *AuthHandler {
	return &AuthHandler{
		registerUC: registerUC,
		loginUC:    loginUC,
		refreshUC:  refreshUC,
		logger:     logger,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Registration validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.registerUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusCreated, output)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Login validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.loginUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req auth.RefreshInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Refresh validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.refreshUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
