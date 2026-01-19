package handlers

import (
	"net/http"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application/auth"
	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
	registerUC          *auth.RegisterUseCase
	loginUC             *auth.LoginUseCase
	refreshUC           *auth.RefreshUseCase
	checkAvailabilityUC *auth.CheckAvailabilityUseCase
	verifyCodeUC        *auth.VerifyCodeUseCase
	logger              *logrus.Logger
}

func NewAuthHandler(
	registerUC *auth.RegisterUseCase,
	loginUC *auth.LoginUseCase,
	refreshUC *auth.RefreshUseCase,
	checkAvailabilityUC *auth.CheckAvailabilityUseCase,
	verifyCodeUC *auth.VerifyCodeUseCase,
	logger *logrus.Logger,
) *AuthHandler {
	return &AuthHandler{
		registerUC:          registerUC,
		loginUC:             loginUC,
		refreshUC:           refreshUC,
		checkAvailabilityUC: checkAvailabilityUC,
		verifyCodeUC:        verifyCodeUC,
		logger:              logger,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Registration validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	// Validate that at least email or phone is provided
	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		}
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

	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		}
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

func (h *AuthHandler) CheckAvailability(c *gin.Context) {
	var req auth.CheckAvailabilityInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Availability check validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		}
		return
	}

	output, err := h.checkAvailabilityUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) VerifyCode(c *gin.Context) {
	var req auth.VerifyCodeInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Verify code validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	output, err := h.verifyCodeUC.Execute(c.Request.Context(), req)
	if err != nil {
		// Keep error mapping explicit but generic-friendly
		switch err.Error() {
		case "no verification code found for user":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Verification code not found")
		case "verification code already used":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Verification code already used")
		case "verification code expired":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Verification code expired")
		case "invalid verification code":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Invalid verification code")
		default:
			HandleError(c, err)
		}
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
