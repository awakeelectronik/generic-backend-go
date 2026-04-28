package handlers

import (
	"net/http"

	"github.com/awakeelectronik/generic-backend-go/internal/application/auth"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
	registerUC           *auth.RegisterUseCase
	loginUC              *auth.LoginUseCase
	refreshUC            *auth.RefreshUseCase
	checkAvailabilityUC  *auth.CheckAvailabilityUseCase
	checkReferralUC      *auth.CheckReferralUseCase
	verifyCodeUC         *auth.VerifyCodeUseCase
	resendVerificationUC *auth.ResendVerificationUseCase
	forgotPasswordUC     *auth.ForgotPasswordUseCase
	resetPasswordUC      *auth.ResetPasswordUseCase
	changePasswordUC     *auth.ChangePasswordUseCase
	logger               *logrus.Logger
}

func NewAuthHandler(
	registerUC *auth.RegisterUseCase,
	loginUC *auth.LoginUseCase,
	refreshUC *auth.RefreshUseCase,
	checkAvailabilityUC *auth.CheckAvailabilityUseCase,
	checkReferralUC *auth.CheckReferralUseCase,
	verifyCodeUC *auth.VerifyCodeUseCase,
	resendVerificationUC *auth.ResendVerificationUseCase,
	forgotPasswordUC *auth.ForgotPasswordUseCase,
	resetPasswordUC *auth.ResetPasswordUseCase,
	changePasswordUC *auth.ChangePasswordUseCase,
	logger *logrus.Logger,
) *AuthHandler {
	return &AuthHandler{
		registerUC:           registerUC,
		loginUC:              loginUC,
		refreshUC:            refreshUC,
		checkAvailabilityUC:  checkAvailabilityUC,
		checkReferralUC:      checkReferralUC,
		verifyCodeUC:         verifyCodeUC,
		resendVerificationUC: resendVerificationUC,
		forgotPasswordUC:     forgotPasswordUC,
		resetPasswordUC:      resetPasswordUC,
		changePasswordUC:     changePasswordUC,
		logger:               logger,
	}
}

func (h *AuthHandler) CheckReferral(c *gin.Context) {
	var req auth.CheckReferralInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Referral check validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	output, err := h.checkReferralUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Registration validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	// Validate that at least email or phone is provided
	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Datos inválidos")
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
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Datos inválidos")
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
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
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
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	// Validate that at least email or phone is provided
	if err := req.Validate(); err != nil {
		if appErr, ok := err.(*appErrors.AppError); ok {
			ErrorResponse(c, appErr.StatusCode, appErr.Code, appErr.Message)
		} else {
			ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Datos inválidos")
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
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	output, err := h.verifyCodeUC.Execute(c.Request.Context(), req)
	if err != nil {
		h.logger.WithError(err).Warn("Code verification failed")

		// Provide specific error messages in Spanish
		switch err.Error() {
		case "no verification code found for user":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación no encontrado")
		case "verification code already used":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación ya utilizado")
		case "verification code expired":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación expirado")
		case "invalid verification code":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación inválido")
		default:
			ErrorResponse(c, http.StatusInternalServerError, "VERIFICATION_ERROR", "Error al verificar código")
		}
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) ResendVerificationCode(c *gin.Context) {
	var req auth.ResendVerificationInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Resend verification validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	output, err := h.resendVerificationUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req auth.ForgotPasswordInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Forgot password validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	output, err := h.forgotPasswordUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req auth.ResetPasswordInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Reset password validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	output, err := h.resetPasswordUC.Execute(c.Request.Context(), req)
	if err != nil {
		h.logger.WithError(err).Warn("Reset password failed")
		switch err.Error() {
		case "no verification code found for user":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación no encontrado")
		case "verification code already used":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación ya utilizado")
		case "verification code expired":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación expirado")
		case "invalid verification code":
			ErrorResponse(c, http.StatusBadRequest, "VERIFICATION_ERROR", "Código de verificación inválido")
		default:
			HandleError(c, err)
		}
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req auth.ChangePasswordInput

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Change password validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	req.UserID = c.GetString("user_id")
	output, err := h.changePasswordUC.Execute(c.Request.Context(), req)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
}
