package handlers

import (
	"net/http"

	"github.com/awakeelectronik/sumabitcoin-backend/internal/application"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type UserHandler struct {
	userRepo application.UserRepository
	logger   *logrus.Logger
}

func NewUserHandler(
	userRepo application.UserRepository,
	logger *logrus.Logger,
) *UserHandler {
	return &UserHandler{
		userRepo: userRepo,
		logger:   logger,
	}
}

type UserOutput struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
}

func (h *UserHandler) GetByID(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		h.logger.WithFields(logrus.Fields{
			"user_id":         userID,
			"current_user_id": currentUserID,
		}).Warn("Unauthorized user access")
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot access other user's profile")
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, UserOutput{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Phone:     user.Phone,
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt.String(),
	})
}

type UpdateUserInput struct {
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

func (h *UserHandler) Update(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot update other user's profile")
		return
	}

	var req UpdateUserInput
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Update validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		HandleError(c, err)
		return
	}

	user.Name = req.Name
	user.Phone = req.Phone

	if err := h.userRepo.Update(c.Request.Context(), user); err != nil {
		HandleError(c, err)
		return
	}

	h.logger.WithField("user_id", userID).Info("User updated successfully")

	SuccessResponse(c, http.StatusOK, UserOutput{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Phone:     user.Phone,
		Verified:  user.Verified,
		CreatedAt: user.CreatedAt.String(),
	})
}

func (h *UserHandler) Delete(c *gin.Context) {
	userID := c.Param("id")
	currentUserID := c.GetString("user_id")

	if userID != currentUserID {
		ErrorResponse(c, http.StatusForbidden, "FORBIDDEN", "Cannot delete other user")
		return
	}

	if err := h.userRepo.Delete(c.Request.Context(), userID); err != nil {
		HandleError(c, err)
		return
	}

	h.logger.WithField("user_id", userID).Info("User deleted successfully")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
	})
}
