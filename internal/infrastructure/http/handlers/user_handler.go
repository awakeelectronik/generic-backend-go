package handlers

import (
	"net/http"
	"strconv"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	userUC "github.com/awakeelectronik/generic-backend-go/internal/application/user"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type UserHandler struct {
	userRepo    application.UserRepository
	listUsersUC *userUC.ListUsersUseCase
	logger      *logrus.Logger
}

func NewUserHandler(
	userRepo application.UserRepository,
	listUsersUC *userUC.ListUsersUseCase,
	logger *logrus.Logger,
) *UserHandler {
	return &UserHandler{
		userRepo:    userRepo,
		listUsersUC: listUsersUC,
		logger:      logger,
	}
}

// List returns a paginated list of users with global summary counts.
// Intended for admin use; protect at the route level.
func (h *UserHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	q := c.Query("q")

	output, err := h.listUsersUC.Execute(c.Request.Context(), page, pageSize, q)
	if err != nil {
		HandleError(c, err)
		return
	}

	SuccessResponse(c, http.StatusOK, output)
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
	Name  string `json:"name" binding:"required,min=2"`
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

	// Extra guard: ensure name is present (some test contexts may not trigger validator)
	if req.Name == "" {
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "name is required")
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

// GetProfile returns the profile of the currently authenticated user
func (h *UserHandler) GetProfile(c *gin.Context) {
	currentUserID := c.GetString("user_id")

	user, err := h.userRepo.GetByID(c.Request.Context(), currentUserID)
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
