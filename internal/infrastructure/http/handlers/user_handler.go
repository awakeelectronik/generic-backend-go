package handlers

import (
	"net/http"
	"strconv"

	userUC "github.com/awakeelectronik/generic-backend-go/internal/application/user"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type UserHandler struct {
	listUsersUC  *userUC.ListUsersUseCase
	getUserUC    *userUC.GetUserUseCase
	updateUserUC *userUC.UpdateUserUseCase
	deleteUserUC *userUC.DeleteUserUseCase
	logger       *logrus.Logger
}

func NewUserHandler(
	listUsersUC *userUC.ListUsersUseCase,
	getUserUC *userUC.GetUserUseCase,
	updateUserUC *userUC.UpdateUserUseCase,
	deleteUserUC *userUC.DeleteUserUseCase,
	logger *logrus.Logger,
) *UserHandler {
	return &UserHandler{
		listUsersUC:  listUsersUC,
		getUserUC:    getUserUC,
		updateUserUC: updateUserUC,
		deleteUserUC: deleteUserUC,
		logger:       logger,
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

func (h *UserHandler) GetByID(c *gin.Context) {
	out, err := h.getUserUC.Execute(c.Request.Context(), c.GetString("user_id"), c.Param("id"))
	if err != nil {
		HandleError(c, err)
		return
	}
	SuccessResponse(c, http.StatusOK, out)
}

// GetProfile is a convenience for the authenticated user — equivalent to
// GET /users/:id with id == current user.
func (h *UserHandler) GetProfile(c *gin.Context) {
	currentUserID := c.GetString("user_id")
	out, err := h.getUserUC.Execute(c.Request.Context(), currentUserID, currentUserID)
	if err != nil {
		HandleError(c, err)
		return
	}
	SuccessResponse(c, http.StatusOK, out)
}

func (h *UserHandler) Update(c *gin.Context) {
	var req userUC.UpdateUserInput
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Update validation error")
		ErrorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", ValidationMessageES(err))
		return
	}

	out, err := h.updateUserUC.Execute(c.Request.Context(), c.GetString("user_id"), c.Param("id"), req)
	if err != nil {
		HandleError(c, err)
		return
	}
	SuccessResponse(c, http.StatusOK, out)
}

func (h *UserHandler) Delete(c *gin.Context) {
	if err := h.deleteUserUC.Execute(c.Request.Context(), c.GetString("user_id"), c.Param("id")); err != nil {
		HandleError(c, err)
		return
	}
	SuccessResponse(c, http.StatusOK, gin.H{"message": "User deleted successfully"})
}
