package handlers

import (
	"net/http"

	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/gin-gonic/gin"
)

type SuccessResponseBody struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

type ErrorResponseBody struct {
	Success bool   `json:"success"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func SuccessResponse(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, SuccessResponseBody{
		Success: true,
		Data:    data,
	})
}

func ErrorResponse(c *gin.Context, statusCode int, code, message string) {
	c.JSON(statusCode, ErrorResponseBody{
		Success: false,
		Code:    code,
		Message: message,
	})
}

func HandleError(c *gin.Context, err error) {
	if appErr, ok := err.(*appErrors.AppError); ok {
		// Do not leak internal details for server errors.
		if appErr.StatusCode >= 500 {
			c.JSON(appErr.StatusCode, ErrorResponseBody{
				Success: false,
				Code:    appErr.Code,
				Message: "Error interno del servidor",
			})
			return
		}
		c.JSON(appErr.StatusCode, ErrorResponseBody{
			Success: false,
			Code:    appErr.Code,
			Message: appErr.Message,
		})
		return
	}

	c.JSON(http.StatusInternalServerError, ErrorResponseBody{
		Success: false,
		Code:    "INTERNAL_ERROR",
		Message: "Error interno del servidor",
	})
}
