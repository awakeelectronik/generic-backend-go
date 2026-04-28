package security

import (
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
)

// AdminChecker implementa application.AdminChecker comparando email y teléfono del usuario.
// Está pensado para apps con un solo administrador. Si más adelante se necesitan varios,
// reemplazar la implementación detrás de la interfaz application.AdminChecker.
type AdminChecker struct {
	Email string
	Phone string
}

// NewAdminChecker crea un checker con los datos del único admin. Si email y phone están
// ambos vacíos, IsAdmin siempre devuelve false (no hay admin configurado).
func NewAdminChecker(email, phone string) *AdminChecker {
	return &AdminChecker{Email: email, Phone: phone}
}

// IsAdmin indica si el usuario es el administrador (mismo email y teléfono).
func (a *AdminChecker) IsAdmin(user *domain.User) bool {
	if user == nil {
		return false
	}
	if a.Email == "" && a.Phone == "" {
		return false
	}
	return user.Email == a.Email && user.Phone == a.Phone
}
