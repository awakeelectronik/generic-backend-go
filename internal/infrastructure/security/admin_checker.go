package security

import (
	"strings"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
)

// AdminChecker implementa application.AdminChecker.
//
// Fuente primaria: el ROL persistido del usuario (users.role == 'admin'),
// asignado solo por el seed — nunca por la API pública. Fallback legacy: match
// de email+teléfono contra la config, para bases donde el admin existe pero el
// seed aún no corrió el backfill del rol. El fallback compara email
// case-insensitive porque los correos se normalizan a minúsculas al registrar
// pero la config puede venir con mayúsculas.
type AdminChecker struct {
	Email string
	Phone string
}

// NewAdminChecker crea un checker con los datos del único admin. Si email y phone están
// ambos vacíos, el fallback legacy queda deshabilitado (el rol persistido sigue valiendo).
func NewAdminChecker(email, phone string) *AdminChecker {
	return &AdminChecker{Email: email, Phone: phone}
}

// IsAdmin indica si el usuario es administrador (rol persistido o fallback legacy).
func (a *AdminChecker) IsAdmin(user *domain.User) bool {
	if user == nil {
		return false
	}
	if user.IsAdmin() {
		return true
	}
	if a.Email == "" && a.Phone == "" {
		return false
	}
	return strings.EqualFold(user.Email, a.Email) && user.Phone == a.Phone
}
