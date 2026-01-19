package handlers

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ValidationMessageES converts common validator/binding errors into a Spanish message
// suitable to show to end-users. Keep it generic enough to avoid leaking internals.
func ValidationMessageES(err error) string {
	if err == nil {
		return "Datos inválidos"
	}

	var ve validator.ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		fe := ve[0] // show first error only (simple UX)
		field := fieldLabelES(fe.Field())
		switch fe.Tag() {
		case "required":
			return fmt.Sprintf("El campo %s es obligatorio", field)
		case "email":
			return "El correo electrónico no es válido"
		case "min":
			return fmt.Sprintf("El campo %s debe tener al menos %s caracteres", field, fe.Param())
		case "len":
			if field == "teléfono" {
				return "El teléfono debe tener 10 dígitos"
			}
			if field == "code" || field == "código" {
				return "El código debe tener 4 dígitos"
			}
			return fmt.Sprintf("El campo %s debe tener %s caracteres", field, fe.Param())
		case "numeric":
			if field == "teléfono" {
				return "El teléfono solo debe contener números"
			}
			return fmt.Sprintf("El campo %s solo debe contener números", field)
		default:
			return "Datos inválidos"
		}
	}

	// Fallback for other binding errors (invalid JSON, etc.)
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "invalid character") || strings.Contains(msg, "unexpected eof") || strings.Contains(msg, "unexpected end of json input") {
		return "JSON inválido"
	}

	return "Datos inválidos"
}

func fieldLabelES(field string) string {
	switch field {
	case "Email":
		return "correo electrónico"
	case "Password":
		return "contraseña"
	case "Name":
		return "nombre"
	case "Phone":
		return "teléfono"
	case "Code":
		return "código"
	case "RefreshToken":
		return "token de actualización"
	default:
		// best effort: split CamelCase -> words
		return strings.ToLower(field)
	}
}
