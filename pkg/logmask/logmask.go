// Package logmask ofrece helpers para enmascarar PII antes de escribirla en
// logs. Los logs viajan a sistemas con menos control de acceso que la BD
// (agregadores, consolas de hosting); el contacto completo de un usuario no
// debe llegar ahí.
package logmask

import "strings"

// Email reduce un correo a primera letra + dominio: "w***@example.com".
func Email(email string) string {
	if email == "" {
		return ""
	}
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

// Phone deja visibles solo los últimos 4 dígitos: "******4567".
func Phone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(phone)-4) + phone[len(phone)-4:]
}

// Destination enmascara un destino de verificación según su forma
// (correo si contiene @, teléfono en caso contrario).
func Destination(d string) string {
	if strings.Contains(d, "@") {
		return Email(d)
	}
	return Phone(d)
}

// Destinations enmascara una lista de destinos (para logs de fan-out).
func Destinations(ds []string) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, Destination(d))
	}
	return out
}
