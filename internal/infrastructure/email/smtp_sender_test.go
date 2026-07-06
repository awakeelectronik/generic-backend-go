package email

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Destinatarios con CR/LF deben rechazarse ANTES de construir el mensaje:
// interpolados en el header "To:" permitirían inyectar headers (Bcc, etc.).
func TestSendRejectsHeaderInjectionInRecipient(t *testing.T) {
	s := NewSMTPSender("noreply@app.local", "App", "localhost", "25")

	cases := []string{
		"a@b.com\r\nBcc: attacker@evil.com",
		"a@b.com\nBcc: attacker@evil.com",
		"a@b.com\x00",
		"sin-arroba",
	}
	for _, to := range cases {
		err := s.Send(to, "subject", "<p>hi</p>")
		assert.Error(t, err, "destinatario %q debió rechazarse", to)
		if err != nil {
			// El error debe ser el rechazo del destinatario, no un fallo de sendmail
			// (que indicaría que el mensaje sí se intentó entregar).
			assert.True(t, strings.Contains(err.Error(), "invalid recipient"),
				"error inesperado para %q: %v", to, err)
		}
	}
}
