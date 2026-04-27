package email

import (
	"bytes"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"os/exec"
	"strings"
	"time"
)

// SMTPSender entrega el correo al MTA local (p. ej. Postfix en el mismo VPS) vía sendmail -t.
// El parámetro From se usa en el header y como envelope sender; FromName aparece en el header
// "From" como display name para que los clientes lo muestren con la marca de la app.
//
// Los parámetros host y port se mantienen por compatibilidad con la configuración (.env) pero
// no se usan: el relay real lo define el MTA en el servidor. Se eligió sendmail en vez de
// net/smtp porque algunos Postfix locales fallan con EOF en el diálogo mínimo de smtp.SendMail
// a localhost:25.
type SMTPSender struct {
	from     string
	fromName string
}

// NewSMTPSender crea un sender que invoca /usr/sbin/sendmail o /usr/lib/sendmail.
// fromName es el display name que aparece junto al correo (típicamente APP_NAME).
func NewSMTPSender(from, fromName, host, port string) *SMTPSender {
	_ = host
	_ = port
	return &SMTPSender{from: from, fromName: fromName}
}

// Send envía un correo HTML al destinatario.
func (s *SMTPSender) Send(to, subject, body string) error {
	now := time.Now().UTC()
	messageID := fmt.Sprintf("<%d.%s@%s>", now.UnixNano(), strings.ReplaceAll(to, "@", "_"), messageIDHostFromFrom(s.from))
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)
	encodedFromName := mime.QEncoding.Encode("utf-8", s.fromName)
	encodedBody, err := toQuotedPrintable(body)
	if err != nil {
		return fmt.Errorf("failed to encode email body: %w", err)
	}

	header := strings.Join([]string{
		fmt.Sprintf("From: %s <%s>", encodedFromName, s.from),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Subject: %s", encodedSubject),
		fmt.Sprintf("Date: %s", now.Format(time.RFC1123Z)),
		fmt.Sprintf("Message-ID: %s", messageID),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
	}, "\r\n")

	msg := []byte(header + encodedBody)
	return s.sendViaSendmail(msg)
}

func (s *SMTPSender) sendViaSendmail(msg []byte) error {
	paths := []string{"/usr/sbin/sendmail", "/usr/lib/sendmail"}
	var lastErr error

	for _, p := range paths {
		cmd := exec.Command(p, "-f", s.from, "-t", "-i")
		cmd.Stdin = bytes.NewReader(msg)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s failed: %w output=%s", p, err, strings.TrimSpace(string(out)))
	}

	if lastErr == nil {
		return fmt.Errorf("sendmail binary not found")
	}
	return lastErr
}

func messageIDHostFromFrom(from string) string {
	parts := strings.Split(strings.TrimSpace(from), "@")
	if len(parts) == 2 {
		domain := strings.TrimSpace(parts[1])
		if domain != "" {
			return domain
		}
	}
	return "app.local"
}

func toQuotedPrintable(content string) (string, error) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write([]byte(content)); err != nil {
		_ = w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
