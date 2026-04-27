package email

// NoopSender no envía correo; cumple application.EmailSender para tests y entornos sin MTA.
type NoopSender struct{}

func NewNoopSender() *NoopSender {
	return &NoopSender{}
}

func (n *NoopSender) Send(to, subject, body string) error {
	_ = to
	_ = subject
	_ = body
	return nil
}
