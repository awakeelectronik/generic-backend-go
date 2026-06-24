package security

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/sirupsen/logrus"
)

// VerificationCode represents a stored verification code for a user.
type VerificationCode struct {
	UserID    string
	Code      string
	ExpiresAt time.Time
	Used      bool
	Attempts  int
}

// VerificationService implements application.VerificationService. It owns the
// code generation, channel fan-out and HTML email rendering; the persistence of
// codes and send-throttle state lives behind a VerificationStore so the backend
// (in-memory vs Redis) is swappable. The default store is in-memory; pass a
// Redis-backed store via NewVerificationServiceWithStore for multi-instance /
// restart-safe deployments.
type VerificationService struct {
	store       VerificationStore
	emailSender application.EmailSender
	appName     string
	brandHex    string
	logger      *logrus.Logger
}

// NewVerificationService creates a service backed by the in-memory store
// (process-local, lost on restart). Signature kept for backward compatibility.
func NewVerificationService(
	emailSender application.EmailSender,
	appName, brandHex string,
	logger *logrus.Logger,
) *VerificationService {
	return NewVerificationServiceWithStore(
		newMemoryVerificationStore(DefaultVerificationPolicy()),
		emailSender, appName, brandHex, logger,
	)
}

// NewVerificationServiceWithStore wires the service to an explicit store
// (e.g. a Redis-backed one) so codes survive restarts and are shared across
// instances.
func NewVerificationServiceWithStore(
	store VerificationStore,
	emailSender application.EmailSender,
	appName, brandHex string,
	logger *logrus.Logger,
) *VerificationService {
	return &VerificationService{
		store:       store,
		emailSender: emailSender,
		appName:     appName,
		brandHex:    brandHex,
		logger:      logger,
	}
}

const (
	verificationCodeTTL     = 1 * time.Hour
	minResendInterval       = 8 * time.Second
	maxSendsPerHourPerUser  = 5
	maxVerificationAttempts = 5
	sendHistoryWindow       = 1 * time.Hour
)

// SendVerificationCode generates a 6-digit code and delivers it to the
// destination. If destination looks like an email, it sends an HTML email
// via the injected EmailSender. Phone destinations are logged only (SMS
// not yet implemented).
func (vs *VerificationService) SendVerificationCode(userID, destination string) error {
	return vs.SendVerificationCodeToDestinations(userID, []string{destination})
}

// SendVerificationCodeToDestinations genera un solo código y lo intenta entregar a cada destino
// (mismo código en correo y en canales no-email). Los duplicados y vacíos se ignoran.
func (vs *VerificationService) SendVerificationCodeToDestinations(userID string, destinations []string) error {
	dests := dedupeDestinations(destinations)
	if len(dests) == 0 {
		return fmt.Errorf("no hay destinos para el código de verificación")
	}

	ctx := context.Background()

	// La verificación del throttle de envío y el registro del intento son
	// atómicos dentro del store; si está limitado, no generamos código.
	if err := vs.store.RegisterSend(ctx, userID); err != nil {
		return err
	}

	code := generateNumericCode()

	if err := vs.store.SaveCode(ctx, userID, code); err != nil {
		vs.logger.WithError(err).WithField("user_id", userID).Error("Failed to store verification code")
		return err
	}

	// Consola en desarrollo: el código queda guardado aunque falle el envío.
	fmt.Printf("[verificación DEV] user_id=%s destinos=%v código=%s\n", userID, dests, code)

	var sendErrs []error
	for _, destination := range dests {
		if isEmail(destination) {
			subject := fmt.Sprintf("Tu código de verificación - %s", vs.appName)
			body := buildVerificationEmailHTML(vs.appName, vs.brandHex, code)
			if err := vs.emailSender.Send(destination, subject, body); err != nil {
				vs.logger.WithError(err).WithFields(logrus.Fields{
					"user_id":     userID,
					"destination": destination,
				}).Error("Failed to send verification email")
				sendErrs = append(sendErrs, fmt.Errorf("error enviando código de verificación a %s: %w", destination, err))
				continue
			}
			vs.logger.WithFields(logrus.Fields{
				"user_id":     userID,
				"destination": destination,
			}).Info("Verification email sent")
			continue
		}
		// SMS / WhatsApp not yet implemented
		vs.logger.WithFields(logrus.Fields{
			"user_id":     userID,
			"destination": destination,
			"code":        code,
		}).Warn("SMS not implemented — verification code logged (development only)")
	}

	if len(sendErrs) > 0 {
		return errors.Join(sendErrs...)
	}
	return nil
}

// generateNumericCode returns a cryptographically-random 6-digit code (with a
// time-based fallback if the RNG ever fails). 6 digits = 1M combinations, which
// the per-code attempt limit makes infeasible to brute-force.
func generateNumericCode() string {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		n = big.NewInt(time.Now().UnixNano() % 1000000)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func dedupeDestinations(destinations []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range destinations {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// VerifyCode checks that the provided code is valid, not expired, and unused.
func (vs *VerificationService) VerifyCode(userID, code string) error {
	if err := vs.store.VerifyCode(context.Background(), userID, code); err != nil {
		return err
	}
	vs.logger.WithField("user_id", userID).Info("Verification code confirmed")
	return nil
}

// CleanupExpiredCodes removes expired codes from the store.
func (vs *VerificationService) CleanupExpiredCodes() {
	vs.store.CleanupExpired(context.Background())
}

// ResetRateLimitsForUser clears send throttling for a user (integration tests).
func (vs *VerificationService) ResetRateLimitsForUser(userID string) {
	vs.store.ResetSends(context.Background(), userID)
}

// GetDebugCode returns the current code for a user. Intended for tests only.
func (vs *VerificationService) GetDebugCode(userID string) (string, bool) {
	return vs.store.PeekCode(context.Background(), userID)
}

func isEmail(destination string) bool {
	return strings.Contains(destination, "@")
}

func buildVerificationEmailHTML(appName, brandHex, code string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="es">
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 24px;">
  <h2 style="color: %s;">%s</h2>
  <p style="font-size: 16px;">Tu código de verificación es:</p>
  <div style="margin: 24px 0; text-align: center;">
    <span style="letter-spacing: 12px; color: #222; font-size: 52px; font-weight: bold;">%s</span>
  </div>
  <p style="color: #666;">Este código expira en <strong>1 hora</strong>.</p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
  <p style="color: #999; font-size: 12px;">Si no creaste esta cuenta en %s, ignora este mensaje.</p>
</body>
</html>`, brandHex, appName, code, appName)
}
