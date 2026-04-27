package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

// VerificationCode represents a stored verification code for a user.
type VerificationCode struct {
	UserID    string
	Code      string
	ExpiresAt time.Time
	Used      bool
}

// VerificationService implements application.VerificationService.
// NOTE: codes are stored in-memory. For multi-instance or restart-safe
// deployments, replace the map with Redis or a DB-backed store.
type VerificationService struct {
	mu          sync.Mutex
	codes       map[string]*VerificationCode
	sendHistory map[string][]time.Time // per user: timestamps of code sends (rate limiting)
	emailSender application.EmailSender
	appName     string
	brandHex    string
	logger      *logrus.Logger
}

// NewVerificationService creates a new VerificationService.
// appName and brandHex parameterize the HTML email so each deployment of this
// template renders with its own identity.
func NewVerificationService(
	emailSender application.EmailSender,
	appName, brandHex string,
	logger *logrus.Logger,
) *VerificationService {
	return &VerificationService{
		codes:       make(map[string]*VerificationCode),
		sendHistory: make(map[string][]time.Time),
		emailSender: emailSender,
		appName:     appName,
		brandHex:    brandHex,
		logger:      logger,
	}
}

const (
	verificationCodeTTL    = 1 * time.Hour
	minResendInterval      = 8 * time.Second
	maxSendsPerHourPerUser = 5
	sendHistoryWindow      = 1 * time.Hour
)

// SendVerificationCode generates a 4-digit code and delivers it to the
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

	vs.mu.Lock()
	defer vs.mu.Unlock()

	if err := vs.assertSendAllowedLocked(userID); err != nil {
		return err
	}

	vs.cleanupExpiredCodesLocked()
	vs.recordSendLocked(userID)

	max := big.NewInt(10000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		n = big.NewInt(time.Now().UnixNano() % 10000)
	}
	code := fmt.Sprintf("%04d", n.Int64())

	// Nuevo envío invalida el código anterior (mismo almacén por userID).
	vs.codes[userID] = &VerificationCode{
		UserID:    userID,
		Code:      code,
		ExpiresAt: time.Now().Add(verificationCodeTTL),
		Used:      false,
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

func (vs *VerificationService) assertSendAllowedLocked(userID string) error {
	now := time.Now()
	history := vs.sendHistory[userID]
	var recent []time.Time
	for _, t := range history {
		if now.Sub(t) <= sendHistoryWindow {
			recent = append(recent, t)
		}
	}
	vs.sendHistory[userID] = recent

	if len(recent) >= maxSendsPerHourPerUser {
		return fmt.Errorf("%w", appErrors.ErrVerificationRateLimited)
	}
	if len(recent) > 0 {
		last := recent[len(recent)-1]
		if now.Sub(last) < minResendInterval {
			return fmt.Errorf("%w", appErrors.ErrVerificationRateLimited)
		}
	}
	return nil
}

func (vs *VerificationService) recordSendLocked(userID string) {
	now := time.Now()
	vs.sendHistory[userID] = append(vs.sendHistory[userID], now)
}

// VerifyCode checks that the provided code is valid, not expired, and unused.
func (vs *VerificationService) VerifyCode(userID, code string) error {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	stored, exists := vs.codes[userID]
	if !exists {
		return fmt.Errorf("no verification code found for user")
	}
	if stored.Used {
		return fmt.Errorf("verification code already used")
	}
	if time.Now().After(stored.ExpiresAt) {
		return fmt.Errorf("verification code expired")
	}
	if stored.Code != code {
		return fmt.Errorf("invalid verification code")
	}

	stored.Used = true
	vs.logger.WithField("user_id", userID).Info("Verification code confirmed")
	return nil
}

// CleanupExpiredCodes removes expired codes from the in-memory store.
func (vs *VerificationService) CleanupExpiredCodes() {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.cleanupExpiredCodesLocked()
}

func (vs *VerificationService) cleanupExpiredCodesLocked() {
	now := time.Now()
	for userID, code := range vs.codes {
		if now.After(code.ExpiresAt) {
			delete(vs.codes, userID)
		}
	}
}

// ResetRateLimitsForUser clears send throttling for a user (integration tests).
func (vs *VerificationService) ResetRateLimitsForUser(userID string) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	delete(vs.sendHistory, userID)
}

// GetDebugCode returns the current code for a user. Intended for tests only.
func (vs *VerificationService) GetDebugCode(userID string) (string, bool) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	stored, ok := vs.codes[userID]
	if !ok || stored == nil {
		return "", false
	}
	return stored.Code, true
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
