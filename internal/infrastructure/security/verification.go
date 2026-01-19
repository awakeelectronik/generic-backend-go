package security

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/sirupsen/logrus"
)

// VerificationCode represents a verification code for a user
type VerificationCode struct {
	UserID    string
	Code      string
	ExpiresAt time.Time
	Used      bool
}

// VerificationService provides verification code functionality
//
// NOTE: This in-memory implementation is intended for development/testing.
// In production, store codes in Redis/database and deliver via SMS/Email provider.
type VerificationService struct {
	codes  map[string]*VerificationCode
	logger *logrus.Logger
}

// NewVerificationService creates a new verification service
func NewVerificationService(logger *logrus.Logger) *VerificationService {
	return &VerificationService{
		codes:  make(map[string]*VerificationCode),
		logger: logger,
	}
}

// SendVerificationCode generates and "sends" a verification code
// For development, it just logs the code. In production, send via SMS/Email.
func (vs *VerificationService) SendVerificationCode(userID, destination string) error {
	code := fmt.Sprintf("%04d", rand.Intn(10000))

	// Store code (expires in 10 minutes)
	vs.codes[userID] = &VerificationCode{
		UserID:    userID,
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	vs.logger.WithFields(logrus.Fields{
		"user_id":      userID,
		"destination":  destination,
		"code":         code,
		"expires_mins": 10,
	}).Info("Verification code generated (dev)")

	return nil
}

// VerifyCode checks if the provided code is valid for the user
func (vs *VerificationService) VerifyCode(userID, code string) error {
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

// CleanupExpiredCodes removes expired verification codes
// In production, this should run periodically.
func (vs *VerificationService) CleanupExpiredCodes() {
	now := time.Now()
	for userID, code := range vs.codes {
		if now.After(code.ExpiresAt) {
			delete(vs.codes, userID)
		}
	}
}

// GetDebugCode returns the current verification code for a user.
// Intended ONLY for tests/development.
func (vs *VerificationService) GetDebugCode(userID string) (string, bool) {
	stored, ok := vs.codes[userID]
	if !ok || stored == nil {
		return "", false
	}
	return stored.Code, true
}

