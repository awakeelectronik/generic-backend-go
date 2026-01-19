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
type VerificationService struct {
	codes  map[string]*VerificationCode // In production, use Redis/database
	logger *logrus.Logger
}

// NewVerificationService creates a new verification service
func NewVerificationService(logger *logrus.Logger) *VerificationService {
	return &VerificationService{
		codes:  make(map[string]*VerificationCode),
		logger: logger,
	}
}

// SendVerificationCode generates and "sends" a verification code.
// For development, it just logs the code. In production, send via SMS/Email.
func (vs *VerificationService) SendVerificationCode(userID, destination string) error {
	// Generate 4-digit code
	code := fmt.Sprintf("%04d", rand.Intn(10000))

	// Store code (expires in 10 minutes)
	vs.codes[userID] = &VerificationCode{
		UserID:    userID,
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	// Log the code for development (in production, send SMS/Email)
	vs.logger.WithFields(logrus.Fields{
		"user_id":      userID,
		"destination":  destination,
		"code":         code,
	}).Info("Verification code sent (dev)")

	return nil
}

// VerifyCode checks if the provided code is valid for the user.
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

	// Mark as used
	stored.Used = true

	vs.logger.WithField("user_id", userID).Info("Verification code confirmed")

	return nil
}

