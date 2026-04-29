package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNoContact      = errors.New("user must have email or phone")
	ErrUserEmptyName      = errors.New("user name is required")
	ErrUserEmptyPassword  = errors.New("user password is required")
)

type User struct {
	ID           string
	Email        string
	Password     string
	Name         string
	Phone        string
	Verified     bool
	TokenVersion int
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

// NewUser builds a User and rejects any obviously invalid combination. The
// password is expected to already be hashed — callers must hash before calling.
func NewUser(email, password, name, phone string) (*User, error) {
	email = strings.TrimSpace(email)
	phone = strings.TrimSpace(phone)
	name = strings.TrimSpace(name)

	if email == "" && phone == "" {
		return nil, ErrUserNoContact
	}
	if name == "" {
		return nil, ErrUserEmptyName
	}
	if password == "" {
		return nil, ErrUserEmptyPassword
	}

	now := time.Now()
	return &User{
		ID:           uuid.New().String(),
		Email:        email,
		Password:     password,
		Name:         name,
		Phone:        phone,
		Verified:     false,
		TokenVersion: 1,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (u *User) IsActive() bool {
	return u.DeletedAt == nil
}

func (u *User) Delete() {
	now := time.Now()
	u.DeletedAt = &now
}
