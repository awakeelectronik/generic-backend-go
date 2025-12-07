package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        string
	Email     string
	Password  string
	Name      string
	Phone     string
	Verified  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func NewUser(email, password, name, phone string) *User {
	return &User{
		ID:        uuid.New().String(),
		Email:     email,
		Password:  password,
		Name:      name,
		Phone:     phone,
		Verified:  false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (u *User) IsActive() bool {
	return u.DeletedAt == nil
}

func (u *User) Delete() {
	now := time.Now()
	u.DeletedAt = &now
}
