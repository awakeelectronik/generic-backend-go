package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
	"github.com/sirupsen/logrus"
)

// TestRegisterInput_passwordByteLength guards the bcrypt 72-BYTE bound: the
// binding tag's max=72 counts runes, so a multibyte password can pass it yet
// exceed 72 bytes and be silently truncated by bcrypt. Validate must reject it.
func TestRegisterInput_passwordByteLength(t *testing.T) {
	// 25 euro signs = 25 runes but 75 bytes.
	if err := (&RegisterInput{Email: "a@b.com", Password: strings.Repeat("€", 25)}).Validate(); err == nil {
		t.Fatalf("expected a >72-byte password to be rejected")
	}
	if err := (&RegisterInput{Email: "a@b.com", Password: "password123"}).Validate(); err != nil {
		t.Fatalf("expected a valid password to pass, got %v", err)
	}
	if err := (&RegisterInput{Email: "a@b.com", Password: "short"}).Validate(); err == nil {
		t.Fatalf("expected a <8-byte password to be rejected")
	}
}

func silentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// fakeHasher treats "hash:<plain>" as the stored hash, so Compare succeeds only
// for the matching plaintext.
type fakeHasher struct{}

var _ application.PasswordHasher = fakeHasher{}

func (fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (fakeHasher) Compare(hash, password string) error {
	if hash == "hash:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

// --- CheckAvailability ---

func TestCheckAvailability_emailAvailable(t *testing.T) {
	uc := NewCheckAvailabilityUseCase(&fakeUserRepo{}, silentLogger())
	out, err := uc.Execute(context.Background(), CheckAvailabilityInput{Email: "free@x.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Available {
		t.Fatalf("an unknown email should be available")
	}
}

func TestCheckAvailability_emailTaken(t *testing.T) {
	repo := &fakeUserRepo{byEmail: map[string]*domain.User{"taken@x.com": {ID: "u1"}}}
	out, err := NewCheckAvailabilityUseCase(repo, silentLogger()).Execute(context.Background(), CheckAvailabilityInput{Email: "taken@x.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Available {
		t.Fatalf("an existing email must not be available")
	}
}

// TestCheckAvailability_dbErrorFailsClosed is the regression for the fail-open
// fix: on a DB error the use case must return an error, never available=true.
func TestCheckAvailability_dbErrorFailsClosed(t *testing.T) {
	repo := &fakeUserRepo{emailErr: errors.New("db down")}
	out, err := NewCheckAvailabilityUseCase(repo, silentLogger()).Execute(context.Background(), CheckAvailabilityInput{Email: "x@x.com"})
	if err == nil {
		t.Fatalf("a DB error must fail closed, but got out=%+v err=nil", out)
	}
}

// --- Login ---

func loginUC(repo *fakeUserRepo) *LoginUseCase {
	return NewLoginUseCase(repo, fakeHasher{}, &fakeTokenProvider{}, nil, silentLogger())
}

func verifiedUser() *fakeUserRepo {
	return &fakeUserRepo{byEmail: map[string]*domain.User{
		"a@b.com": {ID: "u1", Email: "a@b.com", Password: "hash:pw", Verified: true, TokenVersion: 1},
	}}
}

func TestLogin_happyPath(t *testing.T) {
	out, err := loginUC(verifiedUser()).Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "pw"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.UserID != "u1" || out.Email != "a@b.com" {
		t.Fatalf("unexpected output: %+v", out)
	}
	if out.Token == "" || out.RefreshToken == "" {
		t.Fatalf("expected both tokens to be issued")
	}
}

func TestLogin_wrongPassword(t *testing.T) {
	_, err := loginUC(verifiedUser()).Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "wrong"})
	if !errors.Is(err, appErrors.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestLogin_userNotFound(t *testing.T) {
	_, err := loginUC(&fakeUserRepo{}).Execute(context.Background(), LoginInput{Email: "nope@b.com", Password: "pw"})
	if !errors.Is(err, appErrors.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

// countingHasher records how many times Compare runs so the timing test can
// assert bcrypt work happens even when no user matches.
type countingHasher struct{ compares int }

func (h *countingHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (h *countingHasher) Compare(hash, password string) error {
	h.compares++
	if hash == "hash:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

// TestLogin_userNotFoundStillComparesPassword is the anti-enumeration timing
// regression: even when the user does not exist, the use case must still run a
// password Compare (against the dummy hash) so the response time can't reveal
// whether the account exists.
func TestLogin_userNotFoundStillComparesPassword(t *testing.T) {
	h := &countingHasher{}
	uc := NewLoginUseCase(&fakeUserRepo{}, h, &fakeTokenProvider{}, nil, silentLogger())
	// Reset: the constructor calls Hash, not Compare, so the counter starts at 0.
	h.compares = 0

	_, err := uc.Execute(context.Background(), LoginInput{Email: "nope@b.com", Password: "pw"})
	if !errors.Is(err, appErrors.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
	if h.compares != 1 {
		t.Fatalf("expected exactly one dummy Compare on user-miss, got %d", h.compares)
	}
}

func TestLogin_unverifiedUserForbidden(t *testing.T) {
	repo := &fakeUserRepo{byEmail: map[string]*domain.User{
		"a@b.com": {ID: "u1", Email: "a@b.com", Password: "hash:pw", Verified: false, TokenVersion: 1},
	}}
	_, err := loginUC(repo).Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "pw"})

	var appErr *appErrors.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected an *AppError, got %v", err)
	}
	if appErr.StatusCode != http.StatusForbidden || appErr.Code != "UNVERIFIED_USER" {
		t.Fatalf("expected 403 UNVERIFIED_USER, got %d %q", appErr.StatusCode, appErr.Code)
	}
}
