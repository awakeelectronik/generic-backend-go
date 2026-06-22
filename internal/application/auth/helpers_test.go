package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

// --- fakes ---

type fakeTokenProvider struct {
	accessErr  error
	refreshErr error
}

func (f *fakeTokenProvider) GenerateToken(userID, email string, version int) (string, error) {
	if f.accessErr != nil {
		return "", f.accessErr
	}
	return "access-" + userID, nil
}

func (f *fakeTokenProvider) GenerateRefreshToken(userID string, version int) (string, error) {
	if f.refreshErr != nil {
		return "", f.refreshErr
	}
	return "refresh-" + userID, nil
}

func (f *fakeTokenProvider) ValidateToken(string) (string, string, int, error) { return "", "", 0, nil }
func (f *fakeTokenProvider) ValidateRefreshToken(string) (string, int, error)  { return "", 0, nil }

type fakeUserRepo struct {
	byEmail  map[string]*domain.User
	byPhone  map[string]*domain.User
	emailErr error
	phoneErr error
}

var _ application.UserRepository = (*fakeUserRepo)(nil)

func (f *fakeUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	if f.emailErr != nil {
		return nil, f.emailErr
	}
	return f.byEmail[email], nil
}

func (f *fakeUserRepo) GetByPhone(_ context.Context, phone string) (*domain.User, error) {
	if f.phoneErr != nil {
		return nil, f.phoneErr
	}
	return f.byPhone[phone], nil
}

// Remaining methods are unused by the helpers under test; present only to
// satisfy the application.UserRepository interface.
func (f *fakeUserRepo) Create(context.Context, *domain.User) error          { return nil }
func (f *fakeUserRepo) GetByID(context.Context, string) (*domain.User, error) { return nil, nil }
func (f *fakeUserRepo) Update(context.Context, *domain.User) error          { return nil }
func (f *fakeUserRepo) UpdatePasswordAndBumpTokenVersion(context.Context, string, string) (int, error) {
	return 0, nil
}
func (f *fakeUserRepo) BumpTokenVersion(context.Context, string) (int, error) { return 0, nil }
func (f *fakeUserRepo) Delete(context.Context, string) error                  { return nil }
func (f *fakeUserRepo) ListWithSummary(context.Context, int, int, string) ([]*domain.User, int, int, int, error) {
	return nil, 0, 0, 0, nil
}

// --- issueTokenPair ---

func TestIssueTokenPair_success(t *testing.T) {
	token, refresh, err := issueTokenPair(&fakeTokenProvider{}, "u1", "u@e.com", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "access-u1" || refresh != "refresh-u1" {
		t.Fatalf("unexpected tokens: token=%q refresh=%q", token, refresh)
	}
}

func TestIssueTokenPair_accessErrorMapsToInternal(t *testing.T) {
	_, _, err := issueTokenPair(&fakeTokenProvider{accessErr: errors.New("boom")}, "u1", "u@e.com", 1)
	if !errors.Is(err, appErrors.ErrInternalServer) {
		t.Fatalf("expected ErrInternalServer, got %v", err)
	}
}

func TestIssueTokenPair_refreshErrorMapsToInternal(t *testing.T) {
	_, _, err := issueTokenPair(&fakeTokenProvider{refreshErr: errors.New("boom")}, "u1", "u@e.com", 1)
	if !errors.Is(err, appErrors.ErrInternalServer) {
		t.Fatalf("expected ErrInternalServer, got %v", err)
	}
}

// --- findUserByEmailOrPhone ---

func TestFindUserByEmailOrPhone_prefersEmail(t *testing.T) {
	repo := &fakeUserRepo{
		byEmail: map[string]*domain.User{"u@e.com": {ID: "by-email"}},
		byPhone: map[string]*domain.User{"3001234567": {ID: "by-phone"}},
	}
	got, err := findUserByEmailOrPhone(context.Background(), repo, "u@e.com", "3001234567")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != "by-email" {
		t.Fatalf("expected email lookup to win, got %+v", got)
	}
}

func TestFindUserByEmailOrPhone_fallsBackToPhone(t *testing.T) {
	repo := &fakeUserRepo{byPhone: map[string]*domain.User{"3001234567": {ID: "by-phone"}}}
	got, err := findUserByEmailOrPhone(context.Background(), repo, "", "3001234567")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ID != "by-phone" {
		t.Fatalf("expected phone lookup, got %+v", got)
	}
}

func TestFindUserByEmailOrPhone_neitherProvidedReturnsNil(t *testing.T) {
	got, err := findUserByEmailOrPhone(context.Background(), &fakeUserRepo{}, "   ", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil user when neither field is provided, got %+v", got)
	}
}
