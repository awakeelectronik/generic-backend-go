package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/awakeelectronik/generic-backend-go/internal/application"
	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	"github.com/gin-gonic/gin"
)

// --- stubs ---

type stubTokenProvider struct {
	userID  string
	email   string
	version int
	err     error
}

var _ application.TokenProvider = stubTokenProvider{}

func (s stubTokenProvider) ValidateToken(string) (string, string, int, error) {
	return s.userID, s.email, s.version, s.err
}
func (s stubTokenProvider) GenerateToken(string, string, int) (string, error) { return "", nil }
func (s stubTokenProvider) GenerateRefreshToken(string, int) (string, error)  { return "", nil }
func (s stubTokenProvider) ValidateRefreshToken(string) (string, int, error)  { return "", 0, nil }

type stubUserRepo struct {
	user *domain.User
	err  error
}

var _ application.UserRepository = stubUserRepo{}

func (s stubUserRepo) GetByID(context.Context, string) (*domain.User, error) { return s.user, s.err }
func (s stubUserRepo) Create(context.Context, *domain.User) error            { return nil }
func (s stubUserRepo) GetByEmail(context.Context, string) (*domain.User, error) {
	return nil, nil
}
func (s stubUserRepo) GetByPhone(context.Context, string) (*domain.User, error) {
	return nil, nil
}
func (s stubUserRepo) Update(context.Context, *domain.User) error { return nil }
func (s stubUserRepo) UpdatePasswordAndBumpTokenVersion(context.Context, string, string) (int, error) {
	return 0, nil
}
func (s stubUserRepo) BumpTokenVersion(context.Context, string) (int, error) { return 0, nil }
func (s stubUserRepo) Delete(context.Context, string) error                  { return nil }
func (s stubUserRepo) ListWithSummary(context.Context, int, int, string) ([]*domain.User, int, int, int, error) {
	return nil, 0, 0, 0, nil
}

type stubAdminChecker struct{ admin bool }

func (s stubAdminChecker) IsAdmin(*domain.User) bool { return s.admin }

// --- helpers ---

func doRequest(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func authRouter(tp application.TokenProvider, repo application.UserRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", AuthMiddleware(tp, repo), func(c *gin.Context) {
		c.String(http.StatusOK, c.GetString("user_id"))
	})
	return r
}

// --- AuthMiddleware ---

func TestAuth_missingHeader(t *testing.T) {
	r := authRouter(stubTokenProvider{}, stubUserRepo{})
	if w := doRequest(r, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("missing header: expected 401, got %d", w.Code)
	}
}

func TestAuth_malformedHeader(t *testing.T) {
	r := authRouter(stubTokenProvider{}, stubUserRepo{})
	if w := doRequest(r, "Token abc"); w.Code != http.StatusUnauthorized {
		t.Fatalf("malformed header: expected 401, got %d", w.Code)
	}
}

func TestAuth_invalidToken(t *testing.T) {
	r := authRouter(stubTokenProvider{err: context.Canceled}, stubUserRepo{})
	if w := doRequest(r, "Bearer bad"); w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token: expected 401, got %d", w.Code)
	}
}

func TestAuth_userNotFound(t *testing.T) {
	tp := stubTokenProvider{userID: "u1", version: 1}
	r := authRouter(tp, stubUserRepo{user: nil})
	if w := doRequest(r, "Bearer good"); w.Code != http.StatusUnauthorized {
		t.Fatalf("user not found: expected 401, got %d", w.Code)
	}
}

func TestAuth_unverifiedUserForbidden(t *testing.T) {
	tp := stubTokenProvider{userID: "u1", version: 1}
	repo := stubUserRepo{user: &domain.User{ID: "u1", Verified: false, TokenVersion: 1}}
	if w := doRequest(authRouter(tp, repo), "Bearer good"); w.Code != http.StatusForbidden {
		t.Fatalf("unverified user: expected 403, got %d", w.Code)
	}
}

func TestAuth_tokenVersionMismatchRevoked(t *testing.T) {
	tp := stubTokenProvider{userID: "u1", version: 1}
	repo := stubUserRepo{user: &domain.User{ID: "u1", Verified: true, TokenVersion: 2}}
	if w := doRequest(authRouter(tp, repo), "Bearer stale"); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: expected 401, got %d", w.Code)
	}
}

func TestAuth_happyPathSetsUserID(t *testing.T) {
	tp := stubTokenProvider{userID: "u1", email: "u@e.com", version: 5}
	repo := stubUserRepo{user: &domain.User{ID: "u1", Verified: true, TokenVersion: 5}}
	w := doRequest(authRouter(tp, repo), "Bearer good")
	if w.Code != http.StatusOK {
		t.Fatalf("happy path: expected 200, got %d", w.Code)
	}
	if w.Body.String() != "u1" {
		t.Fatalf("expected handler to see user_id=u1, got %q", w.Body.String())
	}
}

// --- AdminMiddleware ---

func adminRouter(setUser *domain.User, checker application.AdminChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	pre := func(c *gin.Context) {
		if setUser != nil {
			c.Set("user", setUser)
		}
		c.Next()
	}
	r.GET("/protected", pre, AdminMiddleware(checker), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestAdmin_noUserInContext(t *testing.T) {
	r := adminRouter(nil, stubAdminChecker{admin: true})
	if w := doRequest(r, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no user in context: expected 401, got %d", w.Code)
	}
}

func TestAdmin_nonAdminForbidden(t *testing.T) {
	r := adminRouter(&domain.User{ID: "u1"}, stubAdminChecker{admin: false})
	if w := doRequest(r, ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d", w.Code)
	}
}

func TestAdmin_adminAllowed(t *testing.T) {
	r := adminRouter(&domain.User{ID: "u1"}, stubAdminChecker{admin: true})
	if w := doRequest(r, ""); w.Code != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d", w.Code)
	}
}
