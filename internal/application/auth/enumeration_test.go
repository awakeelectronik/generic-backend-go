package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
	appErrors "github.com/awakeelectronik/generic-backend-go/pkg/errors"
)

// --- fakes compartidos por estos tests ---

// fakeThrottle cuenta fallos por clave y bloquea al alcanzar max.
type fakeThrottle struct {
	failures map[string]int
	max      int
}

func newFakeThrottle(max int) *fakeThrottle {
	return &fakeThrottle{failures: map[string]int{}, max: max}
}

func (f *fakeThrottle) IsLocked(_ context.Context, key string) bool { return f.failures[key] >= f.max }
func (f *fakeThrottle) RegisterFailure(_ context.Context, key string) { f.failures[key]++ }
func (f *fakeThrottle) Reset(_ context.Context, key string) { delete(f.failures, key) }

type fakeVerification struct{ verifyErr error }

func (f *fakeVerification) SendVerificationCode(string, string) error            { return nil }
func (f *fakeVerification) SendVerificationCodeToDestinations(string, []string) error { return nil }
func (f *fakeVerification) VerifyCode(string, string) error                       { return f.verifyErr }

// --- Fix #2: el 429 de lockout no debe delatar existencia de cuenta ---

// Una cuenta INEXISTENTE debe escalar al mismo 429 LOGIN_LOCKED que una real:
// si solo se contaran los fallos del camino usuario-existe, el 429 sería un
// oráculo de enumeración.
func TestLogin_unknownAccountLocksLikeReal(t *testing.T) {
	th := newFakeThrottle(3)
	uc := NewLoginUseCase(&fakeUserRepo{}, fakeHasher{}, &fakeTokenProvider{}, th, silentLogger())
	in := LoginInput{Email: "ghost@x.com", Password: "whatever"}

	for i := 0; i < 3; i++ {
		if _, err := uc.Execute(context.Background(), in); !errors.Is(err, appErrors.ErrUnauthorized) {
			t.Fatalf("intento %d: esperaba 401, got %v", i, err)
		}
	}

	_, err := uc.Execute(context.Background(), in)
	var appErr *appErrors.AppError
	if !errors.As(err, &appErr) || appErr.StatusCode != 429 || appErr.Code != "LOGIN_LOCKED" {
		t.Fatalf("una cuenta inexistente debe dar 429 LOGIN_LOCKED tras N fallos, got %v", err)
	}
}

// Simétrico: una cuenta real también se bloquea (mismo código/estado), así el
// atacante no puede distinguir por la respuesta.
func TestLogin_realAccountLocks(t *testing.T) {
	th := newFakeThrottle(3)
	uc := NewLoginUseCase(verifiedUser(), fakeHasher{}, &fakeTokenProvider{}, th, silentLogger())
	wrong := LoginInput{Email: "a@b.com", Password: "wrong"}

	for i := 0; i < 3; i++ {
		uc.Execute(context.Background(), wrong)
	}
	// Con la contraseña CORRECTA sigue bloqueada (el check de lock va antes).
	_, err := uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "pw"})
	var appErr *appErrors.AppError
	if !errors.As(err, &appErr) || appErr.Code != "LOGIN_LOCKED" {
		t.Fatalf("cuenta real debe bloquearse igual, got %v", err)
	}
}

// Un login exitoso limpia el contador (no acumula hacia el bloqueo).
func TestLogin_successResetsThrottle(t *testing.T) {
	th := newFakeThrottle(3)
	uc := NewLoginUseCase(verifiedUser(), fakeHasher{}, &fakeTokenProvider{}, th, silentLogger())

	uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "wrong"})
	uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "wrong"})
	if _, err := uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "pw"}); err != nil {
		t.Fatalf("login correcto debía pasar, got %v", err)
	}
	// Tras el reset, dos fallos más no deben bloquear (umbral 3).
	uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "wrong"})
	if _, err := uc.Execute(context.Background(), LoginInput{Email: "a@b.com", Password: "pw"}); err != nil {
		t.Fatalf("el contador debía haberse reseteado tras el éxito, got %v", err)
	}
}

// --- Fix #1: reset-password no debe distinguir estados de fallo ---

// Cuenta inexistente, cuenta real con código incorrecto y cuenta real sin código
// pendiente deben devolver EXACTAMENTE la misma respuesta (código, mensaje y
// status). Distinguirlas reabre la enumeración: el atacante primea el estado
// "con código" con un forgot-password previo.
func TestResetPassword_allFailuresIndistinguishable(t *testing.T) {
	in := ResetPasswordInput{Email: "target@x.com", Code: "000000", NewPassword: "newpassword1"}

	unknownUC := NewResetPasswordUseCase(&fakeUserRepo{}, fakeHasher{}, &fakeVerification{}, &fakeTokenProvider{}, silentLogger())
	_, errUnknown := unknownUC.Execute(context.Background(), in)

	realRepo := &fakeUserRepo{byEmail: map[string]*domain.User{"target@x.com": {ID: "u1", Email: "target@x.com"}}}
	wrongCodeUC := NewResetPasswordUseCase(realRepo, fakeHasher{}, &fakeVerification{verifyErr: appErrors.ErrVerificationCodeInvalid}, &fakeTokenProvider{}, silentLogger())
	_, errWrongCode := wrongCodeUC.Execute(context.Background(), in)

	noCodeUC := NewResetPasswordUseCase(realRepo, fakeHasher{}, &fakeVerification{verifyErr: appErrors.ErrVerificationCodeNotFound}, &fakeTokenProvider{}, silentLogger())
	_, errNoCode := noCodeUC.Execute(context.Background(), in)

	assertSameAppError(t, "unknown vs wrong-code", errUnknown, errWrongCode)
	assertSameAppError(t, "unknown vs no-code", errUnknown, errNoCode)

	var appErr *appErrors.AppError
	if !errors.As(errUnknown, &appErr) || appErr.Code != "RESET_INVALID" {
		t.Fatalf("esperaba RESET_INVALID genérico, got %v", errUnknown)
	}
}

func assertSameAppError(t *testing.T, label string, a, b error) {
	t.Helper()
	var ea, eb *appErrors.AppError
	if !errors.As(a, &ea) || !errors.As(b, &eb) {
		t.Fatalf("%s: ambos deben ser *AppError, got a=%v b=%v", label, a, b)
	}
	if ea.Code != eb.Code || ea.Message != eb.Message || ea.StatusCode != eb.StatusCode {
		t.Fatalf("%s: respuestas distinguibles a=%+v b=%+v", label, ea, eb)
	}
}
