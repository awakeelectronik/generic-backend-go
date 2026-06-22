package security

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func newJWT() *JWTProvider {
	return NewJWTProvider("super-secret", 24, 168, "test-issuer")
}

func TestJWT_accessRoundTrip(t *testing.T) {
	p := newJWT()
	tok, err := p.GenerateToken("u1", "u@e.com", 7)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	uid, email, ver, err := p.ValidateToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if uid != "u1" || email != "u@e.com" || ver != 7 {
		t.Fatalf("claims mismatch: uid=%q email=%q ver=%d", uid, email, ver)
	}
}

func TestJWT_refreshRoundTrip(t *testing.T) {
	p := newJWT()
	tok, err := p.GenerateRefreshToken("u1", 3)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	uid, ver, err := p.ValidateRefreshToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if uid != "u1" || ver != 3 {
		t.Fatalf("claims mismatch: uid=%q ver=%d", uid, ver)
	}
}

func TestJWT_rejectsWrongSecret(t *testing.T) {
	signer := NewJWTProvider("secret-A", 24, 168, "iss")
	verifier := NewJWTProvider("secret-B", 24, 168, "iss")
	tok, _ := signer.GenerateToken("u1", "u@e.com", 1)
	if _, _, _, err := verifier.ValidateToken(tok); err == nil {
		t.Fatalf("expected validation to fail under a different secret")
	}
}

func TestJWT_rejectsExpiredToken(t *testing.T) {
	p := NewJWTProvider("secret", -1, -1, "iss") // expira en el pasado
	tok, _ := p.GenerateToken("u1", "u@e.com", 1)
	if _, _, _, err := p.ValidateToken(tok); err == nil {
		t.Fatalf("expected an expired token to be rejected")
	}
}

// TestJWT_rejectsNoneAlgorithm guards against the classic JWT alg-confusion
// attack: a token forged with the "none" algorithm must not validate.
func TestJWT_rejectsNoneAlgorithm(t *testing.T) {
	p := newJWT()
	forged := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{UserID: "attacker"})
	s, err := forged.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, _, _, err := p.ValidateToken(s); err == nil {
		t.Fatalf("expected the 'none'-algorithm token to be rejected")
	}
}

func TestJWT_rejectsGarbage(t *testing.T) {
	p := newJWT()
	if _, _, _, err := p.ValidateToken("not.a.valid.jwt"); err == nil {
		t.Fatalf("expected a malformed token to be rejected")
	}
}
