package security

import (
	"testing"

	"github.com/awakeelectronik/generic-backend-go/internal/domain"
)

func TestAdminChecker_matchesEmailAndPhone(t *testing.T) {
	ac := NewAdminChecker("admin@x.com", "3001112222")
	if !ac.IsAdmin(&domain.User{Email: "admin@x.com", Phone: "3001112222"}) {
		t.Fatalf("expected exact email+phone match to be admin")
	}
}

func TestAdminChecker_wrongPhoneIsNotAdmin(t *testing.T) {
	ac := NewAdminChecker("admin@x.com", "3001112222")
	if ac.IsAdmin(&domain.User{Email: "admin@x.com", Phone: "9999999999"}) {
		t.Fatalf("email match but phone mismatch must not be admin")
	}
}

func TestAdminChecker_wrongEmailIsNotAdmin(t *testing.T) {
	ac := NewAdminChecker("admin@x.com", "3001112222")
	if ac.IsAdmin(&domain.User{Email: "nope@x.com", Phone: "3001112222"}) {
		t.Fatalf("phone match but email mismatch must not be admin")
	}
}

func TestAdminChecker_nilUserIsNotAdmin(t *testing.T) {
	ac := NewAdminChecker("admin@x.com", "3001112222")
	if ac.IsAdmin(nil) {
		t.Fatalf("nil user must not be admin")
	}
}

// Critical: with no admin configured, an empty-contact user must NOT match via
// "" == "".
func TestAdminChecker_unconfiguredNeverAdmin(t *testing.T) {
	ac := NewAdminChecker("", "")
	if ac.IsAdmin(&domain.User{Email: "", Phone: ""}) {
		t.Fatalf("an unconfigured admin must never report any user as admin")
	}
}
