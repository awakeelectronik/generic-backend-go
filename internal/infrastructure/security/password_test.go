package security

import "testing"

func TestPassword_hashAndCompare(t *testing.T) {
	ph := NewPasswordHasher()
	hash, err := ph.Hash("s3cr3t-pw")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "s3cr3t-pw" {
		t.Fatalf("hash must not equal the plaintext")
	}
	if err := ph.Compare(hash, "s3cr3t-pw"); err != nil {
		t.Fatalf("compare with the correct password should succeed: %v", err)
	}
}

func TestPassword_compareWrongFails(t *testing.T) {
	ph := NewPasswordHasher()
	hash, _ := ph.Hash("correct-horse")
	if err := ph.Compare(hash, "battery-staple"); err == nil {
		t.Fatalf("compare with a wrong password must fail")
	}
}

// TestPassword_hashIsSalted documents that bcrypt salts each hash, so the same
// input yields different stored hashes that both still verify.
func TestPassword_hashIsSalted(t *testing.T) {
	ph := NewPasswordHasher()
	h1, _ := ph.Hash("same-pw")
	h2, _ := ph.Hash("same-pw")
	if h1 == h2 {
		t.Fatalf("bcrypt must produce distinct hashes for identical input (salt)")
	}
	if err := ph.Compare(h1, "same-pw"); err != nil {
		t.Fatalf("h1 should verify: %v", err)
	}
	if err := ph.Compare(h2, "same-pw"); err != nil {
		t.Fatalf("h2 should verify: %v", err)
	}
}
