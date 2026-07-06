package security

import "golang.org/x/crypto/bcrypt"

type PasswordHasher struct {
	cost int
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		cost: bcrypt.DefaultCost,
	}
}

// NewPasswordHasherWithCost permite fijar el work factor (BCRYPT_COST). Un cost
// fuera del rango válido de bcrypt cae al DefaultCost en vez de fallar en cada
// Hash: GenerateFromPassword trataría el valor inválido de forma silenciosa.
func NewPasswordHasherWithCost(cost int) *PasswordHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &PasswordHasher{cost: cost}
}

func (ph *PasswordHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), ph.cost)
	return string(hash), err
}

func (ph *PasswordHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
