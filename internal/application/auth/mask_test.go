package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskEmail(t *testing.T) {
	assert.Equal(t, "", maskEmail(""))
	assert.Equal(t, "w***@example.com", maskEmail("william@example.com"))
	assert.Equal(t, "***", maskEmail("@nodomain"))
	assert.Equal(t, "***", maskEmail("not-an-email"))
}

func TestMaskPhone(t *testing.T) {
	assert.Equal(t, "", maskPhone(""))
	assert.Equal(t, "******4567", maskPhone("3001234567"))
	assert.Equal(t, "****", maskPhone("123"))
}
