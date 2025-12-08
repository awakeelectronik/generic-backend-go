package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appErrors "github.com/awakeelectronik/sumabitcoin-backend/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestAuthRegister(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)

	tests := []struct {
		name           string
		payload        map[string]string
		expectedStatus int
		expectedField  string
		shouldHaveData bool
	}{
		{
			name: "Register successful",
			payload: map[string]string{
				"email":    "user@example.com",
				"password": "password123",
				"name":     "John Doe",
				"phone":    "+573001234567",
			},
			expectedStatus: http.StatusCreated,
			expectedField:  "data",
			shouldHaveData: true,
		},
		{
			name: "Register_with_only_email",
			payload: map[string]string{
				"email":    "onlyemail@example.com",
				"password": "password123",
				"name":     "Email User",
			},
			expectedStatus: http.StatusCreated,
			expectedField:  "data",
			shouldHaveData: true,
		},
		{
			name: "Register_with_only_phone",
			payload: map[string]string{
				"phone":    "+573009876543",
				"password": "password123",
				"name":     "Phone User",
			},
			expectedStatus: http.StatusCreated,
			expectedField:  "data",
			shouldHaveData: true,
		},
		{
			name: "Register_missing_email_and_phone",
			payload: map[string]string{
				"password": "password123",
				"name":     "John Doe",
			},
			expectedStatus: http.StatusBadRequest,
			expectedField:  "code",
			shouldHaveData: false,
		},
		{
			name: "Register duplicate email",
			payload: map[string]string{
				"email":    "duplicate@example.com",
				"password": "password123",
				"name":     "John Doe",
				"phone":    "+573001234567",
			},
			expectedStatus: http.StatusConflict,
			expectedField:  "code",
			shouldHaveData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts.ClearTables()

			// Si es test de duplicado, crear el usuario primero
			if tt.name == "Register duplicate email" {
				payload := map[string]string{
					"email":    "duplicate@example.com",
					"password": "password123",
					"name":     "First User",
					"phone":    "+573001234567",
				}
				body, _ := json.Marshal(payload)
				req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				ts.Router.ServeHTTP(w, req)
				t.Logf("status=%d body=%s", w.Code, w.Body.String())
			}

			// Test actual
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			ts.Router.ServeHTTP(w, req)
			t.Logf("status=%d body=%s", w.Code, w.Body.String())

			assert.Equal(t, tt.expectedStatus, w.Code)

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)

			if tt.shouldHaveData {
				data, ok := resp["data"].(map[string]interface{})
				assert.True(t, ok, "expected data field to be a map")
				assert.NotNil(t, data["id"])
			} else {
				assert.Equal(t, false, resp["success"])
				assert.NotNil(t, resp["code"])
			}
		})
	}
}

func TestAuthLogin(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	// Crear usuario primero (inserta con contraseña en texto plano y se hashea internamente)
	if err := ts.InsertTestUser("user-123", "login@example.com", "password123"); err != nil {
		t.Fatalf("failed to insert test user: %v", err)
	}
	// Verificar que el repo puede obtener al usuario
	if u, err := ts.UserRepo.GetByEmail(context.TODO(), "login@example.com"); err != nil {
		if ae, ok := err.(*appErrors.AppError); ok && ae.Internal != nil {
			t.Fatalf("error querying user via repo: %v (internal: %v)", err, ae.Internal)
		}
		t.Fatalf("error querying user via repo: %v", err)
	} else if u == nil {
		t.Fatalf("user not found via repo after insert")
	}

	tests := []struct {
		name            string
		email           string
		password        string
		expectedStatus  int
		shouldHaveToken bool
	}{
		{
			name:            "Login successful",
			email:           "login@example.com",
			password:        "password123",
			expectedStatus:  http.StatusOK,
			shouldHaveToken: true,
		},
		{
			name:            "Login invalid credentials",
			email:           "login@example.com",
			password:        "wrongpassword",
			expectedStatus:  http.StatusUnauthorized,
			shouldHaveToken: false,
		},
		{
			name:            "Login user not found",
			email:           "notfound@example.com",
			password:        "password123",
			expectedStatus:  http.StatusUnauthorized,
			shouldHaveToken: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]string{
				"email":    tt.email,
				"password": tt.password,
			}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			ts.Router.ServeHTTP(w, req)

			t.Logf("status=%d body=%s", w.Code, w.Body.String())

			assert.Equal(t, tt.expectedStatus, w.Code)

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)

			if tt.shouldHaveToken {
				data, _ := resp["data"].(map[string]interface{})
				assert.NotNil(t, data["token"])
			}
		})
	}
}
