package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUserProfile(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	// Crear usuario
	userID := "user-123"
	ts.InsertTestUser(userID, "user@example.com", "hashedpass")

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		expectedData   map[string]interface{}
	}{
		{
			name:           "Get profile with valid token",
			token:          ts.TestToken,
			expectedStatus: http.StatusOK,
			expectedData: map[string]interface{}{
				"email": "user@example.com",
			},
		},
		{
			name:           "Get profile without token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			expectedData:   nil,
		},
		{
			name:           "Get profile with invalid token",
			token:          "invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
			expectedData:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/users/profile", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tt.token))
			}

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)

			if tt.expectedData != nil {
				for key, val := range tt.expectedData {
					assert.Equal(t, val, resp[key])
				}
			}
		})
	}
}

func TestGetUserByID(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	// Crear dos usuarios
	userID1 := "user-123"
	userID2 := "user-456"
	ts.InsertTestUser(userID1, "user1@example.com", "hashedpass")
	ts.InsertTestUser(userID2, "user2@example.com", "hashedpass")

	tests := []struct {
		name           string
		requestUserID  string
		tokenUserID    string
		expectedStatus int
	}{
		{
			name:           "Get own profile (authorized)",
			requestUserID:  userID1,
			tokenUserID:    userID1,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get other's profile (forbidden)",
			requestUserID:  userID2,
			tokenUserID:    userID1,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Get non-existent user",
			requestUserID:  "not-exists",
			tokenUserID:    userID1,
			expectedStatus: http.StatusForbidden, // O 404 según tu diseño
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/api/v1/users/%s", tt.requestUserID)
			req := httptest.NewRequest("GET", url, nil)

			// Generar token para el usuario
			token, _ := ts.TokenProvider.GenerateToken(tt.tokenUserID, "test@example.com")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestUpdateUserProfile(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	userID := "user-123"
	ts.InsertTestUser(userID, "user@example.com", "hashedpass")

	tests := []struct {
		name           string
		userID         string
		payload        map[string]string
		expectedStatus int
	}{
		{
			name:   "Update own profile",
			userID: userID,
			payload: map[string]string{
				"name":  "New Name",
				"phone": "+573009876543",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "Update with missing required field",
			userID: userID,
			payload: map[string]string{
				"phone": "+573009876543",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("/api/v1/users/%s", tt.userID)
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("PUT", url, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			token, _ := ts.TokenProvider.GenerateToken(userID, "user@example.com")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
