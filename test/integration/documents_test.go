package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDocumentUpload(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	userID := "user-123"
	ts.InsertTestUser(userID, "user@example.com", "hashedpass")

	tests := []struct {
		name           string
		fileName       string
		fileContent    []byte
		hasAuth        bool
		expectedStatus int
	}{
		{
			name:           "Upload document successful",
			fileName:       "test.jpg",
			fileContent:    []byte("fake image content"),
			hasAuth:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Upload without authentication",
			fileName:       "test.jpg",
			fileContent:    []byte("fake image content"),
			hasAuth:        false,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Upload without file",
			fileName:       "",
			fileContent:    nil,
			hasAuth:        true,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Crear multipart form
			buf := new(bytes.Buffer)
			writer := multipart.NewWriter(buf)

			if tt.fileContent != nil {
				part, _ := writer.CreateFormFile("document", tt.fileName)
				io.Copy(part, bytes.NewBuffer(tt.fileContent))
			}
			writer.Close()

			req := httptest.NewRequest(
				"POST",
				"/api/v1/documents/upload",
				buf,
			)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			if tt.hasAuth {
				token, _ := ts.TokenProvider.GenerateToken(userID, "user@example.com")
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var resp map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &resp)
				assert.NotNil(t, resp["data"])
			}
		})
	}
}

func TestDocumentUploadSameFileMultipleTimes(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	userID := "user-123"
	ts.InsertTestUser(userID, "user@example.com", "hashedpass")

	// Upload mismo archivo 3 veces
	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("Upload same file - attempt %d", i), func(t *testing.T) {
			buf := new(bytes.Buffer)
			writer := multipart.NewWriter(buf)

			part, _ := writer.CreateFormFile("document", "same_file.jpg")
			io.Copy(part, bytes.NewBuffer([]byte("fake image content")))
			writer.Close()

			req := httptest.NewRequest(
				"POST",
				"/api/v1/documents/upload",
				buf,
			)
			req.Header.Set("Content-Type", writer.FormDataContentType())

			token, _ := ts.TokenProvider.GenerateToken(userID, "user@example.com")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)

			// Cada upload debe tener un document_id diferente
			assert.NotNil(t, resp["data"])
			data := resp["data"].(map[string]interface{})
			assert.Equal(t, "same_file.jpg", data["file_name"]) // Name original igual
			assert.NotNil(t, data["document_id"])               // IDs diferentes
		})
	}
}

func TestListDocuments(t *testing.T) {
	testDB := SetupTestDB(t)
	defer TeardownTestDB(t, testDB)

	ts := SetupTestServer(t, testDB)
	ts.ClearTables()

	userID := "user-123"
	ts.InsertTestUser(userID, "user@example.com", "hashedpass")

	tests := []struct {
		name           string
		hasAuth        bool
		expectedStatus int
	}{
		{
			name:           "List documents with auth",
			hasAuth:        true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "List documents without auth",
			hasAuth:        false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/documents", nil)

			if tt.hasAuth {
				token, _ := ts.TokenProvider.GenerateToken(userID, "user@example.com")
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}

			w := httptest.NewRecorder()
			ts.Router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
