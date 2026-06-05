package integration

import (
	"strings"
	"testing"
)

func TestTestDatabaseIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		want     string
		wantErr  bool
		errMatch string
	}{
		{
			name: "genericbackendtest",
			want: "`genericbackendtest`",
		},
		{
			name: "generic_backend_test",
			want: "`generic_backend_test`",
		},
		{
			name:     "production",
			wantErr:  true,
			errMatch: `must contain "test"`,
		},
		{
			name:     "test-db",
			wantErr:  true,
			errMatch: "unsupported characters",
		},
		{
			name:     "testdb;DROP DATABASE production",
			wantErr:  true,
			errMatch: "unsupported characters",
		},
		{
			name:     "",
			wantErr:  true,
			errMatch: "is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := testDatabaseIdentifier(tt.name)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if tt.errMatch != "" && !strings.Contains(err.Error(), tt.errMatch) {
					t.Fatalf("expected error containing %q, got %q", tt.errMatch, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("identifier = %q, want %q", got, tt.want)
			}
		})
	}
}
