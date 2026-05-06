package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectError   bool
		expectedError error
	}{
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345"},
			},
			expectedKey: "12345",
			expectError: false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectError:   true,
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectError:   true,
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - no key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer 12345"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "extra spaces but valid",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345 extra"},
			},
			expectedKey: "12345",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				if tt.expectedError != nil && err != tt.expectedError {
					t.Fatalf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Fatalf("expected key %s, got %s", tt.expectedKey, key)
			}
		})
	}
}
