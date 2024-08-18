// Copyright (c) 2024 Bill Nixon

package exposed_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/bnixon67/exposed"
)

func readFile(name string) string {
	r, err := os.Open(name)
	if err != nil {
		panic(err)
	}

	b, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}

	return string(b)
}
func TestCheckPwnedPassword(t *testing.T) {
	tests := []struct {
		name           string
		password       string
		mode           string
		responseBody   string
		wantCount      int
		wantErr        bool
		httpStatusCode int
	}{
		{
			name:           "SHA-1 password found",
			password:       "password",
			mode:           "sha1",
			responseBody:   readFile("testdata/5BAA6"),
			wantCount:      10434004,
			wantErr:        false,
			httpStatusCode: http.StatusOK,
		},
		{
			name:           "SHA-1 password not found",
			password:       "notfoundpassword",
			mode:           "sha1",
			responseBody:   "",
			wantCount:      0,
			wantErr:        false,
			httpStatusCode: http.StatusOK,
		},
		{
			name:           "NTLM password found",
			password:       "password",
			mode:           "ntlm",
			responseBody:   readFile("testdata/8846F"),
			wantCount:      10434004,
			wantErr:        false,
			httpStatusCode: http.StatusOK,
		},
		{
			name:           "NTLM password not found",
			password:       "notfoundpassword",
			mode:           "ntlm",
			responseBody:   "",
			wantCount:      0,
			wantErr:        false,
			httpStatusCode: http.StatusOK,
		},
		{
			name:           "HTTP error",
			password:       "password",
			mode:           "sha1",
			responseBody:   "",
			wantCount:      0,
			wantErr:        true,
			httpStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "count not found",
			password:       "password",
			mode:           "ntlm",
			responseBody:   readFile("testdata/8846F.bad"),
			wantCount:      0,
			wantErr:        true,
			httpStatusCode: http.StatusOK,
		},
		{
			name:           "bad url",
			password:       "password",
			mode:           "ntlm",
			responseBody:   readFile("testdata/8846F.bad"),
			wantCount:      0,
			wantErr:        true,
			httpStatusCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.httpStatusCode)
				_, _ = w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			c := exposed.NewPwnedClient(&http.Client{}, server.URL)
			count, err := c.CheckPwnedPassword(tc.password, tc.mode)

			if (err != nil) != tc.wantErr {
				t.Errorf("CheckPwnedPassword() error = %v, expectedErr %v", err, tc.wantErr)
				return
			}

			if count != tc.wantCount {
				t.Errorf("CheckPwnedPassword() = %v, expected %v", count, tc.wantCount)
			}
		})
	}
}
