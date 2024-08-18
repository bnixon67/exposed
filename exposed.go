// Copyright (c) 2024 Bill Nixon

// The `exposed` package provides utilities to check if a password or its
// hash has been exposed in breaches using the Have I Been Pwned API.
//
// See https://haveibeenpwned.com/API/v3#PwnedPasswords for more information.
package exposed

import (
	"bufio"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// BaseURL is the endpoint for the Pwned Passwords API.
const BaseURL = "https://api.pwnedpasswords.com/range"

var ValidHashes = []string{"sha1", "ntlm"}
var ValidLookups = []string{"password", "hash"}

// PwnedClient is a client to checkif passwords or hashes have been exposed.
type PwnedClient struct {
	httpClient *http.Client
	baseURL    string
}

// NewPwnedClient creates a new PwnedClient with given HTTP client and base URL.
func NewPwnedClient(client *http.Client, baseURL string) *PwnedClient {
	return &PwnedClient{
		httpClient: client,
		baseURL:    baseURL,
	}
}

var DefaultPwnedClient = PwnedClient{
	httpClient: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	},
	baseURL: BaseURL,
}

// extractCount returns the breach count from a line.
func extractCount(line string) (int, error) {
	_, count, found := strings.Cut(line, ":")
	if !found {
		return 0, errors.New("count not found")
	}

	return strconv.Atoi(count)
}

// buildURL builds the URL for the API request.
func buildURL(baseURL, hash, mode string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	u.Path = path.Join(u.Path, hash[:5])
	if mode == "ntlm" {
		query := u.Query()
		query.Set("mode", mode)
		u.RawQuery = query.Encode()
	}
	return u, nil
}

// newGetRequestWithPadding creates an HTTP GET request for the given URL,
// setting the Add-Padding header to enhance privacy.
func newGetRequestWithPadding(u *url.URL) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// pads out responds to enhance privacy with additional zero results
	req.Header.Set("Add-Padding", "true")

	return req, nil
}

// findLineWithPrefix scans r and returns first line that starts with prefix.
func findLineWithPrefix(r io.Reader, prefix string) (string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix) {
			return line, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil // ignore io.EOF
}

// processResponse processes body and extracts the breach count.
func processResponse(body io.Reader, hash string) (int, error) {
	suffix := hash[5:]
	line, err := findLineWithPrefix(body, suffix)
	if err != nil {
		return 0, err
	}
	if line == "" {
		return 0, nil
	}
	return extractCount(line)
}

// ntHash computes the NT hash of s and returns it as an uppercase
// hex string.
func ntHash(s string) string {
	// Convert s to UTF-16 Little Endian
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}

	hash := md4.New()
	hash.Write(b)
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

// sha1Hash computes the SHA-1 hash of s and returns it as an uppercase
// hex string.
func sha1Hash(s string) string {
	hash := sha1.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// CheckPwnedHash checks if the hash of type mode has been exposed in breaches.
func (c *PwnedClient) CheckPwnedHash(hash, mode string) (int, error) {
	hash = strings.ToUpper(hash)

	reqURL, err := buildURL(c.baseURL, hash, mode)
	if err != nil {
		return 0, err
	}

	req, err := newGetRequestWithPadding(reqURL)
	if err != nil {
		return 0, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("received non-OK HTTP status for %q: %d", reqURL, resp.StatusCode)
	}

	return processResponse(resp.Body, hash)
}

// CheckPwnedPassword checks if the password has been exposed in breaches.
// Mode is used to select which type of hash to use, i.e., ntlm or sha1.
func (c *PwnedClient) CheckPwnedPassword(password, mode string) (int, error) {
	var hash string
	switch mode {
	case "ntlm":
		hash = ntHash(password)
	default:
		hash = sha1Hash(password)
	}
	return c.CheckPwnedHash(hash, mode)
}

// CheckPwned checks if a password or hash has been exposed in breaches.
func (c *PwnedClient) CheckPwned(text, lookup, mode string) (int, error) {
	switch lookup {
	case "hash":
		return c.CheckPwnedHash(text, mode)
	case "password":
		return c.CheckPwnedPassword(text, mode)
	default:
		return 0, fmt.Errorf("invalid lookup type: %s", lookup)
	}
}

// CheckPwned checks if a password or hash has been exposed in breaches.
func CheckPwned(text, lookup, mode string) (int, error) {
	switch lookup {
	case "hash":
		return DefaultPwnedClient.CheckPwnedHash(text, mode)
	case "password":
		return DefaultPwnedClient.CheckPwnedPassword(text, mode)
	default:
		return 0, fmt.Errorf("invalid lookup type: %s", lookup)
	}
}
