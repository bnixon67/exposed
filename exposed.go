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
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// BaseURL is the endpoint for the Pwned Passwords API.
const BaseURL = "https://api.pwnedpasswords.com/range"

// sha1Hash computes the SHA-1 hash of plainText and returns it as an
// uppercase hex string.
func sha1Hash(plainText string) string {
	hash := sha1.Sum([]byte(plainText))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// ntlmHash computes the NT hash of plainText and returns it as an uppercase
// hex string.
func ntlmHash(plainText string) string {
	// Convert UTF-8 plainText to UTF-16 LE (Little Endian)
	utf16Text := utf16.Encode([]rune(plainText))
	b := make([]byte, len(utf16Text)*2)
	for i, r := range utf16Text {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}

	hash := md4.New()
	hash.Write(b)
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

// scanLines finds a line with the prefix of hashSuffix in scanner.
func scanLines(hashSuffix string, scanner *bufio.Scanner) (string, error) {
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, hashSuffix) {
			return line, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// extractCount returns the breach count from a line.
func extractCount(line string) (int, error) {
	_, count, found := strings.Cut(line, ":")
	if !found {
		return 0, errors.New("count not found")
	}

	return strconv.Atoi(count)
}

// constructURL builds the URL for the API request.
func constructURL(baseURL, hash, mode string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	hashPrefix := hash[:5]
	u.Path = path.Join(u.Path, hashPrefix)
	if mode == "ntlm" {
		query := u.Query()
		query.Set("mode", mode)
		u.RawQuery = query.Encode()
	}
	return u, nil
}

// createRequest creates an HTTP GET request for the given URL.
func createRequest(u *url.URL) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// pads out responds to enhance privacy with additional zero results
	req.Header.Set("Add-Padding", "true")
	return req, nil
}

// processResponse processes the HTTP response body and extracts the breach
// count.
func processResponse(body io.Reader, hash string) (int, error) {
	hashSuffix := hash[5:]
	scanner := bufio.NewScanner(body)
	line, err := scanLines(hashSuffix, scanner)
	if err != nil {
		return 0, err
	}
	if line == "" {
		return 0, nil
	}
	return extractCount(line)
}

// CheckPwnedHash checks if the hash has been exposed in breaches.
func CheckPwnedHash(client *http.Client, baseURL, hash, mode string) (int, error) {
	reqURL, err := constructURL(baseURL, hash, mode)
	if err != nil {
		return 0, err
	}

	req, err := createRequest(reqURL)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
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
func CheckPwnedPassword(client *http.Client, baseURL, password, mode string) (int, error) {
	var hash string
	switch mode {
	case "ntlm":
		hash = ntlmHash(password)
	default:
		hash = sha1Hash(password)
	}
	return CheckPwnedHash(client, baseURL, hash, mode)
}
