// Copyright 2025 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/bnixon67/exposed"
	"golang.org/x/term"
)

const (
	maxScanTokenSize     = 1024 * 1024 // 1MB for scanner buffer
	exitCodeInvalidFlags = 1
	exitCodeScannerError = 2
)

// formatIntWithSeparator formats an integer with a specified single-character
// separator, grouping the digits in threes. It supports both negative and
// non-negative integers.
func formatIntWithSeparator(n int, separator rune) string {
	// Handle the special case of math.MinInt which cannot be negated
	if n == math.MinInt {
		return strconv.Itoa(n)
	}

	isNegative := n < 0
	if isNegative {
		n = -n
	}

	s := strconv.Itoa(n)
	l := len(s)

	if l <= 3 {
		if isNegative {
			return "-" + s
		}
		return s
	}

	numSeparators := (l - 1) / 3
	bufferSize := l + numSeparators
	var buf bytes.Buffer
	buf.Grow(bufferSize)

	if isNegative {
		buf.WriteByte('-')
	}

	// Process initial segment
	mod := l % 3
	if mod > 0 {
		buf.WriteString(s[:mod])
		if l > mod {
			buf.WriteRune(separator)
		}
	}

	// Process remaining segments
	for p := mod; p < l; p += 3 {
		buf.WriteString(s[p : p+3])
		if p+3 < l {
			buf.WriteRune(separator)
		}
	}

	return buf.String()
}

// readAndCheck reads input from an io.Reader line by line, trims any
// surrounding whitespace from each line, and checks if the line has been
// exposed using the exposed.CheckPwned function with the provided lookupMode
// and hashMode. It respects context cancellation for graceful shutdown.
func readAndCheck(ctx context.Context, r io.Reader, lookupMode, hashMode string) error {
	scanner := bufio.NewScanner(r)

	// Increase buffer size to handle long lines
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue // Skip empty lines
		}

		count, err := exposed.CheckPwned(line, lookupMode, hashMode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed for %q: %v\n", line, err)
			continue
		}

		if count == 0 {
			fmt.Printf("%s: not found\n", line)
			continue
		}

		fmt.Printf("%s: exposed %s times\n",
			line, formatIntWithSeparator(count, ','))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	return nil
}

// formatValues takes a slice of strings and returns a single string where
// each value is quoted and separated by a comma and space.
//
// For example, ["a", "b", "c"] becomes "a", "b", "c".
func formatValues(values []string) string {
	return `"` + strings.Join(values, `", "`) + `"`
}

// isValid checks if the provided value is in the list of validValues.
// Returns true and empty string if valid, false and error message if invalid.
func isValid(name, value string, validValues []string) (bool, string) {
	for _, v := range validValues {
		if value == v {
			return true, ""
		}
	}
	return false, fmt.Sprintf("invalid %s: %q, valid values: %s",
		name, value, formatValues(validValues))
}

func main() {
	// Setup flags with more descriptive usage text
	mode := flag.String("mode", "sha1",
		"hash algorithm to use ("+formatValues(exposed.ValidHashes)+")")
	lookup := flag.String("lookup", "password",
		"lookup type ("+formatValues(exposed.ValidLookups)+")")
	flag.Parse()

	// Validate the flags
	validations := []struct {
		name        string
		value       string
		validValues []string
	}{
		{"mode", *mode, exposed.ValidHashes},
		{"lookup", *lookup, exposed.ValidLookups},
	}

	for _, v := range validations {
		valid, msg := isValid(v.name, v.value, v.validValues)
		if !valid {
			fmt.Fprintf(os.Stderr, "%s: %s\n", filepath.Base(os.Args[0]), msg)
			os.Exit(exitCodeInvalidFlags)
		}
	}

	// Setup context for graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nInterrupt received, shutting down...")
		cancel()
	}()

	// Provide user guidance if running in a terminal session
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if *lookup == "password" {
			fmt.Println("Enter passwords to check, one per line (Ctrl+C to exit):")
		} else {
			fmt.Printf("Enter %s hashes to check, one per line (Ctrl+C to exit):\n", *mode)
		}
	}

	if err := readAndCheck(ctx, os.Stdin, *lookup, *mode); err != nil {
		if err == context.Canceled {
			// User interrupted, exit gracefully
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitCodeScannerError)
	}
}
