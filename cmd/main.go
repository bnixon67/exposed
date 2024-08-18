// Copyright (c) 2024 Bill Nixon

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bnixon67/exposed"
	"golang.org/x/term"
)

// formatIntWithSeparator formats an integer with a specified single-character
// separator, grouping the digits in threes. It supports both negative and
// non-negative integers.
func formatIntWithSeparator(n int, separator rune) string {
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
// and hashMode.
func readAndCheck(r io.Reader, lookupMode, hashMode string) {
	// Scan input line by line.
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

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
		fmt.Fprintln(os.Stderr, "scanner error:", err)
	}
}

// formatValues takes a slice of strings and returns a single string where
// each value is quoted and separated by a comma and space.
//
// For example, ["a", "b", "c"] becomes "a", "b", "c".
func formatValues(values []string) string {
	return "\"" + strings.Join(values, "\", \"") + "\""
}

// isValid checks if the provided value is in the list of validValues.
func isValid(name, value string, validValues []string) (bool, string) {
	for _, v := range validValues {
		if value == v {
			return true, ""
		}
	}
	return false, fmt.Sprintf("invalid %s: %q, valid values: %s\n", name, value, formatValues(validValues))
}

func main() {
	// setup flags
	mUsage := fmt.Sprintf("mode (%s)", formatValues(exposed.ValidHashes))
	mode := flag.String("mode", "sha1", mUsage)

	lUsage := fmt.Sprintf("lookup (%s)", formatValues(exposed.ValidLookups))
	lookup := flag.String("lookup", "password", lUsage)
	flag.Parse()

	// validate the flags
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
			fmt.Fprintf(os.Stderr, "%s: %s", filepath.Base(os.Args[0]), msg)
			os.Exit(1)
		}
	}

	// adjust if running in a terminal session
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if *lookup == "password" {
			fmt.Println("Enter passwords to check, one per line:")
		} else {
			fmt.Printf("Enter %s hashes to check, one per line:\n", *mode)
		}

	}

	readAndCheck(os.Stdin, *lookup, *mode)
}
