// Copyright (c) 2024 Bill Nixon

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
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

func processInput(inputScanner *bufio.Scanner, client *http.Client, lookupMode, hashMode string) {
	for inputScanner.Scan() {
		text := inputScanner.Text()

		var (
			count int
			err   error
		)

		if lookupMode == "hash" {
			text = strings.ToUpper(text)
			count, err = exposed.CheckPwnedHash(client, exposed.BaseURL, text, hashMode)
		} else {
			count, err = exposed.CheckPwnedPassword(client, exposed.BaseURL, text, hashMode)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed for %q: %v\n", text, err)
			continue
		}

		if count == 0 {
			fmt.Printf("%s: not found\n", text)
			continue
		}

		fmt.Printf("%s: exposed %s times\n", text, formatIntWithSeparator(count, ','))
	}

	if err := inputScanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

func main() {
	mode := flag.String("mode", "sha1", "hash mode (sha1, ntlm)")
	lookup := flag.String("lookup", "password", "lookup password or hash")
	flag.Parse()

	if term.IsTerminal(int(os.Stdin.Fd())) {
		if *lookup == "password" {
			fmt.Println("Enter passwords to check, one per line:")
		} else {
			fmt.Printf("Enter %s hashes to check, one per line:\n", *mode)
		}

	}

	client := &http.Client{}
	inputScanner := bufio.NewScanner(os.Stdin)

	processInput(inputScanner, client, *lookup, *mode)
}
