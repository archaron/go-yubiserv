package misc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// HexToModHex converts a standard hex string to mod-hex format.
func HexToModHex(hex string) string {
	hexmod := map[rune]rune{
		'0': 'c',
		'1': 'b',
		'2': 'd',
		'3': 'e',
		'4': 'f',
		'5': 'g',
		'6': 'h',
		'7': 'i',
		'8': 'j',
		'9': 'k',
		'a': 'l',
		'b': 'n',
		'c': 'r',
		'd': 't',
		'e': 'u',
		'f': 'v',
	}

	return strings.Map(func(r rune) rune {
		if c, ok := hexmod[r]; ok {
			return c
		}

		return 0
	}, hex)
}

// DvorakToModHex converts OPT in Dvorak keyboard layout to standard modhex OTP.
func DvorakToModHex(dvModHex string) string {
	d2modhex := map[rune]rune{
		'j': 'c',
		'x': 'b',
		'e': 'd',
		'.': 'e',
		'u': 'f',
		'i': 'g',
		'd': 'h',
		'c': 'i',
		'h': 'j',
		't': 'k',
		'n': 'l',
		'b': 'n',
		'p': 'r',
		'y': 't',
		'g': 'u',
		'k': 'v',
	}

	return strings.Map(func(r rune) rune {
		if c, ok := d2modhex[r]; ok {
			return c
		}

		return 0
	}, dvModHex)
}

// ModHexToDvorak converts OPT in Modhex to Dvorak keyboard layout OTP.
func ModHexToDvorak(dvModHex string) string {
	modhex2d := map[rune]rune{
		'c': 'j',
		'b': 'x',
		'd': 'e',
		'e': '.',
		'f': 'u',
		'g': 'i',
		'h': 'd',
		'i': 'c',
		'j': 'h',
		'k': 't',
		'l': 'n',
		'n': 'b',
		'r': 'p',
		't': 'y',
		'u': 'g',
		'v': 'k',
	}

	return strings.Map(func(r rune) rune {
		if c, ok := modhex2d[r]; ok {
			return c
		}

		return 0
	}, dvModHex)
}

// ModHexToHex converts mod-hex OPT to a standard hex string.
func ModHexToHex(modHex string) string {
	modhex := map[rune]rune{
		'c': '0',
		'b': '1',
		'd': '2',
		'e': '3',
		'f': '4',
		'g': '5',
		'h': '6',
		'i': '7',
		'j': '8',
		'k': '9',
		'l': 'a',
		'n': 'b',
		'r': 'c',
		't': 'd',
		'u': 'e',
		'v': 'f',
	}

	return strings.Map(func(r rune) rune {
		if c, ok := modhex[r]; ok {
			return c
		}

		return 0
	}, modHex)
}

// Rand generates random bytes.
func Rand(count int) ([]byte, error) {
	buf := make([]byte, count)

	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}

	return buf, nil
}

// HexRand generates random hex string.
func HexRand(count int) (string, error) {
	buf, err := Rand(count)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}

// IsModHex checks if the given string uses modhex encoding.
func IsModHex(s string) bool {
	return regexp.MustCompile(`(?m)^[cbdefghijklnrtuv]+$`).MatchString(s)
}

// IsDvorakModHex checks if the given string uses Dvorak-layout modhex encoding.
func IsDvorakModHex(s string) bool {
	return regexp.MustCompile(`(?m)^[jxe.uidchtnbpygk]+$`).MatchString(s)
}

// IsAlphaNum checks if the given string is alphanumeric.
func IsAlphaNum(s string) bool {
	return regexp.MustCompile(`(?m)^[a-zA-Z0-9]+$`).MatchString(s)
}
