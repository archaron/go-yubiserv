package misc

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

// Hex2modhex converts standard hex string to mod-hex format
func Hex2modhex(hex string) string {
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

// Dvorak2modhex converts OPT in Dvorak keyboard layout to standard modhex OTP.
func Dvorak2modhex(dvModHex string) string {
	hexmod := map[rune]rune{
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
		if c, ok := hexmod[r]; ok {
			return c
		}
		return 0
	}, dvModHex)
}

// Modhex2hex converts mod-hex OPT to standard hex string.
func Modhex2hex(modHex string) string {
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

// Rand generates random bytes
func Rand(count int) ([]byte, error) {
	buf := make([]byte, count)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	} else {
		return buf, nil
	}
}

// HexRand generates random hex string
func HexRand(count int) (string, error) {
	if buf, err := Rand(count); err != nil {
		return "", err
	} else {
		return hex.EncodeToString(buf), nil
	}
}

// IsModhex checks, if given string is in modhex encoding
func IsModhex(s string) bool {
	return regexp.MustCompile(`(?m)^[cbdefghijklnrtuv]+$`).MatchString(s)
}

// IsDvorakModhex checks, if given string is in Dvorak layout modhex encoding
func IsDvorakModhex(s string) bool {
	return regexp.MustCompile(`(?m)^[jxe.uidchtnbpygk]+$`).MatchString(s)
}

// IsAlphanum checks, if given string is alphanumeric
func IsAlphanum(s string) bool {
	return regexp.MustCompile(`(?m)^[a-zA-Z0-9]+$`).MatchString(s)
}
