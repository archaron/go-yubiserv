// Package common - Common functions and types
package common

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec
	"encoding/base64"
	"sort"
	"strings"
)

// SignMap - signs specified strings slice with the given apiKey.
// @return []byte Raw HMAC signature.
func SignMap(m []string, apiKey []byte) []byte {
	mc := make([]string, len(m))
	copy(mc, m)
	sort.Strings(mc)
	payload := strings.Join(mc, "&")
	h := hmac.New(sha1.New, apiKey)
	h.Write([]byte(payload))

	return h.Sum(nil)
}

// SignMapToBase64 - signs specified strings slice with the given apiKey.
// @return []byte Base64-encoded HMAC signature.
func SignMapToBase64(m []string, apiKey []byte) string {
	return base64.StdEncoding.EncodeToString(SignMap(m, apiKey))
}
