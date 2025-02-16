package common_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/archaron/go-yubiserv/common"
)

func TestHMACSign(t *testing.T) {
	t.Parallel()

	apiKey, _ := base64.StdEncoding.DecodeString("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
	testHash := "iCV9uFJDtuyELQsxFPnR80Yj2XU="
	testHashBin, _ := base64.StdEncoding.DecodeString(testHash)

	testMap := []string{
		"status=OK",
		"t=2019-06-06T05:14:15Z0369",
		"nonce=0123456789abcdef",
		"otp=cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj",
		"sl=25",
	}

	t.Run("should give a right HMAC value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, testHashBin, common.SignMap(testMap, apiKey))
	})

	t.Run("should give a right HMAC base64-encoded value", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, testHash, common.SignMapToBase64(testMap, apiKey))
	})
}
