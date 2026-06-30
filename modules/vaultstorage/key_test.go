package vaultstorage_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/archaron/go-yubiserv/modules/vaultstorage"
)

func TestKey_String(t *testing.T) {
	t.Parallel()

	t.Run("standard key", func(t *testing.T) {
		t.Parallel()

		k := vaultstorage.Key{
			ID:        1,
			PublicID:  "cccccccccccc",
			PrivateID: "112233445566",
			AESKey:    "00112233445566778899aabbccddeeff", // gitleaks:allow test key
			LockCode:  "aabbccddeeff",
			Active:    true,
			Created:   "2023-01-01T00:00:00Z",
		}

		expected := "YubiKey: ID: 000000000001, PublicID: cccccccccccc, PrivateID: 112233445566, " +
			"AESKey: 00112233445566778899aabbccddeeff, LockCode: aabbccddeeff Active: true Created: 2023-01-01T00:00:00Z"

		require.Equal(t, expected, k.String())
	})

	t.Run("inactive key", func(t *testing.T) {
		t.Parallel()

		k := vaultstorage.Key{
			ID:        2,
			PublicID:  "dddddddddddd",
			PrivateID: "aabbccddeeff",
			AESKey:    "ffeeddccbbaa99887766554433221100", // gitleaks:allow test key
			Active:    false,
		}

		require.Contains(t, k.String(), "Active: false")
		require.Contains(t, k.String(), "Pub")
	})

	t.Run("empty key", func(t *testing.T) {
		t.Parallel()

		k := vaultstorage.Key{}
		require.NotEmpty(t, k.String())
	})
}
