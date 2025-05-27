package sqlitestorage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyStruct(t *testing.T) {
	t.Parallel()

	t.Run("struct fields and tags", func(t *testing.T) {
		t.Parallel()

		key := Key{
			ID:        123456789012,
			PublicID:  "cccccccccccc",
			Created:   "2023-01-01T00:00:00Z",
			PrivateID: "112233445566",
			AESKey:    "00112233445566778899aabbccddeeff",
			LockCode:  "aabbccddeeff",
			Active:    true,
		}

		// Verify field values
		require.Equal(t, uint64(123456789012), key.ID)
		require.Equal(t, "cccccccccccc", key.PublicID)
		require.Equal(t, "2023-01-01T00:00:00Z", key.Created)
		require.Equal(t, "112233445566", key.PrivateID)
		require.Equal(t, "00112233445566778899aabbccddeeff", key.AESKey)
		require.Equal(t, "aabbccddeeff", key.LockCode)
		require.True(t, key.Active)
	})

	t.Run("string representation", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name     string
			key      Key
			expected string
		}{
			{
				name: "standard key",
				key: Key{
					ID:        1,
					PublicID:  "cccccccccccc",
					PrivateID: "112233445566",
					AESKey:    "00112233445566778899aabbccddeeff",
					Active:    true,
				},
				expected: "YubiKey[ID:000000000001 Pub:cccccc... Priv:112233 AES:001122... Active:true]",
			},
			{
				name: "inactive key",
				key: Key{
					ID:        2,
					PublicID:  "dddddddddddd",
					PrivateID: "aabbccddeeff",
					AESKey:    "ffeeddccbbaa99887766554433221100",
					Active:    false,
				},
				expected: "YubiKey[ID:000000000002 Pub:dddddd... Priv:aabbcc AES:ffeedd... Active:false]",
			},
			{
				name: "empty values",
				key: Key{
					ID:        0,
					PublicID:  "",
					PrivateID: "",
					AESKey:    "",
					Active:    false,
				},
				expected: "YubiKey[ID:000000000000 Pub:... Priv: AES:... Active:false]",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				require.Equal(t, tc.expected, tc.key.String())
			})
		}
	})

	t.Run("string truncation", func(t *testing.T) {
		t.Parallel()

		key := Key{
			ID:        1,
			PublicID:  "aabbccddeeff",                     // Exactly 12 chars
			PrivateID: "112233445566",                     // Exactly 12 chars
			AESKey:    "00112233445566778899aabbccddeeff", // Exactly 32 chars
			Active:    true,
		}

		output := key.String()
		require.Contains(t, output, "Pub:aabbcc...") // First 6 chars of PublicID
		require.Contains(t, output, "Priv:112233")   // Full PrivateID (not truncated)
		require.Contains(t, output, "AES:001122...") // First 6 chars of AESKey
	})
}
