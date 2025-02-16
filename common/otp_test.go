package common_test

import (
	"crypto/aes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
)

func TestOTP(t *testing.T) {
	t.Parallel()
	t.Run("decrypt test", func(t *testing.T) {
		t.Parallel()

		for k, vector := range common.TestVectors {
			binPayload, err := hex.DecodeString(misc.ModHexToHex(k))
			require.NoError(t, err, "cannot decode hex payload")

			result := &common.OTP{}

			require.NoError(t, result.Decrypt(vector.AESKey, binPayload), "cannot decrypt OTP '%s'", k)
			require.NotNil(t, result)
			require.Equal(t, vector.OTP, *result)
			require.Equal(t, vector.Text, result.String())
		}
	})

	t.Run("EncryptToModHex test", func(t *testing.T) {
		t.Parallel()

		for k, vector := range common.TestVectors {
			result, err := vector.OTP.EncryptToModHex(vector.AESKey)
			require.NoError(t, err, "cannot encrypt OTP '%s'", k)
			require.Equal(t, k, result)
		}
	})

	t.Run("EncryptToModHex other key, sequence test", func(t *testing.T) {
		t.Parallel()

		aesKey, err := hex.DecodeString("c4422890653076cde73d449b191b416a")

		require.NoError(t, err)

		for i := range uint8(5) {
			otp := &common.OTP{
				PrivateID:        [6]byte{0, 1, 2, 3, 4, 5},
				UsageCounter:     uint16(i),
				TimestampCounter: [3]byte{i, i, i},
				SessionCounter:   0,
				Random:           uint16(i),
			}
			result, err := otp.EncryptToModHex(aesKey)
			require.NoError(t, err, "cannot encrypt OTP '%s'", otp)
			require.NotEmpty(t, result, "empty cannot encrypt OTP '%s'", otp)
		}
	})

	t.Run("must error on bad OTP", func(t *testing.T) {
		t.Parallel()

		binPayload, err := hex.DecodeString(misc.ModHexToHex("dvgtiblfkbgturecfllberrvkinnctnn"))
		require.NoError(t, err, "cannot decode hex payload")

		aesOK := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		aesWrong := []byte{0xff, 0xff, 0xff, 0xff, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xff}
		aesKeyBad := []byte{0xfe, 0xed, 0x00, 0xda, 0x00, 0xba, 0xbe}
		result := &common.OTP{}

		require.NoError(t, result.Decrypt(aesOK, binPayload))
		require.Error(t, result.Decrypt(aesWrong, binPayload))

		err = result.Decrypt(aesKeyBad, binPayload)
		require.ErrorIs(t, errors.Unwrap(err), aes.KeySizeError(7))

		_, err = result.Encrypt(aesKeyBad)
		require.ErrorIs(t, err, aes.KeySizeError(7))

		_, err = result.EncryptToModHex(aesKeyBad)
		require.ErrorIs(t, err, aes.KeySizeError(7))
	})
}
