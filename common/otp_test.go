package common

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/archaron/go-yubiserv/misc"
)

func TestOTP(t *testing.T) {
	t.Run("decrypt test", func(t *testing.T) {
		for k, vector := range TestVectors {
			binPayload, err := hex.DecodeString(misc.ModHexToHex(k))
			require.NoError(t, err, "cannot decode hex payload")
			result := &OTP{}
			require.NoError(t, result.Decrypt(vector.AESKey, binPayload), "cannot decrypt OTP '%s'", k)
			require.NotNil(t, result)
			require.Equal(t, vector.OTP, *result)
			require.Equal(t, vector.Text, result.String())
		}
	})

	t.Run("EncryptToModhex test", func(t *testing.T) {
		for k, vector := range TestVectors {
			result, err := vector.OTP.EncryptToModhex(vector.AESKey)
			require.NoError(t, err, "cannot encrypt OTP '%s'", k)
			require.Equal(t, k, result)
		}
	})

	t.Run("EncryptToModhex other key, sequence test", func(t *testing.T) {
		aesKey, err := hex.DecodeString("c4422890653076cde73d449b191b416a")
		require.NoError(t, err)
		for i := uint8(0); i < 5; i++ {
			otp := &OTP{
				PrivateID:        [6]byte{0, 1, 2, 3, 4, 5},
				UsageCounter:     uint16(i),
				TimestampCounter: [3]byte{i, i, i},
				SessionCounter:   0,
				Random:           uint16(i),
			}
			result, err := otp.EncryptToModhex(aesKey)
			require.NoError(t, err, "cannot encrypt OTP '%s'", otp)
			fmt.Println(result)
		}
	})

	t.Run("must error on bad OTP", func(t *testing.T) {
		binPayload, err := hex.DecodeString(misc.ModHexToHex("dvgtiblfkbgturecfllberrvkinnctnn"))
		require.NoError(t, err, "cannot decode hex payload")
		aesOK := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		aesWrong := []byte{0xff, 0xff, 0xff, 0xff, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xff}
		aesKeyBad := []byte{0xfe, 0xed, 0x00, 0xda, 0x00, 0xba, 0xbe}
		result := &OTP{}
		require.NoError(t, result.Decrypt(aesOK, binPayload))
		require.Error(t, result.Decrypt(aesWrong, binPayload))

		require.ErrorIs(t, result.Decrypt(aesKeyBad, binPayload), aes.KeySizeError(7))

		_, err = result.Encrypt(aesKeyBad)
		require.ErrorIs(t, err, aes.KeySizeError(7))

		_, err = result.EncryptToModhex(aesKeyBad)
		require.ErrorIs(t, err, aes.KeySizeError(7))

	})

}
