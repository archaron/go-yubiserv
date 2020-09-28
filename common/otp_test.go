package common

import (
	"encoding/hex"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOTP(t *testing.T) {
	t.Run("decrypt test", func(t *testing.T) {
		for k, vector := range TestVectors {
			binPayload, err := hex.DecodeString(misc.Modhex2hex(k))
			require.NoError(t, err, "cannot decode hex payload")
			result := &OTP{}
			require.NoError(t, result.Decrypt(vector.AESKey, binPayload), "cannot decrypt OTP '%s'", k)
			require.NotNil(t, result)
			require.Equal(t, vector.OTP, *result)
		}
	})

	t.Run("EncryptToModhex test", func(t *testing.T) {
		for k, vector := range TestVectors {
			result, err := vector.OTP.EncryptToModhex(vector.AESKey)
			require.NoError(t, err, "cannot encrypt OTP '%s'", k)
			require.Equal(t, k, result)
		}
	})
}
