package vaultstorage_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/modules/vaultstorage"
)

var ErrWrongTestID = errors.New("test public id must be cccccccccccc")

func TestStorageDecryptor(t *testing.T) {

	t.Parallel()

	t.Run("should decrypt test OTP", func(t *testing.T) {
		t.Parallel()

		for k, vector := range common.TestVectors {
			svc, err := vaultstorage.NewTestService(
				zaptest.NewLogger(t),
				func(publicID string) (*vaultstorage.Key, error) {
					if publicID != "cccccccccccc" {
						return nil, ErrWrongTestID
					}

					return &vaultstorage.Key{
						ID:        1,
						PublicID:  "cccccccccccc",
						Created:   "",
						PrivateID: hex.EncodeToString(vector.PrivateID[:]),
						AESKey:    hex.EncodeToString(vector.AESKey),
						LockCode:  "010203040506",
						Active:    true,
					}, nil
				},
			)
			require.NoError(t, err)

			otp, err := svc.DecryptOTP("cccccccccccc", k)
			require.NoError(t, err, "cannot decrypt OTP '%s'", k)
			require.NotNil(t, otp)
			require.Equal(t, vector.OTP, *otp)
		}
	})
}
