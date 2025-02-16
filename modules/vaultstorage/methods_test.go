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

func TestStorageDecryptor(t *testing.T) {

	t.Parallel()

	t.Run("should decrypt test OTP", func(t *testing.T) {
		t.Parallel()
		for k, vector := range common.TestVectors {
			svc, err := vaultstorage.NewTestService(
				zaptest.NewLogger(t),
				func(publicID string) (*vaultstorage.Key, error) {
					if publicID != "cccccccccccc" {
						return nil, errors.New("test public id must be cccccccccccc")
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

func TestStorageDB(t *testing.T) {

	t.Parallel()

	// var err error
	// svc := Service{
	// 	 log: zaptest.NewLogger(t),
	//	 vault: vault.
	// }
	//
	//	svc.db, err = sqlx.Open("sqlite3", "file:test.db?cache=shared&mode=memory")
	//	require.NoError(t, err, "failed to create in-memory database")
	//	defer func() {
	//		require.NoError(t, svc.db.Close())
	//	}()
	//
	//	// Ensure database is created
	//	require.NoError(t, svc.db.Ping(), "failed to ping in-memory database")
	//
	//	t.Run("should create tables", func(t *testing.T) {
	//		require.NoError(t, svc.createDatabase(), "cannot ensure needed tables")
	//	})
	//
	//	// Generate some ID for testing
	//	rand.Seed(uint64(time.Now().UTC().UnixNano()))
	//
	//	keyID := rand.Uint64() & 0xFFFFFFFFFFFF
	//	require.NoError(t, err, "cannot generate random Key id")
	//
	//	privateBuf := make([]byte, 6)
	//	_, err = rand.Read(privateBuf)
	//	require.NoError(t, err, "cannot generate random private id")
	//
	//	aesBuf := make([]byte, 16)
	//	_, err = rand.Read(aesBuf)
	//	require.NoError(t, err, "cannot generate random aes Key")
	//
	//	lockBuf := make([]byte, 6)
	//	_, err = rand.Read(lockBuf)
	//	require.NoError(t, err, "cannot generate random lock code")
	//
	//	publicID := misc.Hex2modhex(fmt.Sprintf("%012x", keyID))
	//
	//	testKey := &Key{
	//		ID:        keyID,
	//		PublicID:  publicID,
	//		PrivateID: hex.EncodeToString(privateBuf),
	//		AESKey:    hex.EncodeToString(aesBuf),
	//		LockCode:  hex.EncodeToString(lockBuf),
	//		Active:    false,
	//		Created:   time.Now().UTC().Format("2006-01-02T15:04:05.000"),
	//	}
	//
	//	t.Run("should create Key", func(t *testing.T) {
	//		require.NoError(t, svc.StoreKey(testKey), "cannot create Key in storage")
	//	})
	//
	//	t.Run("should receive Key", func(t *testing.T) {
	//		Key, err := svc.GetKey(publicID)
	//		require.NoError(t, err, "cannot get Key from storage")
	//		require.Equal(t, testKey, Key)
	//	})
	//
}
