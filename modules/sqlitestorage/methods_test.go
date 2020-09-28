package sqlitestorage

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/exp/rand"
	"testing"
	"time"
)

func TestStorageDecryptor(t *testing.T) {
	svc := Service{
		log: zaptest.NewLogger(t),
	}

	t.Run("should decrypt test OTP", func(t *testing.T) {
		for k, vector := range common.TestVectors {

			// Test stub
			svc.getKey = func(publicID string) (*key, error) {
				if publicID != "cccccccccccc" {
					return nil, errors.New("test public id must be cccccccccccc")
				}

				return &key{
					ID:        1,
					PublicID:  "cccccccccccc",
					Created:   "",
					PrivateID: hex.EncodeToString(vector.PrivateID[:]),
					AESKey:    hex.EncodeToString(vector.AESKey[:]),
					LockCode:  "010203040506",
					Active:    true,
				}, nil
			}

			otp, err := svc.DecryptOTP("cccccccccccc", k)
			require.NoError(t, err, "cannot decrypt OTP '%s'", k)
			require.NotNil(t, otp)
			require.Equal(t, vector.OTP, *otp)
		}
	})
}

func TestStorageDB(t *testing.T) {
	var err error
	svc := Service{
		log: zaptest.NewLogger(t),
	}

	svc.db, err = sqlx.Open("sqlite3", "file:test.db?cache=shared&mode=memory")
	require.NoError(t, err, "failed to create in-memory database")
	defer func() {
		require.NoError(t, svc.db.Close())
	}()

	// Ensure database is created
	require.NoError(t, svc.db.Ping(), "failed to ping in-memory database")

	t.Run("should create tables", func(t *testing.T) {
		require.NoError(t, svc.createDatabase(), "cannot ensure needed tables")
	})

	// Generate some ID for testing
	rand.Seed(uint64(time.Now().UTC().UnixNano()))

	keyID := rand.Uint64() & 0xFFFFFFFFFFFF
	require.NoError(t, err, "cannot generate random key id")

	privateBuf := make([]byte, 6)
	_, err = rand.Read(privateBuf)
	require.NoError(t, err, "cannot generate random private id")

	aesBuf := make([]byte, 16)
	_, err = rand.Read(aesBuf)
	require.NoError(t, err, "cannot generate random aes key")

	lockBuf := make([]byte, 6)
	_, err = rand.Read(lockBuf)
	require.NoError(t, err, "cannot generate random lock code")

	publicID := misc.Hex2modhex(fmt.Sprintf("%012x", keyID))

	testKey := &key{
		ID:        keyID,
		PublicID:  publicID,
		PrivateID: hex.EncodeToString(privateBuf),
		AESKey:    hex.EncodeToString(aesBuf),
		LockCode:  hex.EncodeToString(lockBuf),
		Active:    false,
		Created:   time.Now().UTC().Format("2006-01-02T15:04:05.000"),
	}

	t.Run("should create key", func(t *testing.T) {
		require.NoError(t, svc.StoreKey(testKey), "cannot create key in storage")
	})

	t.Run("should receive key", func(t *testing.T) {
		key, err := svc.GetKey(publicID)
		require.NoError(t, err, "cannot get key from storage")
		require.Equal(t, testKey, key)
	})

}
