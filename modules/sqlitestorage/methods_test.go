package sqlitestorage_test

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"golang.org/x/exp/rand"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/archaron/go-yubiserv/modules/sqlitestorage"
)

var (
	errTestError = errors.New("test error")
)

func setupTestDB(t *testing.T) (*sqlx.DB, *sqlitestorage.Service) {
	db, err := sqlx.Open("sqlite3", "file:test.db?cache=shared&mode=memory&_foreign_keys=true")
	require.NoError(t, err, "failed to create in-memory database")

	t.Cleanup(func() { require.NoError(t, db.Close()) })

	svc := sqlitestorage.TestNewService(zaptest.NewLogger(t), nil, db)
	require.NoError(t, svc.TestCreateDatabase(), "failed to create tables")

	return db, svc
}

func generateTestKey(t *testing.T) *sqlitestorage.Key {
	privateID := make([]byte, 6)
	_, err := rand.Read(privateID)
	require.NoError(t, err)

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	require.NoError(t, err)

	lockCode := make([]byte, 6)
	_, err = rand.Read(lockCode)
	require.NoError(t, err)

	return &sqlitestorage.Key{
		ID:        rand.Uint64() & 0xFFFFFFFFFFFF,
		PublicID:  misc.HexToModHex(fmt.Sprintf("%012x", rand.Uint32())),
		PrivateID: hex.EncodeToString(privateID),
		AESKey:    hex.EncodeToString(aesKey),
		LockCode:  hex.EncodeToString(lockCode),
		Active:    true,
		Created:   time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func TestDecryptOTP(t *testing.T) {
	t.Parallel()

	t.Run("successful decryption", func(t *testing.T) {
		t.Parallel()

		for otpToken, vector := range common.TestVectors {
			t.Run(otpToken, func(t *testing.T) {
				t.Parallel()

				svc := sqlitestorage.TestNewService(
					zaptest.NewLogger(t),
					func(publicID string) (*sqlitestorage.Key, error) {
						require.Equal(t, "cccccccccccc", publicID)
						return &sqlitestorage.Key{
							PublicID:  "cccccccccccc",
							PrivateID: hex.EncodeToString(vector.PrivateID[:]),
							AESKey:    hex.EncodeToString(vector.AESKey),
							Active:    true,
						}, nil
					}, nil)

				otp, err := svc.DecryptOTP("cccccccccccc", otpToken)
				require.NoError(t, err)
				require.Equal(t, vector.OTP, *otp)
			})
		}
	})

	t.Run("error cases", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name        string
			publicID    string
			mockKey     *sqlitestorage.Key
			mockError   error
			expectedErr error
		}{
			{
				name:        "key not found",
				publicID:    "cccccccccccc",
				mockError:   sql.ErrNoRows,
				expectedErr: common.ErrStorageNoKey,
			},
			{
				name:        "inactive key",
				publicID:    "cccccccccccc",
				mockKey:     &sqlitestorage.Key{Active: false},
				expectedErr: common.ErrStorageKeyInactive,
			},
			{
				name:        "invalid AES key",
				publicID:    "cccccccccccc",
				mockKey:     &sqlitestorage.Key{AESKey: "invalid", Active: true},
				expectedErr: common.ErrStorageDecryptFail,
			},
			{
				name:        "storage error",
				publicID:    "cccccccccccc",
				mockError:   errTestError,
				expectedErr: errTestError,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				svc := sqlitestorage.TestNewService(
					zaptest.NewLogger(t),
					func(publicID string) (*sqlitestorage.Key, error) {
						return tc.mockKey, tc.mockError
					}, nil)

				_, err := svc.DecryptOTP(tc.publicID, "dummy")
				require.ErrorIs(t, err, tc.expectedErr)
			})
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		svc := sqlitestorage.TestNewService(
			zaptest.NewLogger(t),
			func(publicID string) (*sqlitestorage.Key, error) {
				return &sqlitestorage.Key{
					PublicID:  publicID,
					PrivateID: hex.EncodeToString(make([]byte, 6)),
					AESKey:    hex.EncodeToString(make([]byte, 16)),
					Active:    true,
				}, nil
			}, nil)

		_, err := svc.DecryptOTP("cccccccccccc", "invalid_token")
		require.ErrorIs(t, err, common.ErrStorageDecryptFail)
	})

	t.Run("private ID mismatch", func(t *testing.T) {
		t.Parallel()

		key := generateTestKey(t)
		key.PublicID = "cccccccccccc"
		key.Active = true

		svc := sqlitestorage.TestNewService(
			zaptest.NewLogger(t),
			func(publicID string) (*sqlitestorage.Key, error) {
				return key, nil
			}, nil)

		// Use a test vector but with wrong private ID
		for otpToken := range common.TestVectors {
			_, err := svc.DecryptOTP("cccccccccccc", otpToken)
			require.ErrorIs(t, err, common.ErrStorageDecryptFail)
			break // Only need one test case
		}
	})

	t.Run("private ID mismatch 2", func(t *testing.T) {
		t.Parallel()

		// Create a test key with known PrivateID
		testKey := &sqlitestorage.Key{
			PublicID:  "cccccccccccc",
			PrivateID: "112233445566",                       // Fixed test PrivateID
			AESKey:    hex.EncodeToString(make([]byte, 16)), // Valid AES key
			Active:    true,
		}

		// Create test OTP with different PrivateID
		otp := common.OTP{
			PrivateID: [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // Doesn't match key
		}

		// Encrypt test OTP
		encrypted, err := otp.Encrypt(make([]byte, 16))
		require.NoError(t, err)

		// Convert to modhex format
		token := misc.HexToModHex(hex.EncodeToString(encrypted))

		svc := sqlitestorage.TestNewService(
			zaptest.NewLogger(t),
			func(publicID string) (*sqlitestorage.Key, error) {
				require.Equal(t, "cccccccccccc", publicID)
				return testKey, nil
			}, nil)

		// Should fail with decrypt error due to PrivateID mismatch
		_, err = svc.DecryptOTP("cccccccccccc", token)
		require.ErrorIs(t, err, common.ErrStorageDecryptFail)
	})
}

func TestStoreKey(t *testing.T) {
	db, svc := setupTestDB(t)

	t.Run("store new key", func(t *testing.T) {
		key := generateTestKey(t)
		require.NoError(t, svc.StoreKey(key))

		// Verify the key was stored
		var count int
		err := db.Get(&count, "SELECT COUNT(*) FROM Keys WHERE public_id=?", key.PublicID)
		require.NoError(t, err)
		require.Equal(t, 1, count)
	})

	t.Run("update existing key", func(t *testing.T) {
		key := generateTestKey(t)
		require.NoError(t, svc.StoreKey(key))

		// Update the key
		key.Active = false
		require.NoError(t, svc.StoreKey(key))

		// Verify the update
		var active bool
		err := db.Get(&active, "SELECT active FROM Keys WHERE public_id=?", key.PublicID)
		require.NoError(t, err)
		require.False(t, active)
	})

	t.Run("invalid key data", func(t *testing.T) {
		invalidKey := &sqlitestorage.Key{
			PublicID: "tooshort", // Invalid length
		}
		err := svc.StoreKey(invalidKey)
		require.Error(t, err)
	})
}

func TestGetKey(t *testing.T) {
	db, svc := setupTestDB(t)

	t.Run("get existing key", func(t *testing.T) {
		key := generateTestKey(t)
		_, err := db.NamedExec(
			"INSERT INTO Keys (id, public_id, created, private_id, lock_code, aes_key, active) VALUES (:id, :public_id, :created, :private_id, :lock_code, :aes_key, :active)",
			key)
		require.NoError(t, err)

		retrieved, err := svc.GetKey(key.PublicID)
		require.NoError(t, err)
		require.Equal(t, key, retrieved)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := svc.GetKey("nonexistent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot get key")
	})

	t.Run("database error", func(t *testing.T) {
		// Force close database to simulate error
		require.NoError(t, db.Close())

		_, err := svc.GetKey("any")
		require.Error(t, err)
	})
}

func TestCreateDatabase(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		db, err := sqlx.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })

		svc := sqlitestorage.TestNewService(zaptest.NewLogger(t), nil, db)
		require.NoError(t, svc.TestCreateDatabase())

		// Verify tables were created
		var tableExists bool
		err = db.Get(&tableExists, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='Keys'")
		require.NoError(t, err)
		require.True(t, tableExists)
	})

	t.Run("creation failure", func(t *testing.T) {
		db, err := sqlx.Open("sqlite3", ":memory:")
		require.NoError(t, err)
		_ = db.Close() // Close immediately to force error

		svc := sqlitestorage.TestNewService(zaptest.NewLogger(t), nil, db)
		err = svc.TestCreateDatabase()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create Keys table")
	})
}
