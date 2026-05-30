package vaultstorage_test

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap/zaptest"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/modules/vaultstorage"
)

var errTestError = errors.New("test error")

func createTestService(t *testing.T, getter vaultstorage.KeyGetterFunc) *vaultstorage.Service {
	t.Helper()

	svc, err := vaultstorage.NewTestService(zaptest.NewLogger(t), getter)
	require.NoError(t, err)

	return svc
}

func TestDecryptOTP(t *testing.T) {
	t.Parallel()

	t.Run("successful decryption", func(t *testing.T) {
		t.Parallel()

		for otpToken, vector := range common.TestVectors {
			t.Run(otpToken, func(t *testing.T) {
				t.Parallel()

				svc := createTestService(t, func(publicID string) (*vaultstorage.Key, error) {
					require.Equal(t, "cccccccccccc", publicID)
					return &vaultstorage.Key{
						PublicID:  "cccccccccccc",
						PrivateID: hex.EncodeToString(vector.PrivateID[:]),
						AESKey:    hex.EncodeToString(vector.AESKey),
						Active:    true,
					}, nil
				})

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
			mockKey     *vaultstorage.Key
			mockError   error
			expectedErr error
			errContains string
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
				mockKey:     &vaultstorage.Key{Active: false},
				expectedErr: common.ErrStorageKeyInactive,
			},
			{
				name:        "invalid AES key",
				publicID:    "cccccccccccc",
				mockKey:     &vaultstorage.Key{AESKey: "invalid", Active: true},
				errContains: "failed to decode AES key",
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

				svc := createTestService(t, func(_ string) (*vaultstorage.Key, error) {
					return tc.mockKey, tc.mockError
				})

				_, err := svc.DecryptOTP(tc.publicID, "dummy")
				if tc.errContains != "" {
					require.ErrorContains(t, err, tc.errContains)
				} else {
					require.ErrorIs(t, err, tc.expectedErr)
				}
			})
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		svc := createTestService(t, func(publicID string) (*vaultstorage.Key, error) {
			return &vaultstorage.Key{
				PublicID:  publicID,
				PrivateID: hex.EncodeToString(make([]byte, 6)),
				AESKey:    hex.EncodeToString(make([]byte, 16)),
				Active:    true,
			}, nil
		})

		_, err := svc.DecryptOTP("cccccccccccc", "invalid_token")
		require.ErrorContains(t, err, "failed to decode token")
	})

	t.Run("private ID mismatch", func(t *testing.T) {
		t.Parallel()

		key := &vaultstorage.Key{
			PublicID:  "cccccccccccc",
			PrivateID: "112233445566",
			AESKey:    hex.EncodeToString(make([]byte, 16)),
			Active:    true,
		}

		svc := createTestService(t, func(_ string) (*vaultstorage.Key, error) {
			return key, nil
		})

		for otpToken := range common.TestVectors {
			_, err := svc.DecryptOTP("cccccccccccc", otpToken)
			require.ErrorIs(t, err, common.ErrStorageDecryptFail)
			break
		}
	})

	t.Run("token decode failure", func(t *testing.T) {
		t.Parallel()

		svc := createTestService(t, func(_ string) (*vaultstorage.Key, error) {
			return &vaultstorage.Key{
				PublicID:  "cccccccccccc",
				PrivateID: hex.EncodeToString(make([]byte, 6)),
				AESKey:    hex.EncodeToString(make([]byte, 16)),
				Active:    true,
			}, nil
		})

		_, err := svc.DecryptOTP("cccccccccccc", "!!!!invalid_modhex!!!!")
		require.ErrorContains(t, err, "failed to decode token")
	})
}

func TestModule(t *testing.T) {
	t.Parallel()

	t.Run("module initialization", func(t *testing.T) {
		t.Parallel()

		require.NotNil(t, vaultstorage.Module)
		require.Len(t, vaultstorage.Module, 1, "must be exactly one module")
		require.NotNil(t, vaultstorage.Module[0].Constructor)
	})
}

func TestNewTestService(t *testing.T) {
	t.Parallel()

	t.Run("with custom getter", func(t *testing.T) {
		t.Parallel()

		svc, err := vaultstorage.NewTestService(
			zaptest.NewLogger(t),
			func(_ string) (*vaultstorage.Key, error) { return &vaultstorage.Key{}, nil },
		)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("with nil getter", func(t *testing.T) {
		t.Parallel()

		svc, err := vaultstorage.NewTestService(zaptest.NewLogger(t), nil)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})
}

func TestName(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, nil)
	require.Equal(t, "vault-keys-storage", svc.Name())
}

func TestStop(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, nil)
	require.NotPanics(t, func() {
		svc.Stop(t.Context())
	})
}

func TestDefaults(t *testing.T) {
	v := viper.New()
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "vault-path", Value: "secret/data/yubiserv"},
			&cli.StringFlag{Name: "vault-address", Value: "https://vault:8200"},
			&cli.StringFlag{Name: "vault-role-file", Value: "role_id"},
			&cli.StringFlag{Name: "vault-secret-file", Value: "secret_id"},
			&cli.StringFlag{Name: "vault-role-id", Value: ""},
			&cli.StringFlag{Name: "vault-secret-id", Value: ""},
			&cli.StringFlag{Name: "vault-login-timeout", Value: "10s"},
		},
		Action: func(c *cli.Context) error {
			require.NoError(t, vaultstorage.Defaults(c, v))

			require.Equal(t, "secret/data/yubiserv", v.GetString("vault.path"))
			require.Equal(t, "https://vault:8200", v.GetString("vault.address"))
			require.Equal(t, "role_id", v.GetString("vault.role_file"))
			require.Equal(t, "secret_id", v.GetString("vault.secret_file"))
			require.Empty(t, v.GetString("vault.role_id"))
			require.Empty(t, v.GetString("vault.secret_id"))
			require.Equal(t, "10s", v.GetString("vault.login_timeout"))

			return nil
		},
	}

	require.NoError(t, app.Run([]string{"test"}))
}

func TestNewServiceInit(t *testing.T) {
	t.Parallel()

	t.Run("service initialization", func(t *testing.T) {
		t.Parallel()

		v := viper.New()
		v.Set("vault.address", "https://127.0.0.1:8200")
		v.Set("vault.path", "secret/data/test")
		v.Set("vault.role_id", "test-role-id")
		v.Set("vault.secret_id", "test-secret-id")
		v.Set("vault.login_timeout", "5s")

		svc, err := vaultstorage.NewTestService(zaptest.NewLogger(t), nil)
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, "vault-keys-storage", svc.Name())
	})
}
