package api

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/im-kulikov/helium/settings"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
)

type testStorage struct{}

func (s *testStorage) DecryptOTP(publicID, token string) (*common.OTP, error) {
	if publicID != "cccccccccccb" {
		return nil, common.ErrStorageNoKey
	}

	aesKey, err := hex.DecodeString("c4422890653076cde73d449b191b416a")
	if err != nil {
		return nil, fmt.Errorf("cannot decode aes: %w", err)
	}

	binToken, err := hex.DecodeString(misc.ModHexToHex(token))
	if err != nil {
		return nil, fmt.Errorf("cannot decode token: %w", err)
	}

	otp := &common.OTP{}

	err = otp.Decrypt(aesKey, binToken)
	if err != nil {
		return nil, common.ErrStorageDecryptFail
	}

	return otp, nil
}

func Test_verify(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, &testStorage{})

	t.Run("should validate signed  OTP request", func(t *testing.T) { //nolint:paralleltest
		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "OK", values["status"])
	})

	t.Run("should error on repeated OTP request", func(t *testing.T) { //nolint:paralleltest
		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "REPLAYED_OTP", values["status"])
	})

	t.Run("should validate signed dvorak OTP request", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"otp":   []string{misc.ModHexToDvorak("cccccccccccbdbcuefnnfbtcnhujnbfrufectfdjgdlc")},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"JA5nlNpWZ11shZpBgVc81AF/v2c="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "OK", values["status"])
	})

	t.Run("should error on invalid h with apiKey set", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":     []string{"invalid"},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on not matching h with apiKey set", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDD="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "BAD_SIGNATURE", values["status"])
	})

	t.Run("should error on invalid OTP format", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnq"},
			"h":     []string{"OibQi9SioatWjUt6ytNf4Jy1KgU="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "BAD_OTP", values["status"])
	})

	t.Run("should error on decryption", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnn"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"WtW0HVlSTNsoa5Nijq2eWggqzsE="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "BAD_OTP", values["status"])
	})
}

func Test_verifyNnParams(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, &testStorage{})

	t.Run("should error on no id", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no otp", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no nonce", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":  []string{"2"},
			"otp": []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":   []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no h with apiKey set", func(t *testing.T) {
		t.Parallel()

		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})
}

func Test_test(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, &testStorage{})

	t.Run("should validate signed  OTP request", func(t *testing.T) {
		t.Parallel()

		body := simpleRequest(t, svc.testHandler, url.Values{
			"otp": []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
		})

		require.Contains(t, body, "OTP Test page")
		require.Contains(t, body, "status=OK")
	})
}

func Test_ops(t *testing.T) {
	t.Parallel()

	svc := createTestService(t, &testStorage{})

	t.Run("should return version", func(t *testing.T) {
		t.Parallel()

		require.JSONEq(t,
			"{\"buildTime\":\"0123456789\",\"status\":\"ok\",\"version\":\"6660999\"}\n",
			simpleRequest(t, svc.version),
		)
	})

	t.Run("should return health", func(t *testing.T) {
		t.Parallel()

		require.JSONEq(t,
			"{\"status\":\"ok\"}\n",
			simpleRequest(t, svc.health),
		)
	})

	t.Run("should return ready", func(t *testing.T) {
		t.Parallel()

		require.JSONEq(t,
			"{\"status\":\"ok\"}\n",
			simpleRequest(t, svc.readiness),
		)
	})
}

func simpleRequest(t *testing.T, handler http.HandlerFunc, args ...url.Values) string {
	t.Helper()

	q := make(url.Values)

	for arg := range args {
		for k, v := range args[arg] {
			q[k] = append(q[k], v...)
		}
	}

	rec := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "http://test/?"+q.Encode(), nil)

	handler(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	return rec.Body.String()
}

func decodeAnswer(t *testing.T, body string) map[string]string {
	t.Helper()

	values := map[string]string{}

	for _, s := range strings.Split(strings.TrimSpace(body), "\n") {
		v := strings.SplitN(s, "=", 2)
		if len(v) > 1 {
			values[v[0]] = v[1]
		} else {
			t.Fatalf("bad answer format: %s", s)
		}
	}

	return values
}

func createTestService(t *testing.T, storage common.StorageInterface) *Service {
	t.Helper()

	apiKey, err := base64.StdEncoding.DecodeString("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
	require.NoError(t, err)

	svc := &Service{
		log:   zaptest.NewLogger(t),
		Users: map[string]*common.OTPUser{},
		settings: &settings.Core{
			BuildTime:    "0123456789",
			BuildVersion: "6660999",
		},
		storage: storage,
		apiKey:  apiKey,
	}

	svc.gmtLocation, err = time.LoadLocation("GMT")
	require.NoError(t, err)

	return svc
}

func decodedRequest(t *testing.T, q url.Values, handler http.HandlerFunc) map[string]string {
	t.Helper()

	values := decodeAnswer(t, simpleRequest(t, handler, q))
	require.Contains(t, values, "status")

	return values
}
