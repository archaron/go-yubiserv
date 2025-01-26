package api

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
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
		return nil, err
	}

	binToken, err := hex.DecodeString(misc.ModHexToHex(token))
	if err != nil {
		return nil, err
	}

	otp := &common.OTP{}
	err = otp.Decrypt(aesKey, binToken)
	if err != nil {
		return nil, common.ErrStorageDecryptFail
	}

	return otp, err
}

func Test_verify(t *testing.T) {
	apikey, err := base64.StdEncoding.DecodeString("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
	storage := &testStorage{}

	// Create test router
	svc := &Service{
		log:     zaptest.NewLogger(t),
		apiKey:  apikey,
		storage: storage,
		Users:   map[string]*common.OTPUser{},
	}

	svc.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should validate signed  OTP request", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "OK", values["status"])
	})

	t.Run("should error on repeated OTP request", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "REPLAYED_OTP", values["status"])
	})

	t.Run("should validate signed dvorak OTP request", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"otp":   []string{misc.ModHexToDvorak("cccccccccccbdbcuefnnfbtcnhujnbfrufectfdjgdlc")},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"JA5nlNpWZ11shZpBgVc81AF/v2c="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "OK", values["status"])
	})

	t.Run("should error on no id", func(t *testing.T) {
		q := url.Values{
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no otp", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no nonce", func(t *testing.T) {
		q := url.Values{
			"id":  []string{"2"},
			"otp": []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":   []string{"Fieq5toKf4ts+Lp2nCdibXjeUDI="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no h with apiKey set", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on invalid h with apiKey set", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":     []string{"invalid"},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on not matching h with apiKey set", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":     []string{"Fieq5toKf4ts+Lp2nCdibXjeUDD="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "BAD_SIGNATURE", values["status"])
	})

	t.Run("should error on invalid OTP format", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"otp":   []string{"ccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":     []string{"DfNzPo8GWR498s3VrnI4bvfzLws="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "BAD_OTP", values["status"])
	})

	t.Run("should error on nil storage", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/", nil)
		require.NoError(t, err)
		svc.storage = nil
		res, err := common.Serve(svc.verify, req)
		svc.storage = storage
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "BACKEND_ERROR", values["status"])
	})

	t.Run("should error on decryption", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"1"},
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnn"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"WtW0HVlSTNsoa5Nijq2eWggqzsE="},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.verify, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		values := decodeAnswer(t, body)
		require.Contains(t, values, "status")
		require.Equal(t, "BAD_OTP", values["status"])
	})
}

func Test_test(t *testing.T) {
	apikey, err := base64.StdEncoding.DecodeString("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
	storage := &testStorage{}

	// Create test router
	svc := &Service{
		log:     zaptest.NewLogger(t),
		apiKey:  apikey,
		storage: storage,
		Users:   map[string]*common.OTPUser{},
	}

	svc.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should validate signed  OTP request", func(t *testing.T) {
		q := url.Values{
			"otp": []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/test/?"+q.Encode(), nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.test, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, http.StatusOK, res.StatusCode)

		require.Contains(t, string(body), "OTP Test page")
		require.Contains(t, string(body), "status=OK")
	})
}

func decodeAnswer(t *testing.T, body []byte) map[string]string {
	values := map[string]string{}
	for _, s := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		v := strings.SplitN(s, "=", 2)
		if len(v) > 1 {
			values[v[0]] = v[1]
		} else {
			t.Fatalf("bad answer format: %s", s)
		}
	}
	return values
}

func Test_ops(t *testing.T) {
	// Create test router
	svc := &Service{
		log:   zaptest.NewLogger(t),
		Users: map[string]*common.OTPUser{},
		settings: &settings.Core{
			BuildTime:    "0123456789",
			BuildVersion: "6660999",
		},
	}

	t.Run("should return version", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://test/version", nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.version, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)
		fmt.Println(string(body))
		// Assertions
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "{\"buildTime\":\"0123456789\",\"status\":\"ok\",\"version\":\"6660999\"}\n", string(body))
	})

	t.Run("should return health", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://test/health", nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.health, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)
		fmt.Println(string(body))
		// Assertions
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "{\"status\":\"ok\"}\n", string(body))
	})

	t.Run("should return ready", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://test/rediness", nil)
		require.NoError(t, err)

		res, err := common.Serve(svc.readiness, req)
		require.NoError(t, err)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)
		fmt.Println(string(body))
		// Assertions
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "{\"status\":\"ok\"}\n", string(body))
	})
}
