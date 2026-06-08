package api //nolint:testpackage

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

	"github.com/Oudwins/zog/zhttp"
	"github.com/im-kulikov/helium/settings"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
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
func Test_verifyNnParams(t *testing.T) { //nolint:tparallel
	t.Parallel()

	svc := createTestService(t, &testStorage{})

	t.Run("should error on no id", func(t *testing.T) {
		q := url.Values{
			"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"ccSijO7Ft09W9e9wu3dXbhFfzyE="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no otp", func(t *testing.T) {
		q := url.Values{
			"id":    []string{"2"},
			"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
			"h":     []string{"Ht1cdOM6H/9PdTG202AYgqJT3mk="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no nonce", func(t *testing.T) {
		q := url.Values{
			"id":  []string{"2"},
			"otp": []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
			"h":   []string{"7PO00ewTSry/sCdMqX9lLMcvoVo="},
		}

		values := decodedRequest(t, q, svc.verifyHandler)
		require.Equal(t, "MISSING_PARAMETER", values["status"])
	})

	t.Run("should error on no h with apiKey set", func(t *testing.T) {
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

	for s := range strings.SplitSeq(strings.TrimSpace(body), "\n") {
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

func Test_makeAPIKey(t *testing.T) {
	t.Parallel()

	t.Run("empty secret", func(t *testing.T) {
		t.Parallel()

		key, err := makeAPIKey("")
		require.NoError(t, err)
		require.Nil(t, key)
	})

	t.Run("valid base64", func(t *testing.T) {
		t.Parallel()

		key, err := makeAPIKey("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
		require.NoError(t, err)
		require.NotNil(t, key)
		require.Len(t, key, 20)
	})

	t.Run("invalid base64", func(t *testing.T) {
		t.Parallel()

		_, err := makeAPIKey("!!!not-base64!!!")
		require.ErrorContains(t, err, "failed to decode api key")
	})
}

func Test_Defaults(t *testing.T) {
	v := viper.New()
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api-address", Value: ":8443"},
			&cli.StringFlag{Name: "api-timeout", Value: "2s"},
			&cli.StringFlag{Name: "api-secret", Value: "test-secret"},
			&cli.StringFlag{Name: "api-tls-cert", Value: ""},
			&cli.StringFlag{Name: "api-tls-key", Value: ""},
		},
		Action: func(c *cli.Context) error {
			require.NoError(t, Defaults(c, v))

			require.Equal(t, ":8443", v.GetString("api.address"))
			require.Equal(t, "2s", v.GetString("api.timeout"))
			require.Equal(t, "test-secret", v.GetString("api.secret"))
			require.Empty(t, v.GetString("api.tls_cert"))
			require.Empty(t, v.GetString("api.tls_key"))

			return nil
		},
	}

	require.NoError(t, app.Run([]string{"test"}))
}

func Test_Defaults_TLS(t *testing.T) {
	v := viper.New()
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api-address", Value: ":8443"},
			&cli.StringFlag{Name: "api-timeout", Value: "1s"},
			&cli.StringFlag{Name: "api-secret", Value: ""},
			&cli.StringFlag{Name: "api-tls-cert", Value: "/path/cert.pem"},
			&cli.StringFlag{Name: "api-tls-key", Value: "/path/key.pem"},
		},
		Action: func(c *cli.Context) error {
			require.NoError(t, Defaults(c, v))

			require.Equal(t, "/path/cert.pem", v.GetString("api.tls_cert"))
			require.Equal(t, "/path/key.pem", v.GetString("api.tls_key"))

			return nil
		},
	}

	require.NoError(t, app.Run([]string{"test"}))
}

func Test_Defaults_TLS_MissingKey(t *testing.T) {
	v := viper.New()
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api-address", Value: ":8443"},
			&cli.StringFlag{Name: "api-timeout", Value: "1s"},
			&cli.StringFlag{Name: "api-secret", Value: ""},
			&cli.StringFlag{Name: "api-tls-cert", Value: "/path/cert.pem"},
			&cli.StringFlag{Name: "api-tls-key", Value: ""},
		},
		Action: func(c *cli.Context) error {
			require.ErrorIs(t, Defaults(c, v), ErrTLSParams)
			return nil
		},
	}

	require.NoError(t, app.Run([]string{"test"}))
}

func Test_Name(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	require.Equal(t, "api", svc.Name())
}

func Test_Stop(t *testing.T) {
	t.Parallel()

	svc := &Service{
		started: make(chan struct{}),
		cancel:  func() {},
	}
	close(svc.started)
	require.NotPanics(t, func() {
		svc.Stop(t.Context())
	})
}

func Test_newRouter(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	handler := svc.newRouter()
	require.NotNil(t, handler)
}

func Test_Printf(t *testing.T) {
	t.Parallel()

	t.Run("debug disabled", func(t *testing.T) {
		t.Parallel()

		misc.Debug = false //nolint:reassign
		svc := createTestService(t, &testStorage{})
		require.NotPanics(t, func() {
			svc.Printf("test message %s", "arg")
		})
	})

	t.Run("debug enabled", func(t *testing.T) {
		misc.Debug = true                        //nolint:reassign
		t.Cleanup(func() { misc.Debug = false }) //nolint:reassign

		svc := createTestService(t, &testStorage{})
		require.NotPanics(t, func() {
			svc.Printf("test message %s", "arg")
		})
	})
}

func Test_newVerifyRequestSchema_emptyKey(t *testing.T) {
	t.Parallel()

	schema := newVerifyRequestSchema(url.Values{}, nil)
	require.NotNil(t, schema)

	q := url.Values{
		"id":    []string{"1"},
		"otp":   []string{"cccccccccccbiucvrkjiegbhidrcicvlgrcgkgurhjnj"},
		"nonce": []string{"jrFwbaYFhn0HoxZIsd9LQ6w2ceU"},
	}

	var req verifyReq
	errs := schema.Parse(zhttp.Request(httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil)), &req)
	require.Empty(t, errs)
	require.Equal(t, "1", req.ID)
	require.Empty(t, req.Signature)
}
