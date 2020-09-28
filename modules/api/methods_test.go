package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
	"go.uber.org/zap/zaptest"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testStorage struct {
}

func (s *testStorage) DecryptOTP(publicID, token string) (*common.OTP, error) {
	if publicID != "cccccccccccb" {
		return nil, common.ErrStorageNoKey
	}

	aesKey, err := hex.DecodeString("c4422890653076cde73d449b191b416a")
	if err != nil {
		return nil, err
	}

	binToken, err := hex.DecodeString(misc.Modhex2hex(token))
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

func TestVerify(t *testing.T) {

	var err error

	apikey, err := base64.StdEncoding.DecodeString("mG5be6ZJU1qBGz24yPh/ESM3UdU=")
	storage := &testStorage{}

	// Create test router
	svc := &Service{
		log:     zaptest.NewLogger(t),
		apiKey:  apikey,
		storage: storage,
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
			"h":     []string{"Fieq5toKf4ts%2BLp2nCdibXjeUDI%3D"},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}

		res, err := serve(svc.verify, req)
		if err != nil {
			t.Fatal(err)
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}

		// Assertions
		assert.Equal(t, http.StatusOK, res.StatusCode)

		values := map[string]string{}
		for _, s := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			v := strings.SplitN(s, "=", 2)
			if len(v) > 1 {
				values[v[0]] = v[1]
			} else {
				t.Fatalf("bad answer format: %s", s)
			}
		}
		assert.Contains(t, values, "status")
		assert.Equal(t, "OK", values["status"])
	})

}

// serve serves http request using provided fasthttp handler
func serve(handler fasthttp.RequestHandler, req *http.Request) (*http.Response, error) {
	ln := fasthttputil.NewInmemoryListener()
	defer func() {
		_ = ln.Close()
	}()

	go func() {
		err := fasthttp.Serve(ln, handler)
		if err != nil {
			panic(fmt.Errorf("failed to serve: %v", err))
		}
	}()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return ln.Dial()
			},
		},
	}

	return client.Do(req)
}
