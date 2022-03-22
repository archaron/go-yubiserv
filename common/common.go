package common

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
	"net"
	"net/http"
	"sort"
	"strings"
)

/** SignMap - signs specified strings slice with given apiKey
@return []byte Raw HMAC signature
*/
func SignMap(m []string, apiKey []byte) []byte {
	mc := make([]string, len(m))
	copy(mc, m)
	sort.Strings(mc)
	payload := strings.Join(mc, "&")
	h := hmac.New(sha1.New, apiKey)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

/** SignMapToBase64 - signs specified strings slice with given apiKey
@return []byte Base64-encoded HMAC signature
*/
func SignMapToBase64(m []string, apiKey []byte) string {
	return base64.StdEncoding.EncodeToString(SignMap(m, apiKey))
}

// Serve serves http request using provided fasthttp handler
func Serve(handler fasthttp.RequestHandler, req *http.Request) (*http.Response, error) {
	ln := fasthttputil.NewInmemoryListener()
	defer func() {
		_ = ln.Close()
	}()

	go func() {
		err := fasthttp.Serve(ln, handler)
		if err != nil {
			panic(fmt.Errorf("failed to Serve: %v", err))
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
