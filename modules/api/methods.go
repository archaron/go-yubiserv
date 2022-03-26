package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/archaron/go-yubiserv/modules/api/templates"
)

func (s *Service) verify(ctx *fasthttp.RequestCtx) {
	var err error
	args := ctx.QueryArgs()
	extra := make(map[string]string)

	// Additional log params
	log := s.log.With(
		zap.String("action", "verify"),
		zap.Uint64("request_id", ctx.ID()),
	)

	// Check request user id
	id, err := args.GetUint("id")
	if err != nil || id < 1 {
		log.Error("field ID has wrong format", zap.Int("id", id), zap.Error(err))
		s.paramMissingResponse(ctx, extra)
		return
	}

	// Check request OTP field
	otp := string(args.Peek("otp"))

	// Ensure lowercase OTP
	otp = strings.ToLower(otp)

	// Check for Dvorak layout and fix it
	if misc.IsDvorakModhex(otp) {
		otp = misc.Dvorak2modhex(otp)
	}

	otpLen := len(otp)
	if otpLen < common.OTPMinLength || otpLen > common.OTPMaxLength || !misc.IsModhex(otp) {
		log.Error("field OTP is not a valid OTP", zap.String("otp", otp), zap.Int("otp_len", otpLen), zap.Error(err))
		s.paramMissingResponse(ctx, extra)
		return
	}

	// Check request Nonce field
	nonce := string(args.Peek("nonce"))
	nonceLen := len(nonce)

	if nonceLen < common.NonceMinLength || nonceLen > common.NonceMaxLength || !misc.IsAlphanum(nonce) {
		log.Error("field Nonce is not a valid nonce", zap.String("nonce", nonce), zap.Int("nonce_len", nonceLen), zap.Error(err))
		s.paramMissingResponse(ctx, extra)
		return
	}

	// If we have an apiKey to verify signature
	if len(s.apiKey) > 0 {
		// Check request H field
		h := string(args.Peek("h"))
		hLen := len(h)

		// If incoming client signature exists, check it
		if hLen > 0 {
			hmacSignature, err := base64.StdEncoding.DecodeString(h)
			if err != nil {
				log.Error("cannot decode base64 string in H field", zap.String("h", h), zap.Error(err))
				s.paramMissingResponse(ctx, extra)
				return
			}

			// Verify client HMAC
			var sm []string
			args.VisitAll(func(key, value []byte) {
				if !bytes.Equal(key, []byte{'h'}) { // Remove the request signature itself
					sm = append(sm, string(key)+"="+string(value))
				}
			})

			signature := common.SignMap(sm, s.apiKey)
			if !hmac.Equal(hmacSignature, signature) {
				log.Error("bad request HMAC signature detected, rejecting request", zap.Error(err))
				s.badSignatureResponse(ctx, extra)
				return
			}
		} else {
			log.Error("missing signature H field, but have api-secret specified, rejecting request", zap.Error(err))
			s.paramMissingResponse(ctx, extra)
			return
		}
	}

	// Ok, all checks done, let's try OTP verify
	matches := regexp.MustCompile(`(?m)^([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})$`).FindAllStringSubmatch(otp, -1)
	if len(matches) != 1 || len(matches[0]) != 3 {
		log.Error("invalid OTP format, cannot extract client ID and hash", zap.Error(err))
		s.badOTPResponse(ctx, extra)
		return
	}

	extra["otp"] = otp
	extra["nonce"] = nonce

	publicID := matches[0][1]

	log = log.With(zap.String("id", publicID))

	if s.storage == nil {
		log.Fatal("storage is nil")
	}

	otpData, err := s.storage.DecryptOTP(publicID, matches[0][2])
	if err != nil {
		log.Error("error decrypting OTP", zap.Error(err))
		s.badOTPResponse(ctx, extra)
		return
	}

	user, ok := s.Users[publicID]
	if !ok {
		s.Users[publicID] = &common.OTPUser{
			UsageCounter:   otpData.UsageCounter,
			SessionCounter: otpData.SessionCounter,
			Timestamp:      otpData.TimestampCounter,
		}
		log.Debug("add new OTP user")
	} else {
		log.Debug("existing OTP user", zap.Any("data", user))
		if (user.UsageCounter > otpData.UsageCounter) ||
			(user.UsageCounter == otpData.UsageCounter && user.SessionCounter >= otpData.SessionCounter) {
			log.Warn("saved counters >= OTP decoded counters, rejecting",
				zap.Uint8("saved_session_counter", user.SessionCounter),
				zap.Uint8("otp_session_counter", otpData.SessionCounter),

				zap.Uint16("saved_usage_counter", user.UsageCounter),
				zap.Uint16("otp_usage_counter", otpData.UsageCounter),
			)
			s.replayedOTPResponse(ctx, extra)
			return
		}
		// Save current counter
		user.UsageCounter = otpData.UsageCounter
		user.Timestamp = otpData.TimestampCounter
		user.SessionCounter = otpData.SessionCounter
	}

	log.Debug("otp decoded, access granted",
		zap.String("public_id", publicID),
		zap.String("otp", otpData.String()),
	)

	s.okResponse(ctx, extra)
}

func (s *Service) version(ctx *fasthttp.RequestCtx) {
	s.jsonResponse(ctx, 200, map[string]interface{}{
		"version":   s.settings.BuildVersion,
		"buildTime": s.settings.BuildTime,
		"status":    "ok",
	})
}

func (s *Service) health(ctx *fasthttp.RequestCtx) {
	s.jsonResponse(ctx, 200, map[string]interface{}{
		"status": "ok",
	})
}

func (s *Service) readiness(ctx *fasthttp.RequestCtx) {
	s.jsonResponse(ctx, 200, map[string]interface{}{
		"status": "ok",
	})
}

// TestResponseParams used for report test result.
type TestResponseParams struct {
	Result string
}

func (s *Service) test(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(200)
	ctx.SetContentType("text/html")

	params := TestResponseParams{}

	otp := string(ctx.QueryArgs().Peek("otp"))
	if len(otp) > 0 {
		requestID := fmt.Sprintf("%6d", time.Now().Unix())

		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			return
		}
		nonce := fmt.Sprintf("%x", b)[:32]

		data := []string{
			"id=" + requestID,
			"otp=" + otp,
			"nonce=" + nonce,
		}

		signature := common.SignMapToBase64(data, s.apiKey)

		q := url.Values{
			"id":    []string{requestID},
			"otp":   []string{otp},
			"nonce": []string{nonce},
			"h":     []string{signature},
		}

		req, err := http.NewRequest(http.MethodGet, "http://test/wsapi/2.0/verify/?"+q.Encode(), nil)
		if err != nil {
			s.log.Error("error creating test request", zap.Error(err))
			return
		}

		res, err := common.Serve(s.verify, req)
		if err != nil {
			s.log.Error("error serving test request", zap.Error(err))
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			s.log.Error("error reading response", zap.Error(err))
		}

		params.Result = string(body)
	}

	err := templates.IndexTemplate.Execute(ctx, params)
	if err != nil {
		s.log.Error("error executing test template", zap.Error(err))
	}
}
