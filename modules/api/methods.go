package api

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"net/url"
	"regexp"
	"strings"
)

func (s *Service) verify(ctx *fasthttp.RequestCtx) {

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

	extra["nonce"] = nonce

	// If we have an apiKey to verify signature
	if len(s.apiKey) > 0 {

		// Check request H field
		h := string(args.Peek("h"))
		hLen := len(h)

		// If incoming client signature exists, check it
		if hLen > 0 {

			h, err = url.QueryUnescape(h)
			if err != nil {
				log.Error("cannot unescape query string in H field", zap.String("h", h), zap.Error(err))
				s.paramMissingResponse(ctx, extra)
				return
			}

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
			log.Debug("HMAC signature", zap.String("signature", common.SignMapToBase64(sm, s.apiKey)))
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

	if s.storage == nil {
		s.log.Fatal("storage is nil")
	}

	otpData, err := s.storage.DecryptOTP(matches[0][1], matches[0][2])
	if err != nil {
		log.Error("error decrypting OTP", zap.Error(err))
		s.badOTPResponse(ctx, extra)
		return
	}

	log.Debug("otp decoded, access granted",
		zap.String("public_id", matches[0][1]),
		zap.String("otp", otpData.String()),
	)

	// TODO: Check usage counters & etc here!
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
