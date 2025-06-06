package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Oudwins/zog"
	"github.com/Oudwins/zog/internals"
	"github.com/Oudwins/zog/zhttp"
	"github.com/go-chi/render"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/archaron/go-yubiserv/modules/api/templates"
)

type verifyReq struct {
	ID        string `query:"id"`
	OTP       string `query:"otp"`
	Nonce     string `query:"nonce"`
	Signature string `query:"h"`
}

//nolint:forcetypeassert
func newVerifyRequestSchema(args url.Values, key []byte) *zog.StructSchema {
	return zog.Struct(zog.Shape{
		"ID": zog.String().
			Trim().
			Required(zog.Message(ResponseCodeMissingParameter)).
			Min(1, zog.Message(ResponseCodeMissingParameter)),
		"OTP": zog.String().
			Trim().
			Required(zog.Message(ResponseCodeMissingParameter)).
			Len(common.OTPMaxLength, zog.Message(ResponseCodeMissingParameter)).
			Transform(
				func(valPtr *string, _ internals.Ctx) error {
					if valPtr == nil {
						return errors.New(ResponseCodeMissingParameter)
					}

					otp := *valPtr

					// Ensure lowercase OTP
					otp = strings.ToLower(otp)

					// Check for Dvorak layout and fix it
					if misc.IsDvorakModHex(otp) {
						otp = misc.DvorakToModHex(otp)
					}

					*valPtr = otp
					return nil
				},
			),
		"Nonce": zog.String().
			Required(zog.Message(ResponseCodeMissingParameter)).
			Min(common.NonceMinLength, zog.Message(ResponseCodeMissingParameter)).
			Max(common.NonceMaxLength, zog.Message(ResponseCodeMissingParameter)).
			Match(regexp.MustCompile(`(?m)^[a-zA-Z0-9]+$`), zog.Message(ResponseCodeMissingParameter)),
		"Signature": zog.String().
			Trim().
			Required(zog.Message(ResponseCodeMissingParameter), func(test internals.TestInterface) {
				if len(key) == 0 {
					test = &internals.Test[string]{}
				}
			}).
			Test(zog.TestFunc[*string]("signature", func(val *string, ctx internals.Ctx) bool {
				if len(key) == 0 {
					return true
				}

				if val == nil || *val == "" {
					ctx.AddIssue(&internals.ZogIssue{Message: ResponseCodeMissingParameter, Path: "signature"})

					return false
				}

				hmacSignature, err := base64.StdEncoding.DecodeString(*val)
				if err != nil {
					ctx.AddIssue(&internals.ZogIssue{
						Message: ResponseCodeMissingParameter,
						Path:    "signature",
						Err:     fmt.Errorf("base64 decoding failed: %w, input=%q", err, *val),
					})

					return false
				}

				var data []string
				for k := range args {
					if k == "h" {
						continue
					}
					data = append(data, k+"="+args.Get(k))
				}

				sort.Strings(data)

				if signature := common.SignMap(data, key); !hmac.Equal(hmacSignature, signature) {
					ctx.AddIssue(&internals.ZogIssue{
						Message: ResponseCodeBadSignature,
						Path:    "signature",
					})

					return false
				}

				return true
			})),
	})
}

func (s *Service) verifyHandler(w http.ResponseWriter, r *http.Request) {
	log := s.log.With(zap.String("method", "verify"))

	var req verifyReq

	extra := make(map[string]string)

	schema := newVerifyRequestSchema(r.URL.Query(), s.apiKey)

	errs := schema.Parse(zhttp.Request(r), &req)

	if len(errs) != 0 {
		for _, iv := range errs["$first"] {
			if message := iv.Message; message != "" {
				if errResp := s.responseW(w, message, s.apiKey, extra); errResp != nil {
					log.Error("error sending backend error response", zap.Error(errResp))
				}

				log.Debug("message", zap.String("field", iv.Path), zap.Error(iv))
				return
			}

		}

	}

	// Ok, all checks done, let's try OTP verify
	matches := regexp.MustCompile(fmt.Sprintf("(?m)^([cbdefghijklnrtuv]{%d})([cbdefghijklnrtuv]{%d})$",
		common.PublicIDLength,
		common.TokenLength,
	)).FindAllStringSubmatch(req.OTP, -1)

	if len(matches) != 1 || len(matches[0]) != 3 {
		log.Error("invalid OTP format, cannot extract client ID and hash", zap.String("otp", req.OTP))

		if err := s.responseW(w, ResponseCodeBadOTP, s.apiKey, extra); err != nil {
			log.Error("could not send response", zap.Error(err))
		}

		return
	}

	extra["otp"] = req.OTP
	extra["nonce"] = req.Nonce

	publicID := matches[0][1]

	log = log.With(zap.String("id", publicID))

	otpData, err := s.storage.DecryptOTP(publicID, matches[0][2])
	if err != nil {
		log.Error("error decrypting OTP", zap.Error(err))

		if errors.Is(err, common.ErrStorageNoKey) {

			if err = s.responseW(w, ResponseCodeNoSuchClient, s.apiKey, extra); err != nil {
				log.Error("could not send response", zap.Error(err))
			}

			return
		}

		if err = s.responseW(w, ResponseCodeBadOTP, s.apiKey, extra); err != nil {
			log.Error("could not send response", zap.Error(err))
		}

		return
	}

	if user, ok := s.Users[publicID]; !ok {
		// If no user found in memory storage, create one
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

			if err = s.responseW(w, ResponseCodeReplayedOTP, s.apiKey, extra); err != nil {
				log.Error("could not send response", zap.Error(err))
			}

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

	if err = s.responseW(w, ResponseCodeOK, s.apiKey, extra); err != nil {
		log.Error("could not send response", zap.Error(err))
	}

}

func (s *Service) version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]interface{}{
		"version":   s.settings.BuildVersion,
		"buildTime": s.settings.BuildTime,
		"status":    "ok",
	})
}

func (s *Service) health(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]interface{}{
		"status": "ok",
	})
}

func (s *Service) readiness(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, map[string]interface{}{
		"status": "ok",
	})
}

// TestResponseParams used for a report test result.
type TestResponseParams struct {
	Result string
}

func (s *Service) testHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err error
		out string
	)

	render.Status(r, http.StatusOK)

	if out, err = s.testVerifyRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	buf := new(bytes.Buffer)
	if err = templates.IndexTemplate().Execute(buf, &TestResponseParams{Result: out}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	render.HTML(w, r, buf.String())
}

func (s *Service) testVerifyRequest(r *http.Request) (string, error) {
	otp := r.URL.Query().Get("otp")

	if otp == "" {
		return "", nil
	}

	buf := make([]byte, common.NonceMinLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}

	data := []string{
		"id=" + strconv.FormatInt(time.Now().Unix(), 10),
		"otp=" + otp,
		"nonce=" + hex.EncodeToString(buf),
	}

	sign := common.SignMapToBase64(data, s.apiKey)
	data = append(data, "h="+url.QueryEscape(sign))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?"+strings.Join(data, "&"), nil)
	s.verifyHandler(rec, req)

	return rec.Body.String(), nil
}
