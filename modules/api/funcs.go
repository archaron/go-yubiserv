package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
)

func (s *Service) paramMissingResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeMissingParameter, s.apiKey, extra); err != nil {
		s.log.Error("error sending param missing response", zap.Error(err))
	}
}

func (s *Service) replayedOTPResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeReplayedOTP, s.apiKey, extra); err != nil {
		s.log.Error("error sending replayed OTP response", zap.Error(err))
	}
}

func (s *Service) badOTPResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeBadOTP, s.apiKey, extra); err != nil {
		s.log.Error("error sending bad OTP response", zap.Error(err))
	}
}

func (s *Service) badSignatureResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeBadSignature, s.apiKey, extra); err != nil {
		s.log.Error("error sending bad signature response", zap.Error(err))
	}
}

func (s *Service) okResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeOK, s.apiKey, extra); err != nil {
		s.log.Error("error sending OK response", zap.Error(err))
	}
}

func (s *Service) response(ctx *fasthttp.RequestCtx, status string, apiKey []byte, extra map[string]string) error {
	// Create ordered pieces
	ordered := make([]string, 0, 5)

	ordered = append(ordered, "t="+strings.ReplaceAll(time.Now().In(s.gmtLocation).Format("2006-01-02T15:04:05Z0.000"), ".", ""))

	if extra != nil {
		for n := range extra {
			ordered = append(ordered, n+"="+extra[n])
		}
	}

	ordered = append(ordered, "status="+status)
	if apiKey != nil {
		ordered = append([]string{"h=" + common.SignMapToBase64(ordered, apiKey)}, ordered...) // Add signature
	}

	ctx.SetStatusCode(200)
	_, err := fmt.Fprint(ctx, strings.Join(ordered, "\r\n")+"\r\n")
	return err
}

func (s *Service) jsonResponse(ctx *fasthttp.RequestCtx, statusCode int, payload map[string]interface{}) {
	// Set JSON content-type
	ctx.SetContentType("application/json; charset=utf8")
	ctx.Response.SetStatusCode(statusCode)

	// Encode results
	if err := json.NewEncoder(ctx).Encode(payload); err != nil {
		s.log.Error("error marshalling json", zap.Any("payload", payload), zap.Error(err))
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	}
}
