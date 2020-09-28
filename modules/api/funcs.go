package api

import (
	"encoding/json"
	"fmt"
	"github.com/archaron/go-yubiserv/common"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"sort"
	"strings"
	"time"
)

func (s *Service) paramMissingResponse(ctx *fasthttp.RequestCtx, extra map[string]string) {
	if err := s.response(ctx, ResponseCodeMissingParameter, s.apiKey, extra); err != nil {
		s.log.Error("error sending param missing response", zap.Error(err))
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

	fields := map[string]string{
		"status": status,
		"t":      strings.ReplaceAll(time.Now().In(s.gmtLocation).Format("2006-01-02T15:04:05Z0.000"), ".", ""),
	}

	if extra != nil {
		for k := range extra {
			fields[k] = extra[k]
		}
	}

	// Ensure keys are alphabetical ordered
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}

	// Sort keys slice
	sort.Strings(keys)

	// Create ordered pieces
	var ordered []string
	for n := range keys {
		ordered = append(ordered, keys[n]+"="+fields[keys[n]])
	}

	// Add signatrure
	if apiKey != nil {
		ordered = append(ordered, "h="+common.SignMapToBase64(ordered, apiKey))
	}
	ctx.SetStatusCode(200)
	_, err := fmt.Fprint(ctx, strings.Join(ordered, "\n"))
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
