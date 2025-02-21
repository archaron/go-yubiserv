package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/archaron/go-yubiserv/common"
)

func (s *Service) responseW(w http.ResponseWriter, status string, apiKey []byte, extra map[string]string) error {
	// Create ordered pieces
	ordered := make([]string, 0)

	ordered = append(ordered, "t="+strings.ReplaceAll(time.Now().In(s.gmtLocation).Format("2006-01-02T15:04:05Z0.000"), ".", ""))

	for n := range extra {
		ordered = append(ordered, n+"="+extra[n])
	}

	ordered = append(ordered, "status="+status)
	if apiKey != nil {
		ordered = append([]string{"h=" + common.SignMapToBase64(ordered, apiKey)}, ordered...) // Add signature
	}

	_, err := fmt.Fprint(w, strings.Join(ordered, "\r\n")+"\r\n")
	if err != nil {
		return fmt.Errorf("error writing response: %w", err)
	}

	return nil
}
