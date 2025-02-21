// Package api implements web API
package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/go-chi/chi/v5"

	"github.com/im-kulikov/helium/settings"
	"github.com/spf13/viper"
	"go.uber.org/dig"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/archaron/go-yubiserv/common"
	"github.com/archaron/go-yubiserv/misc"
)

type (
	serviceParams struct {
		dig.In

		Logger   *zap.Logger
		Config   *viper.Viper
		Settings *settings.Core
		Storage  common.StorageInterface
	}

	// Service represents API service.
	Service struct {
		log     *zap.Logger
		address string

		server *http.Server

		settings    *settings.Core
		gmtLocation *time.Location
		storage     common.StorageInterface

		cancel context.CancelFunc

		apiKey  []byte
		timeout time.Duration
		cert    string
		key     string

		Users common.OTPUsers
	}
)

func (s *Service) newRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/version", s.version)
	r.Get("/health", s.health)
	r.Get("/readiness", s.readiness)

	r.Get("/wsapi/2.0/verify", s.verifyHandler)
	r.Get("/", s.testHandler)

	return r
}

func makeAPIKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}

	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode api key: %w", err)
	}

	return key, nil
}

// Printf function for HTTP debug log.
func (s *Service) Printf(format string, args ...interface{}) {
	if misc.Debug {
		s.log.Warn(fmt.Sprintf(format, args...))
	}
}

func loadTLSConfig(cert, key string) (*tls.Config, error) {
	if cert == "" && key == "" {
		return nil, nil //nolint:nilnil
	}

	cer, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate(cert:%q, key:%q): %w", cert, key, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Start API service.
func (s *Service) Start(parentCtx context.Context) error {
	var ctx context.Context

	ctx, s.cancel = context.WithCancel(parentCtx)

	tlsConfig, err := loadTLSConfig(s.cert, s.key)
	if err != nil {
		return fmt.Errorf("failed to prepare TLS config: %w", err)
	}

	s.server = &http.Server{
		Addr:              s.address,
		Handler:           s.newRouter(),
		TLSConfig:         tlsConfig,
		ReadTimeout:       s.timeout,
		ReadHeaderTimeout: s.timeout,
		WriteTimeout:      s.timeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	s.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		return fmt.Errorf("failed to load GMT: %w", err)
	}

	// Notify systemd
	if _, err = daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		s.log.Info("error sending systemd ready notify")
	}

	run, _ := errgroup.WithContext(ctx)
	run.Go(s.Watchdog(ctx))

	if tlsConfig != nil {
		s.log.Info("listen in secured TLS HTTPS mode", zap.String("address", s.address))
		run.Go(func() error {
			return s.server.ListenAndServeTLS("", "")
		})
	} else {
		s.log.Info("listen in unsecured HTTP mode", zap.String("address", s.address))
		run.Go(s.server.ListenAndServe)
	}

	err = run.Wait()
	if err != nil {
		return fmt.Errorf("unable to wait for all listeners: %w", err)
	}

	return nil
}

// Stop API service.
func (s *Service) Stop(ctx context.Context) {
	s.cancel()

	// Notify systemd app is stopping
	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		s.log.Info("error sending systemd ready notify")
	}

	if s.server == nil {
		return
	}

	s.log.Info("api.stop", zap.Error(s.server.Shutdown(ctx)))
}

// Name of the API service.
func (s *Service) Name() string {
	return "api"
}

// Watchdog for systemd keepalive responses.
func (s *Service) Watchdog(ctx context.Context) func() error {
	return func() error {
		interval, err := daemon.SdWatchdogEnabled(false)
		if err != nil || interval == 0 {
			return fmt.Errorf("unable to enable watchdog: %w", err)
		}

		interval /= 2
		s.log.Debug("watchdog start", zap.Duration("interval", interval))

		timer := time.NewTimer(interval)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
				if _, err = daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
					s.log.Info("error sending systemd alive notify")
				}

				timer.Reset(interval)
			}
		}
	}
}
