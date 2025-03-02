// Package api implements web API
package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"

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

		server  *http.Server
		started chan struct{}

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

// Start API service.
func (s *Service) Start(parentCtx context.Context) error {
	var (
		ctx context.Context
		err error
	)

	ctx, s.cancel = context.WithCancel(parentCtx)

	s.server = &http.Server{
		Addr:              s.address,
		Handler:           s.newRouter(),
		ReadTimeout:       s.timeout,
		ReadHeaderTimeout: s.timeout,
		WriteTimeout:      s.timeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	s.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		return fmt.Errorf("failed to load GMT: %w", err)
	}

	var ok bool

	// Notify systemd
	if ok, err = daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		s.log.Warn("error sending systemd ready notify", zap.Error(err))
	}

	s.log.Debug("systemd notify", zap.Bool("detected", ok))

	run, _ := errgroup.WithContext(ctx)
	run.Go(s.Watchdog(ctx))
	run.Go(s.serve)
	run.Go(func() error {
		close(s.started)

		return nil
	})

	return errors.Wrap(run.Wait(), "api start")
}

func (s *Service) serve() error {
	if s.cert != "" && s.key != "" {
		s.log.Info("listen in secured TLS HTTPS mode", zap.String("address", s.address))

		return errors.Wrap(s.server.ListenAndServeTLS(s.cert, s.key), "https serve")
	}

	s.log.Info("listen in unsecured HTTP mode", zap.String("address", s.address))

	return errors.Wrap(s.server.ListenAndServe(), "http serve")
}

// Stop API service.
func (s *Service) Stop(ctx context.Context) {
	defer s.cancel()

	select {
	case <-ctx.Done():
		return
	case <-s.started:
	}

	// Notify systemd app is stopping
	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		s.log.Info("error sending systemd ready notify")
	}

	if s.server != nil {
		s.log.Info("shutting down server", zap.Error(s.server.Shutdown(ctx)))
	}
}

// Name of the API service.
func (s *Service) Name() string {
	return "api"
}

// Watchdog for systemd keepalive responses.
func (s *Service) Watchdog(ctx context.Context) func() error {
	return func() error {

		interval, err := daemon.SdWatchdogEnabled(false)
		if err != nil {
			return fmt.Errorf("unable to enable watchdog: %w", err)
		}

		if interval == 0 {
			s.log.Debug("not running as service, watchdog disabled")

			return nil
		}

		interval /= 2
		s.log.Info("systemd watchdog start", zap.Duration("interval", interval))

		timer := time.NewTimer(interval)

		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():

				return errors.Wrap(context.Cause(ctx), "watchdog")
			case <-timer.C:

				_, err = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
				if err != nil {
					s.log.Info("error sending systemd alive notify", zap.Error(err))
				}

				timer.Reset(interval)
			}
		}
	}
}
