package api

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/im-kulikov/helium/settings"
	"github.com/spf13/viper"
	"github.com/valyala/fasthttp"
	"go.uber.org/dig"
	"go.uber.org/zap"

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
		log         *zap.Logger
		address     string
		listener    *fasthttp.Server
		settings    *settings.Core
		gmtLocation *time.Location
		storage     common.StorageInterface

		ctx    context.Context
		cancel context.CancelFunc

		apiKey  []byte
		timeout time.Duration
		cert    string
		key     string

		Users common.OTPUsers
	}
)

// Printf function for HTTP debug log.
func (s *Service) Printf(format string, args ...interface{}) {
	if misc.Debug {
		s.log.Warn(fmt.Sprintf(format, args...))
	}
}

// Start API service.
func (s *Service) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	var err error
	s.listener = &fasthttp.Server{
		Handler:      s.requestHandler,
		ReadTimeout:  s.timeout,
		WriteTimeout: s.timeout,
		Logger:       s,
	}

	s.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		return err
	}

	if s.cert != "" && s.key != "" {
		s.log.Debug("listen in secured TLS mode", zap.String("address", s.address))
		go func() {
			if err = s.listener.ListenAndServeTLS(s.address, s.cert, s.key); err != nil {
				s.log.Fatal("api tls listen error", zap.Error(err))
			}
		}()
	} else {
		s.log.Debug("listen in unsecured HTTP mode", zap.String("address", s.address))
		go func() {
			if err = s.listener.ListenAndServe(s.address); err != nil {
				s.log.Fatal("api listen error", zap.Error(err))
			}
		}()
	}

	// Notify systemd
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		s.log.Info("error sending systemd ready notify")
	}

	s.Watchdog(s.ctx)

	<-s.ctx.Done()
	return s.ctx.Err()
}

// Stop API service.
func (s *Service) Stop(ctx context.Context) {
	defer s.cancel()
	// Notify systemd app is stopping
	if _, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		s.log.Info("error sending systemd ready notify")
	}

	if s.listener != nil {
		s.log.Info("api.stop")
		_ = s.listener.Shutdown()
	}
}

// Name of the API service.
func (s *Service) Name() string {
	return "api"
}

func (s *Service) requestHandler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/wsapi/2.0/verify":
		s.verify(ctx)
		return

	case "/version":
		s.version(ctx)
		return
	case "/rediness":
		// Perform state checks, and report readiness status
		s.readiness(ctx)

	case "/health":
		// Service health check
		s.health(ctx)

	case "/":
		s.test(ctx)
	default:
		ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		return
	}
}

// Watchdog for systemd keepalive responses.
func (s *Service) Watchdog(ctx context.Context) {
	go func(ctx context.Context) {
		interval, err := daemon.SdWatchdogEnabled(false)
		if err != nil || interval == 0 {
			return
		}

		interval /= 2
		s.log.Debug("watchdog start", zap.Duration("interval", interval))

		timer := time.NewTimer(interval)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
					s.log.Info("error sending systemd alive notify")
				}

				timer.Reset(interval)
			}
		}
	}(ctx)
}
