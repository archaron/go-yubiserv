package api

import (
	"context"
	"fmt"
	"github.com/archaron/go-yubiserv/common"
	"github.com/im-kulikov/helium/settings"
	"github.com/spf13/viper"
	"github.com/valyala/fasthttp"
	"go.uber.org/dig"
	"go.uber.org/zap"
	"time"
)

type (
	serviceParams struct {
		dig.In

		Logger   *zap.Logger
		Config   *viper.Viper
		Settings *settings.Core
		Storage  common.StorageInterface
	}

	Service struct {
		log         *zap.Logger
		address     string
		listener    *fasthttp.Server
		settings    *settings.Core
		gmtLocation *time.Location
		storage     common.StorageInterface

		apiKey  []byte
		timeout time.Duration
		cert    string
		key     string
	}
)

func (s *Service) Printf(format string, args ...interface{}) {
	s.log.Warn(fmt.Sprintf(format, args))
}

func (s *Service) Start(ctx context.Context) error {
	var err error

	s.listener = &fasthttp.Server{
		Handler:      s.requestHandler,
		ReadTimeout:  s.timeout,
		WriteTimeout: s.timeout,
		Logger:       s,
		//		IdleTimeout:                        s.idleTimeout,
	}

	s.gmtLocation, err = time.LoadLocation("GMT")
	if err != nil {
		return err
	}

	if s.cert != "" && s.key != "" {
		s.log.Debug("listen in secured TLS mode")
		go func() {
			if err = s.listener.ListenAndServeTLS(s.address, s.cert, s.key); err != nil {
				s.log.Fatal("api tls listen error", zap.Error(err))
			}
		}()
	} else {
		s.log.Debug("listen in unsecured HTTP mode")
		go func() {
			if err = s.listener.ListenAndServe(s.address); err != nil {
				s.log.Fatal("api listen error", zap.Error(err))
			}
		}()
	}

	return err

}

func (s *Service) Stop() error {
	if s.listener != nil {
		s.log.Info("api.stop")
		return s.listener.Shutdown()
	}
	return nil
}

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

	default:
		ctx.Error("Unsupported path", fasthttp.StatusNotFound)
		return
	}

}
