package app

import (
	"context"
	"github.com/im-kulikov/helium/service"
	"go.uber.org/dig"

	"github.com/im-kulikov/helium"
	"go.uber.org/zap"
)

type (
	app struct {
		Logger  *zap.Logger
		Service service.Group
	}

	appSettings struct {
		dig.In

		Logger  *zap.Logger
		Service service.Group
	}
)

func newApp(p appSettings) helium.App {
	return &app{
		Logger:  p.Logger,
		Service: p.Service,
	}
}

func (a app) Run(ctx context.Context) error {
	a.Logger.Info("running servers")

	if err := a.Service.Start(ctx); err != nil {
		return err
	}

	a.Logger.Info("app successfully started")

	<-ctx.Done()

	a.Logger.Info("stopping servers")
	a.Service.Stop()

	a.Logger.Info("gracefully stopped")
	return nil
}
