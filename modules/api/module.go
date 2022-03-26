package api

import (
	"encoding/base64"
	"errors"

	"github.com/im-kulikov/helium/module"
	"github.com/im-kulikov/helium/service"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"

	"github.com/archaron/go-yubiserv/common"
)

// Module api constructor
// nolint:gochecknoglobals
var Module = module.Module{
	{Constructor: newAPIService, Options: []dig.ProvideOption{dig.Group("services")}},
}

func newAPIService(p serviceParams) (service.Service, error) {
	var (
		apiKey []byte
		err    error
	)

	if p.Storage == nil {
		return nil, errors.New("no storage module selected")
	}

	// Check if API secret key is specified
	key := p.Config.GetString("api.secret")
	if len(key) > 0 {
		apiKey, err = base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, err
		}
	}

	svc := &Service{
		log:      p.Logger,
		address:  p.Config.GetString("api.address"),
		settings: p.Settings,
		apiKey:   apiKey,
		timeout:  p.Config.GetDuration("api.timeout"),
		storage:  p.Storage,
		cert:     p.Config.GetString("api.tls_cert"),
		key:      p.Config.GetString("api.tls_key"),
		Users:    make(common.OTPUsers),
	}
	svc.log.Debug("API created")
	return svc, nil
}

// Defaults for storage service.
func Defaults(ctx *cli.Context, v *viper.Viper) error {
	// api:
	v.SetDefault("api.address", ctx.String("api-address"))
	v.SetDefault("api.timeout", ctx.String("api-timeout"))
	v.SetDefault("api.secret", ctx.String("api-secret"))

	tlsCert := ctx.String("api-tls-cert")
	tlsKey := ctx.String("api-tls-key")

	if tlsCert != "" || tlsKey != "" {
		if tlsCert == "" || tlsKey == "" {
			return errors.New("both tls certificate file and private key file must be set to enable TLS")
		}
	}

	v.SetDefault("api.tls_cert", tlsCert)
	v.SetDefault("api.tls_key", tlsKey)

	return nil
}
