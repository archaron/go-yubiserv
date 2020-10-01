package api

import (
	"encoding/base64"
	"errors"
	"github.com/im-kulikov/helium/module"
	"github.com/im-kulikov/helium/service"
	"go.uber.org/dig"
)

// Module storage constructor
var Module = module.New(newAPIService, dig.Group("services"))

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

	return &Service{
		log:      p.Logger,
		address:  p.Config.GetString("api.address"),
		settings: p.Settings,
		apiKey:   apiKey,
		timeout:  p.Config.GetDuration("api.timeout"),
		storage:  p.Storage,
		cert:     p.Config.GetString("api.tls_cert"),
		key:      p.Config.GetString("api.tls_key"),
	}, nil
}
