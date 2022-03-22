package vaultstorage

import (
	"errors"
	"github.com/im-kulikov/helium/module"
	"io/ioutil"
)

// Module storage constructor
var Module = module.Module{
	{Constructor: newService},
}

func newService(p serviceParams) (serviceOutParams, error) {
	svc := &Service{
		log:     p.Logger,
		address: p.Config.GetString("vault.address"),
	}

	// Default key fetcher
	svc.getKey = svc.GetKey

	roleFile := p.Config.GetString("vault.role_file")
	rawRole, err := ioutil.ReadFile(roleFile)
	if err != nil {
		return serviceOutParams{}, err
	}

	if len(rawRole) != 36 {
		return serviceOutParams{}, errors.New("invalid role_id length")
	}

	svc.roleId = string(rawRole)

	secretFile := p.Config.GetString("vault.secret_file")
	rawSecret, err := ioutil.ReadFile(secretFile)
	if err != nil {
		return serviceOutParams{}, err
	}

	if len(rawSecret) != 36 {
		return serviceOutParams{}, errors.New("invalid secret_id length")
	}

	svc.secretId = string(rawSecret)

	return serviceOutParams{
		Service: svc,
		Storage: svc,
	}, nil
}
