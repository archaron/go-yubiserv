package vaultstorage

import (
	"errors"
	"os"

	"github.com/im-kulikov/helium/module"
)

// Module storage constructor
// nolint:gochecknoglobals
var Module = module.Module{
	{Constructor: newService},
}

func newService(p serviceParams) (serviceOutParams, error) {
	svc := &Service{
		log:       p.Logger,
		address:   p.Config.GetString("vault.address"),
		vaultPath: p.Config.GetString("vault.path"),
	}

	// Default Key fetcher
	svc.getKey = svc.GetKey

	if svc.roleID = p.Config.GetString("vault.role_id"); svc.roleID == "" {
		roleFile := p.Config.GetString("vault.role_file")
		rawRole, err := os.ReadFile(roleFile)
		if err != nil {
			return serviceOutParams{}, err
		}

		if len(rawRole) != 36 {
			return serviceOutParams{}, errors.New("invalid role_id length")
		}

		svc.roleID = string(rawRole)
	}

	if svc.secretID = p.Config.GetString("vault.secret_id"); svc.secretID == "" {
		secretFile := p.Config.GetString("vault.secret_file")
		rawSecret, err := os.ReadFile(secretFile)
		if err != nil {
			return serviceOutParams{}, err
		}

		if len(rawSecret) != 36 {
			return serviceOutParams{}, errors.New("invalid secret_id length")
		}

		svc.secretID = string(rawSecret)
	}

	return serviceOutParams{
		Service: svc,
		Storage: svc,
	}, nil
}
