package vaultstorage

import (
	"errors"
	"fmt"
	"os"

	"github.com/im-kulikov/helium/module"
	"go.uber.org/zap"
)

const (
	roleLength   = 36
	secretLength = 36
)

// Module storage constructor.
var Module = module.Module{ //nolint:gochecknoglobals
	{Constructor: newService},
}

var (
	ErrInvalidRoleLength   = errors.New("invalid role_id length")
	ErrInvalidSecretLength = errors.New("invalid secret_id length")
)

// NewTestService creates a new service for testing purposes.
func NewTestService(log *zap.Logger, getterFunc KeyGetterFunc) (*Service, error) {
	return &Service{log: log, getKeyFunc: getterFunc}, nil
}

func newService(p serviceParams) (serviceOutParams, error) {
	svc := &Service{
		log:          p.Logger,
		address:      p.Config.GetString("vault.address"),
		vaultPath:    p.Config.GetString("vault.path"),
		loginTimeout: p.Config.GetDuration("vault.login_timeout"),
	}

	// Default Key fetcher
	svc.getKeyFunc = svc.GetKey

	if svc.roleID = p.Config.GetString("vault.role_id"); svc.roleID == "" {
		roleFile := p.Config.GetString("vault.role_file")

		rawRole, err := os.ReadFile(roleFile)
		if err != nil {
			return serviceOutParams{}, fmt.Errorf("cannot read role_id file: %w", err)
		}

		if len(rawRole) != roleLength {
			return serviceOutParams{}, ErrInvalidRoleLength
		}

		svc.roleID = string(rawRole)
	}

	if svc.secretID = p.Config.GetString("vault.secret_id"); svc.secretID == "" {
		secretFile := p.Config.GetString("vault.secret_file")

		rawSecret, err := os.ReadFile(secretFile)
		if err != nil {
			return serviceOutParams{}, fmt.Errorf("cannot read secret_id file: %w", err)
		}

		if len(rawSecret) != secretLength {
			return serviceOutParams{}, ErrInvalidSecretLength
		}

		svc.secretID = string(rawSecret)
	}

	return serviceOutParams{
		Service: svc,
		Storage: svc,
	}, nil
}
