package vaultstorage

import (
	"context"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"github.com/im-kulikov/helium/service"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
)

type (
	serviceParams struct {
		dig.In

		Logger *zap.Logger
		Config *viper.Viper
	}

	serviceOutParams struct {
		dig.Out
		Service service.Service `group:"services"`
		Storage common.StorageInterface
	}

	// Service for vault storage.
	Service struct {
		log    *zap.Logger
		getKey func(publicID string) (*Key, error)

		vault      *vault.Client
		vaultToken *vault.Secret

		address          string
		roleID, secretID string
		vaultPath        string

		ctx context.Context

		sync.Mutex
	}
)

// Start storage service.
func (s *Service) Start(ctx context.Context) error {
	var err error

	s.ctx = ctx

	s.log.Debug("vault keys storage start", zap.String("address", s.address))

	config := vault.DefaultConfig()
	config.Address = s.address

	s.vault, err = vault.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "unable to initialize Vault client")
	}

	if err = s.login(); err != nil {
		return err
	}

	ttl, err := s.vaultToken.TokenTTL()
	if err != nil {
		return err
	}

	reloginTime := ttl * 2 / 3

	s.log.Debug("got vault token", zap.Duration("ttl", ttl), zap.Duration("relogin_time", reloginTime))
	timer := time.NewTimer(reloginTime)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			s.log.Debug("relogin to renew vault access token")
			if err = s.login(); err != nil {
				s.log.Error("cannot relogin to vault, will retry in 60 sec", zap.Error(err))
				timer.Reset(60 * time.Second)
			} else {
				ttl, err := s.vaultToken.TokenTTL()
				if err != nil {
					return err
				}

				reloginTime = ttl * 2 / 3
				s.log.Debug("renewed vault token", zap.Duration("ttl", ttl), zap.Duration("relogin_time", reloginTime))

				timer.Reset(reloginTime)
			}
		}
	}
}

func (s *Service) login() error {
	secretID := &auth.SecretID{FromString: s.secretID}
	appRoleAuth, err := auth.NewAppRoleAuth(
		s.roleID,
		secretID,
	)
	if err != nil {
		return errors.Wrap(err, "unable to initialize AppRole")
	}

	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	authInfo, err := s.vault.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return errors.Wrap(err, "unable to login to AppRole")
	}

	if authInfo == nil {
		return errors.New("no auth info was returned after login")
	}

	s.vaultToken = authInfo
	return nil
}

// Stop the storage service.
func (s *Service) Stop(ctx context.Context) {
}

// Name returns name of the service.
func (s *Service) Name() string {
	return "vault-keys-storage"
}

// Defaults for the storage service.
func Defaults(ctx *cli.Context, v *viper.Viper) error {
	v.SetDefault("vault.path", ctx.String("vault-path"))
	v.SetDefault("vault.address", ctx.String("vault-address"))
	v.SetDefault("vault.role_file", ctx.String("vault-role-file"))
	v.SetDefault("vault.secret_file", ctx.String("vault-secret-file"))
	return nil
}
