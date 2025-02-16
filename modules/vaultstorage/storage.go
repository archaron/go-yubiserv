package vaultstorage

import (
	"context"
	"fmt"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/im-kulikov/helium/service"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
)

type (
	KeyGetterFunc func(publicID string) (*Key, error)

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
		log        *zap.Logger
		getKeyFunc KeyGetterFunc

		vault      *vault.Client
		vaultToken *vault.Secret

		address          string
		roleID, secretID string
		vaultPath        string

		loginTimeout time.Duration

		sync.Mutex
	}
)

const (
	reLoginRatioM = 2
	reLoginRatioD = 3
	retryTimeout  = 60 * time.Second
)

// Start storage service.
func (s *Service) Start(ctx context.Context) error {
	var err error

	s.log.Debug("vault keys storage start", zap.String("address", s.address))

	config := vault.DefaultConfig()
	config.Address = s.address

	s.vault, err = vault.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "unable to initialize Vault client")
	}

	if err = s.login(ctx); err != nil {
		return err
	}

	ttl, err := s.vaultToken.TokenTTL()
	if err != nil {
		return errors.Wrap(err, "unable to get token TTL")
	}

	reloginTime := (ttl * reLoginRatioM) / reLoginRatioD

	s.log.Debug("got vault token", zap.Duration("ttl", ttl), zap.Duration("relogin_time", reloginTime))
	timer := time.NewTimer(reloginTime)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err() //nolint:wrapcheck
		case <-timer.C:
			s.log.Debug("relogin to renew vault access token")

			if err = s.login(ctx); err != nil {
				s.log.Error("cannot relogin to vault, will retry after pause", zap.Duration("pause", retryTimeout), zap.Error(err))
				timer.Reset(retryTimeout)

				continue
			}

			ttl, err := s.vaultToken.TokenTTL()
			if err != nil {
				return fmt.Errorf("cannot get vault token TTL: %w", err)
			}

			reloginTime = (ttl * reLoginRatioM) / reLoginRatioD
			s.log.Debug("renewed vault token", zap.Duration("ttl", ttl), zap.Duration("relogin_time", reloginTime))

			timer.Reset(reloginTime)

		}
	}
}

func (s *Service) login(rootCtx context.Context) error {
	secretID := &approle.SecretID{FromString: s.secretID}
	appRoleAuth, err := approle.NewAppRoleAuth(
		s.roleID,
		secretID,
	)

	if err != nil {
		return errors.Wrap(err, "unable to initialize AppRole")
	}

	ctx, cancel := context.WithTimeout(rootCtx, s.loginTimeout)
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
func (s *Service) Stop(_ context.Context) {
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
	v.SetDefault("vault.role_id", ctx.String("vault-role-id"))
	v.SetDefault("vault.secret_id", ctx.String("vault-secret-id"))
	v.SetDefault("vault.login_timeout", ctx.String("vault-login-timeout"))

	return nil
}
