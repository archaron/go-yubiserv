package vaultstorage

import (
	"context"
	"github.com/archaron/go-yubiserv/common"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"github.com/im-kulikov/helium/service"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"
	"sync"
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

	Service struct {
		log    *zap.Logger
		getKey func(publicID string) (*key, error)
		vault  *vault.Client

		address          string
		roleId, secretId string
		sync.Mutex
	}
)

func (s *Service) Start(ctx context.Context) error {
	var err error
	s.log.Debug("vault keys storage start", zap.String("address", s.address))

	config := vault.DefaultConfig()
	config.Address = s.address

	s.vault, err = vault.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "unable to initialize Vault client")
	}

	secretID := &auth.SecretID{FromFile: "secret_id"}

	appRoleAuth, err := auth.NewAppRoleAuth(
		s.roleId,
		secretID,
	)
	if err != nil {
		return errors.Wrap(err, "unable to initialize AppRole")
	}

	authInfo, err := s.vault.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return errors.Wrap(err, "unable to login to AppRole")
	}

	if authInfo == nil {
		return errors.New("no auth info was returned after login")
	}

	<-ctx.Done()

	return ctx.Err()
}

func (s *Service) Stop(ctx context.Context) {

	//if s.db != nil {
	//	//_ = s.db.Close()
	//}
}

func (s *Service) Name() string {
	return "vault-keys-storage"
}

func Defaults(ctx *cli.Context, v *viper.Viper) error {
	v.SetDefault("vault.address", ctx.String("vault-address"))
	v.SetDefault("vault.role_file", ctx.String("vault-role-file"))
	v.SetDefault("vault.secret_file", ctx.String("vault-secret-file"))
	return nil
}
