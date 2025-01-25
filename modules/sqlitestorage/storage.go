package sqlitestorage

import (
	"context"
	"fmt"
	"sync"

	"github.com/im-kulikov/helium/service"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
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

	// Service for SQLite database storage.
	Service struct {
		log    *zap.Logger
		getKey func(publicID string) (*key, error)
		db     *sqlx.DB

		dbPath string
		sync.Mutex
	}
)

// Start the storage service.
func (s *Service) Start(ctx context.Context) error {
	var err error
	s.log.Debug("keys storage start", zap.String("db_path", s.dbPath))

	s.db, err = sqlx.Open("sqlite3", fmt.Sprintf("%s?mode=rwc&cache=shared", s.dbPath))
	if err != nil {
		return errors.Wrap(err, "failed to open database")
	}

	// Ensure database is created
	if err := s.db.Ping(); err != nil {
		return err
	}

	if err := s.createDatabase(); err != nil {
		return err
	}

	<-ctx.Done()

	return ctx.Err()
}

// Stop the storage service.
func (s *Service) Stop(_ context.Context) {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Name of the service.
func (s *Service) Name() string {
	return "sqlite-keys-storage"
}

// Defaults for the sqlite storage service.
func Defaults(ctx *cli.Context, v *viper.Viper) error {
	fmt.Println("db=", ctx.String("sqlite-dbpath"))
	v.SetDefault("sqlite.dbpath", ctx.String("sqlite-dbpath"))
	return nil
}
