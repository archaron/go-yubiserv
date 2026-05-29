package sqlitestorage

import (
	"context"
	"fmt"

	"github.com/im-kulikov/helium/service"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" //goland:noinspection GoLinter
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/common"
)

type (
	KeyGetterFunc func(ctx context.Context, publicID string) (*Key, error)

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
		log        *zap.Logger
		getKeyFunc KeyGetterFunc
		db         *sqlx.DB
		ctx        context.Context
		cancel     context.CancelFunc

		dbPath string
	}
)

// Start the storage service.
func (s *Service) Start(ctx context.Context) error {
	var err error

	s.log.Debug("keys storage start", zap.String("db_path", s.dbPath))

	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	s.db, err = sqlx.Open("sqlite3", s.dbPath)
	if err != nil {
		return errors.Wrap(err, "failed to open database")
	}

	// Ensure the database is created
	if pingErr := s.db.PingContext(s.ctx); pingErr != nil {
		return fmt.Errorf("could not connect to database: %w", pingErr)
	}

	if createErr := s.createDatabase(s.ctx); createErr != nil {
		return fmt.Errorf("could not create database: %w", createErr)
	}

	<-ctx.Done()

	return nil
}

// Stop the storage service.
func (s *Service) Stop(_ context.Context) {
	if s.db != nil {
		_ = s.db.Close()
	}

	s.cancel()

	<-s.ctx.Done()
}

// Name of the service.
func (s *Service) Name() string {
	return "sqlite-keys-storage"
}

// Defaults for the sqlite storage service.
func Defaults(ctx *cli.Context, v *viper.Viper) error {
	v.SetDefault("sqlite.dbpath", ctx.String("sqlite-dbpath")+"?mode=rwc&cache=shared")

	return nil
}
