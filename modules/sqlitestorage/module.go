// Package sqlitestorage represents SQLite database keys storage.
package sqlitestorage

import (
	"github.com/im-kulikov/helium/module"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// Module storage constructor.
var Module = module.Module{ //nolint:gochecknoglobals
	{Constructor: newService},
}

// TestNewService creates a new service for testing purposes.
func TestNewService(log *zap.Logger, getterFunc KeyGetterFunc, db *sqlx.DB) *Service {
	svc := &Service{log: log, getKeyFunc: getterFunc, db: db}

	if getterFunc == nil {
		svc.getKeyFunc = svc.GetKey
	}

	return svc
}

// TestNewServicePath creates a new service for testing purposes with database path.
func TestNewServicePath(log *zap.Logger, getterFunc KeyGetterFunc, dbPath string) *Service {
	svc := &Service{log: log, getKeyFunc: getterFunc, dbPath: dbPath}

	if getterFunc == nil {
		svc.getKeyFunc = svc.GetKey
	}

	return svc
}

func newService(p serviceParams) serviceOutParams {
	svc := &Service{
		log:    p.Logger,
		dbPath: p.Config.GetString("sqlite.dbpath"),
	}

	// Default key fetcher
	svc.getKeyFunc = svc.GetKey

	return serviceOutParams{
		Service: svc,
		Storage: svc,
	}
}
