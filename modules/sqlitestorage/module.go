package sqlitestorage

import (
	"github.com/im-kulikov/helium/module"
)

// Module storage constructor
var Module = module.Module{
	{Constructor: newService},
}

func newService(p serviceParams) serviceOutParams {
	svc := &Service{
		log:    p.Logger,
		dbPath: p.Config.GetString("sqlite.dbpath"),
	}

	// Default key fetcher
	svc.getKey = svc.GetKey

	return serviceOutParams{
		Service: svc,
		Storage: svc,
	}
}
