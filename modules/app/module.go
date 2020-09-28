package app

import (
	"github.com/archaron/go-yubiserv/modules/api"
	"github.com/archaron/go-yubiserv/modules/sqlitestorage"
	"github.com/im-kulikov/helium/grace"
	"github.com/im-kulikov/helium/logger"
	"github.com/im-kulikov/helium/module"
	"github.com/im-kulikov/helium/service"
	"github.com/im-kulikov/helium/settings"
	"github.com/im-kulikov/helium/web"
)

var Module = module.Module{
	{Constructor: newApp}, // provide helium.App
}.
	Append(
		grace.Module,    // grace context
		settings.Module, // settings module
		logger.Module,   // logger module
		api.Module,
		web.MetricsModule,
		web.ProfilerModule,
		service.Module,
		sqlitestorage.Module,
	)

var GenerateModule = module.Module{}.
	Append(
		settings.Module, // settings module
		logger.Module,   // logger module
	)
