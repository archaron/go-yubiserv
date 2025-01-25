package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/im-kulikov/helium"
	"github.com/im-kulikov/helium/grace"
	"github.com/im-kulikov/helium/logger"
	"github.com/im-kulikov/helium/module"
	"github.com/im-kulikov/helium/settings"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"

	"github.com/archaron/go-yubiserv/misc"
	"github.com/archaron/go-yubiserv/modules/api"
	"github.com/archaron/go-yubiserv/modules/sqlitestorage"
	"github.com/archaron/go-yubiserv/modules/vaultstorage"
)

func defaults(ctx *cli.Context, v *viper.Viper) error {
	if ctx.Bool("debug") {
		misc.Debug = true
	}

	v.SetDefault("logger.full_caller", false)

	// logger:
	v.SetDefault("logger.format", "console")

	// Enable debug messages in log
	if misc.Debug {
		v.SetDefault("logger.level", "debug")
	} else {
		v.SetDefault("logger.level", "info")
	}

	v.SetDefault("logger.trace_level", "fatal")
	v.SetDefault("logger.format", ctx.String("log-format"))

	v.SetDefault("logger.no_disclaimer", true)
	v.SetDefault("logger.color", ctx.String("log-format") != "json")

	// v.SetDefault("logger.no_caller", true)
	v.SetDefault("logger.full_caller", false)
	v.SetDefault("logger.sampling.initial", 100)
	v.SetDefault("logger.sampling.thereafter", 100)

	v.SetDefault("shutdown_timeout", 30*time.Second)

	if err := api.Defaults(ctx, v); err != nil {
		return err
	}

	if err := vaultstorage.Defaults(ctx, v); err != nil {
		return err
	}

	//err := v.WriteConfigAs("./x.yaml")
	//if err != nil {
	//	return err
	//}

	return nil
}

// nolint:gochecknoglobals
var modules = module.Combine(
	helium.DefaultApp, // default application
	grace.Module,      // grace context
	settings.Module,   // settings module
	logger.Module,     // logger module
	api.Module,
)

// nolint:gochecknoglobals
var generateModules = module.Combine(
	settings.Module, // settings module
	logger.Module,   // logger module
)

func main() {
	c := cli.NewApp()
	c.Name = misc.Name
	c.Version = misc.Version

	c.Authors = []*cli.Author{
		{
			Name:  "Alexander Tischenko",
			Email: "tsm@archaron.ru",
		},
	}
	c.Usage = "Yubikey verification server"
	c.UsageText = "Used to authenticate remote clients via yubikey OTP"

	c.Commands = cli.Commands{
		{
			Name: "generate",
			Aliases: []string{
				"g",
			},
			Usage:  "generate some keys for future usage",
			Action: generator(),
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:     "start",
					Value:    1,
					Usage:    "Start key ID",
					Required: false,
					Aliases: []string{
						"s",
					},
				},
				&cli.IntFlag{
					Name:     "count",
					Usage:    "Number of generated keys",
					Value:    1,
					Required: false,
					Aliases: []string{
						"n",
					},
				},

				&cli.StringFlag{
					Name:  "progflags",
					Usage: "PROGFLAGS: Add a final personalization configuration string",
				},
				&cli.BoolFlag{
					Name:  "save",
					Usage: "Save generated keys in storage",
					Value: false,
				},
			},
		},
	}

	c.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "Config file path (YAML)",
		},

		&cli.BoolFlag{Name: "debug", Aliases: []string{"d"}, Value: false, Usage: "Enable debug mode"},

		&cli.StringFlag{Name: "log-format", Value: "console", Usage: "Log format: console/json"},

		&cli.StringFlag{Name: "api-address", Value: ":8443", Usage: "Validation API bind address"},
		&cli.StringFlag{Name: "api-timeout", Value: "1s", Usage: "Validation API connect/read timeout"},
		&cli.StringFlag{Name: "api-secret", Value: "", Usage: "Validation API secret for HMAC signature verification, empty to disable check"},

		&cli.StringFlag{Name: "api-tls-cert", Value: "", Usage: "Validation API TLS cert file path"},
		&cli.StringFlag{Name: "api-tls-key", Value: "", Usage: "Validation API TLS private key file path"},

		&cli.StringFlag{Name: "keystore", Value: "vault", Usage: "Key store backend: sqlite, vault"},

		&cli.StringFlag{Name: "sqlite-dbpath", Value: "yubiserv.db", Usage: "SQLite3 database path"},

		&cli.StringFlag{Name: "vault-address", Value: "https://127.0.0.1:8200", Usage: "Vault server address"},
		&cli.StringFlag{Name: "vault-path", Value: "secret/data/yubiserv", Usage: "Vault path to KV secrets store"},

		&cli.StringFlag{Name: "vault-role-id", Value: "", Usage: "role_id for Vault auth, overrides role-file"},
		&cli.StringFlag{Name: "vault-role-file", Value: "role_id", Usage: "Path to file containing role_id for Vault auth"},
		&cli.StringFlag{Name: "vault-secret-id", Value: "", Usage: "secret_id for Vault auth, overrides secret-file"},
		&cli.StringFlag{Name: "vault-secret-file", Value: "secret_id", Usage: "Path to file containing secret_id for Vault auth"},
	}

	// Default action
	c.Action = func(ctx *cli.Context) error {
		switch ctx.String("keystore") {
		case "vault":
			modules = modules.Append(vaultstorage.Module)
		case "sqlite":
			modules = modules.Append(sqlitestorage.Module)
		default:
			return errors.New("unknown keystore")
		}
		h, err := helium.New(&helium.Settings{
			File:         ctx.String("config"),
			Prefix:       misc.Prefix,
			Name:         misc.Name,
			Type:         "yaml",
			BuildTime:    misc.Version,
			BuildVersion: misc.Build,
			Defaults: func(v *viper.Viper) error {
				return defaults(ctx, v)
			},
		}, modules)
		if err != nil {
			return err
		}

		return h.Run()
	}

	err := c.Run(os.Args)
	err = dig.RootCause(err)
	helium.Catch(err)
}

func generator() cli.ActionFunc {
	return func(c *cli.Context) error {
		h, err := helium.New(&helium.Settings{
			Prefix:       misc.Prefix,
			Name:         misc.Name,
			BuildTime:    misc.Version,
			BuildVersion: misc.Build,
		}, generateModules)
		if err != nil {
			return err
		}

		return h.Invoke(func(log *zap.Logger) {
			start := c.Int("start")
			count := c.Int("count")
			progflags := c.String("progflags")

			fmt.Println("# ykksm 1")
			fmt.Printf("# start %d end %d\n", start, start+count)
			fmt.Println("# serialnr,identity,internaluid,aeskey,lockpw,created,accessed[,progflags]")

			// rand.Read()

			for i := start; i <= count; i++ {
				ctr := fmt.Sprintf("%012x", i)
				modhexctr := misc.HexToModHex(ctr)
				internalUID, err := misc.HexRand(6)
				if err != nil {
					log.Fatal("error generating random", zap.Error(err))
				}

				aesKey, err := misc.HexRand(16)
				if err != nil {
					log.Fatal("error generating random aes key", zap.Error(err))
				}

				lockPW, err := misc.HexRand(6)
				if err != nil {
					log.Fatal("error generating random lockPW", zap.Error(err))
				}

				// fmt.Printf("# hexctr %s modhexctr %s\n", ctr, modhexctr)
				fmt.Printf("%d,%s,%s,%s,%s,%s,%s\n", i, modhexctr, internalUID, aesKey, lockPW, time.Now().Format(time.RFC3339), progflags)
				fmt.Println("# the end")
			}
		})
	}
}
