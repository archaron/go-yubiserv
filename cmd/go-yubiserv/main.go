package main

import (
	"fmt"
	"github.com/archaron/go-yubiserv/misc"
	"github.com/archaron/go-yubiserv/modules/app"
	"github.com/im-kulikov/helium"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
	"go.uber.org/dig"
	"go.uber.org/zap"
	"time"

	"os"
)

func defaults(ctx *cli.Context, v *viper.Viper) error {

	if ctx.Bool("debug") {
		misc.Debug = true
	}
	v.SetDefault("logger.full_caller", true)
	// api:
	v.SetDefault("api.address", ctx.String("api-address"))
	v.SetDefault("api.timeout", ctx.String("api-timeout"))
	v.SetDefault("api.secret", ctx.String("api-secret"))

	// logger:
	v.SetDefault("logger.format", "console")

	// Enable debug messages in log
	if misc.Debug {
		v.SetDefault("logger.level", "debug")
	} else {
		v.SetDefault("logger.level", "info")
	}

	v.SetDefault("logger.trace_level", "fatal")
	v.SetDefault("logger.no_disclaimer", !ctx.Bool("log-disclaimer"))
	v.SetDefault("logger.color", true)
	v.SetDefault("logger.full_caller", false)
	v.SetDefault("logger.sampling.initial", 100)
	v.SetDefault("logger.sampling.thereafter", 100)

	v.SetDefault("sqlite.dbpath", ctx.String("sqlite-dbpath"))

	return nil
}

func main() {

	c := cli.NewApp()
	c.Name = misc.Name
	c.Version = misc.Version

	c.Authors = []*cli.Author{
		{
			Name:  "Alexander Tischenko",
			Email: "tsm@fiberside.ru",
		},
	}
	c.Usage = "Yubikey verification server"
	c.UsageText = "Used to authenticate remote clients via ubikey OTP"

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

		&cli.BoolFlag{Name: "log-disclaimer", Value: false, Usage: "Show app name and version in log"},

		&cli.StringFlag{Name: "api-address", Value: ":8080", Usage: "Validation API bind address"},
		&cli.StringFlag{Name: "api-timeout", Value: "1s", Usage: "Validation API connect/read timeout"},
		&cli.StringFlag{Name: "api-secret", Value: "", Usage: "Validation API secret for HMAC signature verification, empty to disable check"},

		&cli.StringFlag{Name: "sqlite-dbpath", Value: "yubiserv.db", Usage: "SQLite3 database path"},
	}

	// Default action
	c.Action = func(ctx *cli.Context) error {

		settings := &helium.Settings{
			File:         ctx.String("config"),
			Prefix:       misc.Prefix,
			Name:         misc.Name,
			Type:         "yaml",
			BuildTime:    misc.Version,
			BuildVersion: misc.Build,
			Defaults: func(v *viper.Viper) error {
				return defaults(ctx, v)
			},
		}

		h, err := helium.New(settings, app.Module)
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
		}, app.GenerateModule)

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

			//rand.Read()

			for i := start; i <= count; i++ {
				ctr := fmt.Sprintf("%012x", i)
				modhexctr := misc.Hex2modhex(ctr)
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

				//fmt.Printf("# hexctr %s modhexctr %s\n", ctr, modhexctr)
				fmt.Printf("%d,%s,%s,%s,%s,%s,%s\n", i, modhexctr, internalUID, aesKey, lockPW, time.Now().Format(time.RFC3339), progflags)
				fmt.Println("# the end")

			}

		})
	}
}
