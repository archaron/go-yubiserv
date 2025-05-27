package sqlitestorage

import (
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"go.uber.org/zap/zaptest"
)

func TestModule(t *testing.T) {
	t.Parallel()

	t.Run("module initialization", func(t *testing.T) {
		t.Parallel()

		require.NotNil(t, Module)
		require.Equal(t, 1, len(Module))
		require.NotNil(t, Module[0].Constructor)
	})
}

func TestTestNewService(t *testing.T) {
	t.Parallel()

	t.Run("with custom getter", func(t *testing.T) {
		t.Parallel()

		logger := zaptest.NewLogger(t)
		mockDB := &sqlx.DB{}
		customGetter := func(string) (*Key, error) { return nil, nil }

		svc := TestNewService(logger, customGetter, mockDB)

		require.NotNil(t, svc)
		require.NotNil(t, svc.getKeyFunc)
	})
}

func TestNewServiceInit(t *testing.T) {
	t.Parallel()

	t.Run("service initialization", func(t *testing.T) {
		t.Parallel()

		// Настраиваем Viper для теста
		v := viper.New()
		v.Set("sqlite.dbpath", "test.db")

		logger := zaptest.NewLogger(t)

		params := serviceParams{
			Logger: logger,
			Config: v,
		}

		out := newService(params)

		require.NotNil(t, out.Service)
		require.NotNil(t, out.Storage)
	})
}
