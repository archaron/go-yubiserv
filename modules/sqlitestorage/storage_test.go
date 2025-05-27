package sqlitestorage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestServiceStart(t *testing.T) {
	t.Parallel()
	t.Run("database open error", func(t *testing.T) {
		t.Parallel()

		svc := &Service{
			log:    zaptest.NewLogger(t),
			dbPath: "/invalid/path/to/db?mode=ro", // Force read-only on an invalid path
		}

		err := svc.Start(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to open database")
	})

}

func TestServiceName(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	require.Equal(t, "sqlite-keys-storage", svc.Name())
}
