package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestMergeCannotTransferAPIKeyOwnership(t *testing.T) {
	for _, exclusive := range []bool{false, true} {
		ctx := context.Background()
		db, err := Open(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		status := "alive"
		a, err := db.UpsertAccount(ctx, "synthetic-source", "buffer", nil, nil, nil, nil, map[string]any{"token": "synthetic"}, &status)
		if err != nil {
			t.Fatal(err)
		}
		b, err := db.UpsertAccount(ctx, "synthetic-target", "buffer", nil, nil, nil, nil, nil, &status)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.CreateAuthKey(ctx, "owner", "synthetic-secret", []int64{a.ID}, nil, exclusive)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.MergeAccountAuthorization(ctx, a, b); !errors.Is(err, ErrMergeAPIKeyBindings) {
			t.Fatalf("exclusive=%t: %v", exclusive, err)
		}
		got, err := db.GetAccount(ctx, a.ID)
		if err != nil || got.OpenID != a.OpenID {
			t.Fatal("source changed", err)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
