package protocol

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"yyb_go/internal/oauth"
	"yyb_go/internal/store"
)

func TestH5CodeDoesNotReplayAfterSend(t *testing.T) {
	ctx := context.Background()
	target, captured := h5CaptureServer(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "h5.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status := "alive"
	acc, err := db.UpsertAccount(ctx, "synthetic-h5", "synthetic-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	st := h5WireTestSession(target)
	if err := db.PutSession(ctx, acc.ID, nil, st.toBlob(), st.PSK.ExpiredAt, ""); err != nil {
		t.Fatal(err)
	}

	pool := NewPool(DefaultConfig(), db)
	_, err = pool.GetH5Code(ctx, acc.LoginBuffer, oauth.Request{
		AppID:       "wx1234567890abcdef",
		RedirectURI: "https://example.com/callback",
		Scope:       "snsapi_base",
		State:       "fixed",
	}, acc.ID, "", false, acc)
	var attempt *H5AuthorizationAttemptError
	if !errors.As(err, &attempt) {
		t.Fatalf("expected a terminal H5 authorization attempt error, got %v", err)
	}
	if len(captured) != 1 {
		t.Fatalf("authorization sent %d times, want exactly one", len(captured))
	}
	if _, err := db.GetSession(ctx, acc.ID, ""); err != nil {
		t.Fatalf("sent business request invalidated session: %v", err)
	}
}
