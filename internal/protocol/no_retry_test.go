package protocol

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
	"yyb_go/internal/store"
)

func TestNoRetryErrorPreservesProxySession(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	status := "alive"
	acc, err := db.UpsertAccount(ctx, "synthetic-terminal", "synthetic-buffer", nil, nil, nil, nil, nil, &status)
	if err != nil {
		t.Fatal(err)
	}
	proxy := "socks5://example.invalid:1080"
	st := WmpfSession{Session: AppSession{UIN: 1234, SendKey: []byte("send"), RecvKey: []byte("recv")}, PSK: pskEntry{PSKType: 1, PreSharedKey: "001122", TicketEntry: "aabbcc", ExpiredAt: time.Now().Add(time.Hour).Unix()}, TCPProxy: proxy}
	if err = db.PutSession(ctx, acc.ID, nil, st.toBlob(), st.PSK.ExpiredAt, proxy); err != nil {
		t.Fatal(err)
	}
	pool := NewPool(DefaultConfig(), db)
	calls := 0
	cause := errors.New("synthetic application rejection")
	_, err = pool.run(ctx, acc.LoginBuffer, acc.ID, proxy, true, func(context.Context, WmpfSession) (map[string]any, error) { calls++; return nil, MarkNoRetry(cause) }, acc)
	if calls != 1 || !errors.Is(err, cause) || !IsNoRetry(err) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if _, err = db.GetSession(ctx, acc.ID, proxy); err != nil {
		t.Fatal("terminal result invalidated proxy session", err)
	}
}
