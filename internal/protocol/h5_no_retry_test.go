package protocol

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"yyb_go/internal/store"
)

func TestH5CodeDoesNotReplayAfterSend(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "response_lost", true: "malformed_response"}[malformed], func(t *testing.T) {
			ctx := context.Background()
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
			proxy := "socks5://example.invalid:1080"
			st := WmpfSession{
				Session:  AppSession{UIN: 1234, SendKey: bytes.Repeat([]byte{1}, 16), RecvKey: bytes.Repeat([]byte{2}, 16)},
				PSK:      pskEntry{PSKType: 1, PreSharedKey: "001122", TicketEntry: "aabbcc", ExpiredAt: time.Now().Add(time.Hour).Unix()},
				TCPProxy: proxy, ShortlinkTargets: []Target{{IP: "192.0.2.1", Port: 80}, {IP: "192.0.2.2", Port: 80}},
			}
			if err := db.PutSession(ctx, acc.ID, nil, st.toBlob(), st.PSK.ExpiredAt, proxy); err != nil {
				t.Fatal(err)
			}
			pool := NewPool(DefaultConfig(), db)
			calls := 0
			lost := errors.New("synthetic response lost after send")
			pool.h5Send = func(_ context.Context, target Target, _ pskEntry, _, packet []byte, _ time.Duration, route string, fallback bool) ([]byte, []byte, error) {
				calls++
				if route != proxy || fallback || target != st.ShortlinkTargets[0] || len(packet) == 0 {
					t.Fatal("unsafe H5 transport plan")
				}
				if malformed {
					return nil, []byte{0x0a, 0x20, 0x01}, nil
				}
				return nil, nil, lost
			}
			_, err = pool.GetH5Code(ctx, acc.LoginBuffer, "wx1234567890abcdef", "https://example.com/callback", "snsapi_base", "fixed", acc.ID, proxy, true, acc)
			if calls != 1 || err == nil || !IsNoRetry(err) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if !malformed && !errors.Is(err, lost) {
				t.Fatal("transport cause lost", err)
			}
			if _, err := db.GetSession(ctx, acc.ID, proxy); err != nil {
				t.Fatal("sent business request invalidated session", err)
			}
		})
	}
}
