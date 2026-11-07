package httpapi

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"yyb_go/internal/qbbrowser"
)

func TestQBBrowserTokenPreservesEnrollmentBoundaries(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite", ProtocolToken: "synthetic-main", RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	key, err := app.db.CreateAuthKey(ctx, "exclusive", "synthetic-key", nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := protowire.AppendTag(nil, 1, protowire.BytesType)
	raw = protowire.AppendString(raw, "synthetic-ticket")
	raw = protowire.AppendTag(raw, 2, protowire.BytesType)
	raw = protowire.AppendString(raw, "synthetic-device")
	raw = protowire.AppendTag(raw, 3, protowire.BytesType)
	raw = protowire.AppendString(raw, qbbrowser.HostAppID)
	buffer := base64.StdEncoding.EncodeToString(raw)
	app.qr.LoginBuffers().HTTPClient().Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"login_buffer":"` + buffer + `","err_code":0}`))}, nil
	})
	push := func(secret, uid string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/qbbrowser/token", strings.NewReader(`{"access_token":"synthetic-token","user_id":"`+uid+`"}`))
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		app.handleQBBrowserToken(w, r)
		return w
	}
	if w := push("synthetic-key", "key-user"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	account, err := app.db.GetAccountByOpenID(ctx, "qbbrowser:key-user")
	if err != nil {
		t.Fatal(err)
	}
	owners, err := app.db.ExclusiveAccountOwners(ctx)
	if err != nil || owners[account.ID] != key.ID {
		t.Fatal("exclusive enrollment lost", owners, err)
	}
	if account.OnlineSince == nil {
		t.Fatal("online interval missing")
	}
	if w := push("synthetic-main", "key-user"); w.Code == 200 {
		t.Fatal("main token overwrote exclusive account")
	}
	other, err := app.db.CreateAuthKey(ctx, "other", "synthetic-other", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := push("synthetic-other", "key-user"); w.Code == 200 {
		t.Fatal("unbound key overwrote exclusive account", other.ID)
	}
	fresh, err := app.db.GetAccount(ctx, account.ID)
	if err != nil || !fresh.SameAuthorization(account) {
		t.Fatal("rejected push changed authorization", err)
	}
	user, err := app.auth.CreateUser(ctx, "qb-owner", "owner", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/qbbrowser/token", strings.NewReader(`{"access_token":"synthetic-token","user_id":"web-user"}`))
	r = r.WithContext(context.WithValue(ctx, authUserKey, user))
	w := httptest.NewRecorder()
	app.handleQBBrowserToken(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	webAccount, err := app.db.GetAccountByOpenID(ctx, "qbbrowser:web-user")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.auth.AccountOwner(ctx, webAccount.ID)
	if err != nil || owner != user.ID {
		t.Fatal("browser ownership lost", owner, err)
	}
}
