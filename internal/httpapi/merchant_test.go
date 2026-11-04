package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"yyb_go/internal/auth"
	"yyb_go/internal/store"
)

func TestMerchantOwnershipAndAdminWrites(t *testing.T) {
	app, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	if err := app.db.EnsureMerchant(ctx); err != nil {
		t.Fatal(err)
	}
	owner, err := app.auth.CreateUser(ctx, "billowner", "Bill Owner", "test-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := app.auth.CreateUser(ctx, "billoutside", "Outside", "test-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := app.auth.CreateUser(ctx, "billadmin", "Admin", "test-password", "admin")
	if err != nil {
		t.Fatal(err)
	}
	acc, err := app.db.UpsertAccount(ctx, "owned-openid", "buffer", nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.auth.ClaimAccount(ctx, acc.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	for _, openid := range []string{"owned-openid", "foreign-openid", ""} {
		b := store.Bill{OpenID: openid, Package: "p", MchId: "m", AppId: "wx"}
		if err := app.db.InsertBill(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		user   *auth.User
		count  int
		status int
	}{{owner, 1, 200}, {outsider, 0, 200}, {admin, 3, 200}, {nil, 0, 401}} {
		r := httptest.NewRequest(http.MethodGet, "/wx/bills", nil)
		if tc.user != nil {
			r = r.WithContext(context.WithValue(r.Context(), authUserKey, tc.user))
		}
		w := httptest.NewRecorder()
		app.handleMerchantBills(w, r)
		if w.Code != tc.status {
			t.Fatalf("status %d want %d: %s", w.Code, tc.status, w.Body.String())
		}
		if tc.status == 200 {
			var body struct {
				Data []store.Bill `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Data) != tc.count {
				t.Fatalf("ownership count %d want %d: %s", len(body.Data), tc.count, w.Body.String())
			}
		}
	}
	for _, user := range []*auth.User{nil, owner, admin} {
		r := httptest.NewRequest(http.MethodPost, "/wx/bills/confirm", strings.NewReader(`{"id":1}`))
		if user != nil {
			r = r.WithContext(context.WithValue(r.Context(), authUserKey, user))
		}
		w := httptest.NewRecorder()
		app.handleMerchantBillsConfirm(w, r)
		want := 200
		if user == nil {
			want = 401
		} else if user.Role != "admin" {
			want = 403
		}
		if w.Code != want {
			t.Fatalf("confirm=%d want=%d %s", w.Code, want, w.Body.String())
		}
		if want == 200 && !strings.Contains(w.Body.String(), "未执行支付结算") {
			t.Fatalf("misleading confirmation: %s", w.Body.String())
		}
	}
}
