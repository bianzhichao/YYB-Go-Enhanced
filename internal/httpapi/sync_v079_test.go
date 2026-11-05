package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"yyb_go/internal/store"
)

func TestFleetStatusRejectsHiddenMembers(t *testing.T) {
	app, a, _ := fleetTestSetup(t)
	principal := scopedProtocolPrincipal{Key: &store.AuthKey{ID: 7, AccountIDs: []int64{a.ID}}, Owners: map[int64]int64{}}
	ctx := context.WithValue(context.Background(), scopedProtocolContext{}, principal)
	w := httptest.NewRecorder()
	app.handleFleetStatus(w, httptest.NewRequest("GET", fmt.Sprintf("/api/fleet?ref=%d", a.ID), nil).WithContext(ctx))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "fleet-b") {
		t.Fatalf("hidden member exposed: %d %s", w.Code, w.Body.String())
	}
	// Without a scoped restriction, local administration retains the full group.
	w = httptest.NewRecorder()
	app.handleFleetStatus(w, httptest.NewRequest("GET", fmt.Sprintf("/api/fleet?ref=%d", a.ID), nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	// Browser ownership must enforce the same boundary as scoped keys.
	ownedApp, err := NewApp(Config{ResourceRoot: t.TempDir(), AuthDriver: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer ownedApp.Close()
	owner, err := ownedApp.auth.CreateUser(context.Background(), "status-owner", "owner", "synthetic-password", "user")
	if err != nil {
		t.Fatal(err)
	}
	owned := insertKeepAliveTestAccount(t, ownedApp, "owned", time.Now().Add(time.Hour))
	hidden := insertKeepAliveTestAccount(t, ownedApp, "hidden", time.Now().Add(time.Hour))
	if err := ownedApp.auth.ClaimAccount(context.Background(), owned.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{owned.ID, hidden.ID} {
		if err := ownedApp.db.SetAccountFleet(context.Background(), id, owned.ID); err != nil {
			t.Fatal(err)
		}
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/fleet?ref=%d", owned.ID), nil).WithContext(context.WithValue(context.Background(), authUserKey, owner))
	ownedApp.handleFleetStatus(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestRuntimeInvalidRequestPreservesAllSettings(t *testing.T) {
	app := newKeepAliveTestApp(t)
	defer app.Close()
	path := app.pacer.filePath()
	original := []byte(`{"login_budget":7}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	beforeEnabled := app.dynamicAppIDs.enabledNow()
	beforeThreshold := app.dynamicAppIDs.currentThreshold()
	for _, payload := range []string{
		`{"reset":true,"dynamic_deny_enabled":false,"dynamic_deny_threshold":51}`,
		`{"reset":true,"login_budget":1001}`,
		`{"reset":true,"fresh_session_window_ms":-1}`,
	} {
		w := httptest.NewRecorder()
		app.handleRuntimeSettings(w, httptest.NewRequest("PUT", "/api/runtime-settings", strings.NewReader(payload)))
		if w.Code != http.StatusBadRequest {
			t.Fatal(w.Code, w.Body.String())
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(original) {
			t.Fatal("invalid request changed tuning file", err)
		}
		if app.dynamicAppIDs.enabledNow() != beforeEnabled || app.dynamicAppIDs.currentThreshold() != beforeThreshold {
			t.Fatal("invalid request changed dynamic deny")
		}
	}
}
