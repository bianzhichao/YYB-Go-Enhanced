package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"yyb_go/internal/store"
)

func (a *App) handleMerchantPage(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, false) {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tmplPath := filepath.Join(a.resources.Templates, "merchant.html")
	if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
		writeError(w, http.StatusInternalServerError, "template not found")
		return
	}
	serveFileOrText(w, r, tmplPath, "")
}

func (a *App) handleMerchantBills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	if !a.merchantAccess(w, r, false) {
		return
	}
	w.Header().Set("Content-Type", "application/json")

	openid := r.URL.Query().Get("openid")
	nickname := r.URL.Query().Get("nickname")

	bills, err := a.db.ListBills(r.Context(), openid, nickname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	bills, err = a.visibleMerchantBills(r, bills)
	if err != nil {
		writeError(w, 500, "账单权限查询失败")
		return
	}
	a.fillBillNicknames(r.Context(), bills)
	writeJSON(w, http.StatusOK, bills)
}

func (a *App) handleMerchantBillsConfirm(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ID       int64  `json:"id"`
		OpenID   string `json:"openid"`
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}

	bill, err := a.db.GetBill(r.Context(), req.ID)
	if err != nil || bill == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "账单不存在"})
		return
	}

	reqOpenID := strings.TrimSpace(req.OpenID)
	reqNickname := strings.TrimSpace(req.Nickname)
	billOpenID := strings.TrimSpace(bill.OpenID)
	billNickname := strings.TrimSpace(bill.Nickname)

	if reqOpenID != "" && billOpenID != "" && reqOpenID != billOpenID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "openid 不匹配"})
		return
	}
	if reqOpenID == "" && reqNickname != "" && billNickname != "" && reqNickname != billNickname {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "nickname 不匹配"})
		return
	}

	if err := a.db.UpdateBillStatus(r.Context(), req.ID, "done"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    "ok",
		"message": "已手工标记本地账单为 done；未执行支付结算",
	})
}

func (a *App) handleMerchantUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	if !a.merchantAccess(w, r, false) {
		return
	}
	w.Header().Set("Content-Type", "application/json")

	bills, err := a.db.ListBills(r.Context(), "", "")
	if err == nil {
		bills, err = a.visibleMerchantBills(r, bills)
	}
	if err != nil {
		writeError(w, 500, "账单查询失败")
		return
	}
	a.fillBillNicknames(r.Context(), bills)
	users := make([]store.BillUser, 0)
	seen := map[string]bool{}
	for _, bill := range bills {
		key := bill.OpenID + "\x00" + bill.Nickname
		if !seen[key] {
			seen[key] = true
			users = append(users, store.BillUser{OpenID: bill.OpenID, Nickname: bill.Nickname})
		}
	}
	writeJSON(w, 200, users)
}

func (a *App) handleMerchantInsertBill(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var bill store.Bill
	if err := json.NewDecoder(r.Body).Decode(&bill); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}
	if bill.MchId == "" || bill.Package == "" || bill.AppId == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mchId, package, appid 为必填项"})
		return
	}
	a.fillBillNickname(r.Context(), &bill)

	if err := a.db.InsertBill(r.Context(), &bill); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    "ok",
		"message": "账单创建成功",
		"bill":    bill,
	})
}

func (a *App) handleMerchantDeleteBill(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}
	if req.ID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 为必填项"})
		return
	}

	if err := a.db.DeleteBill(r.Context(), req.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "删除成功"})
}

func (a *App) handleMerchantBillFail(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "参数错误"})
		return
	}
	if req.ID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 为必填项"})
		return
	}

	bill, err := a.db.GetBill(r.Context(), req.ID)
	if err != nil || bill == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "账单不存在"})
		return
	}

	if bill.Status == "done" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "该本地账单已完成，无法标记为失败"})
		return
	}

	if err := a.db.UpdateBillStatus(r.Context(), req.ID, "fail"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    "ok",
		"message": "已将本地账单标记为 fail",
	})
}

func (a *App) handleMerchantBillsCleanup(w http.ResponseWriter, r *http.Request) {
	if !a.merchantAccess(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")

	deleted, err := a.db.DeleteBillsByStatuses(r.Context(), []string{"done", "fail"})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"code":    "ok",
		"message": "清理完成",
		"deleted": deleted,
	})
}

func (a *App) fillBillNicknames(ctx context.Context, bills []store.Bill) {
	for i := range bills {
		a.fillBillNickname(ctx, &bills[i])
	}
}

func (a *App) fillBillNickname(ctx context.Context, bill *store.Bill) {
	if bill == nil || strings.TrimSpace(bill.Nickname) != "" || strings.TrimSpace(bill.OpenID) == "" {
		return
	}
	acc, err := a.db.GetAccountByOpenID(ctx, strings.TrimSpace(bill.OpenID))
	if err != nil || acc == nil {
		return
	}
	if nick := strings.TrimSpace(deref(acc.Nickname)); nick != "" {
		bill.Nickname = nick
	}
}

func (a *App) fillBillUserNicknames(ctx context.Context, users []store.BillUser) {
	for i := range users {
		if strings.TrimSpace(users[i].Nickname) != "" || strings.TrimSpace(users[i].OpenID) == "" {
			continue
		}
		acc, err := a.db.GetAccountByOpenID(ctx, strings.TrimSpace(users[i].OpenID))
		if err != nil || acc == nil {
			continue
		}
		if nick := strings.TrimSpace(deref(acc.Nickname)); nick != "" {
			users[i].Nickname = nick
		}
	}
}

func (a *App) merchantAccess(w http.ResponseWriter, r *http.Request, write bool) bool {
	// Authentication-disabled installations retain the target's local-admin mode.
	if a.auth == nil {
		return true
	}
	user := a.browserUser(r)
	if user == nil {
		writeError(w, 401, "请先登录")
		return false
	}
	if write && user.Role != "admin" {
		writeError(w, 403, "需要管理员权限")
		return false
	}
	return true
}

func (a *App) visibleMerchantBills(r *http.Request, bills []store.Bill) ([]store.Bill, error) {
	if a.auth == nil {
		return bills, nil
	}
	user := a.browserUser(r)
	if user == nil {
		return []store.Bill{}, nil
	}
	if user.Role == "admin" {
		return bills, nil
	}
	owned, err := a.auth.AccountIDs(r.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	accounts, err := a.db.ListAccounts(r.Context())
	if err != nil {
		return nil, err
	}
	openids := map[string]bool{}
	for _, account := range accounts {
		if _, ok := owned[account.ID]; ok {
			openids[account.OpenID] = true
		}
	}
	out := make([]store.Bill, 0)
	for _, bill := range bills {
		if bill.OpenID != "" && openids[bill.OpenID] {
			out = append(out, bill)
		}
	}
	return out, nil
}
