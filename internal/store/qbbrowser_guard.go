package store

import (
	"database/sql"
	"encoding/json"

	"yyb_go/internal/qbbrowser"
)

// Both normal and scoped scan writes must preserve standalone refresh tokens.
// Call only after reading the old credentials inside the write transaction.
func qqBrowserBridgeDowngrade(previousJSON, incomingJSON sql.NullString) bool {
	var previous, incoming struct {
		Provider string                `json:"provider"`
		QQ       qbbrowser.Credentials `json:"qbbrowser"`
	}
	_ = json.Unmarshal([]byte(previousJSON.String), &previous)
	_ = json.Unmarshal([]byte(incomingJSON.String), &incoming)
	return incoming.Provider == "qbbrowser" && previous.Provider == "qbbrowser" && previous.QQ.CanRefresh() && !incoming.QQ.CanRefresh()
}
