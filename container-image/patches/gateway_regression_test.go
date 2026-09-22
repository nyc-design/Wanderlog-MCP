package cmd

import (
 "path/filepath"
 "testing"
)

func TestGatewaySessionOnlyCurrentUserID(t *testing.T) {
 t.Setenv("WANDERLOG_DISABLE_KEYCHAIN", "1")
 t.Setenv("WANDERLOG_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent.json"))
 t.Setenv("WANDERLOG_AUTH_SESSION_COOKIE", "synthetic-session")
 if got := currentUserID(); got != 0 { t.Fatalf("got %d, want no persisted identity", got) }
}
