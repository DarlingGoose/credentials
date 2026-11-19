package oserver

import (
	"context"
	"strings"
	"testing"
)

func TestMySQLDatabaseNameValidation(t *testing.T) {
	for _, name := range []string{"oserver", "jpn_learning_oauth", "tenant_42"} {
		if !mysqlDatabaseName.MatchString(name) {
			t.Errorf("database name %q should be accepted", name)
		}
	}

	for _, name := range []string{"", "oauth-prod", "oauth.prod", "oauth`prod", "oauth prod"} {
		if mysqlDatabaseName.MatchString(name) {
			t.Errorf("database name %q should be rejected", name)
		}
	}
}

func TestNewMySQLServerWithDatabaseRejectsInvalidName(t *testing.T) {
	_, err := NewMySQLServerWithDatabase(context.Background(), nil, "oauth; DROP DATABASE oserver")
	if err == nil || !strings.Contains(err.Error(), "invalid database name") {
		t.Fatalf("NewMySQLServerWithDatabase() error = %v, want invalid database name", err)
	}
}

func TestMySQLServerTableUsesConfiguredDatabase(t *testing.T) {
	s := &MySQLServer{database: "jpn_learning_oauth"}
	if got, want := s.table("oauth_tokens"), "`jpn_learning_oauth`.`oauth_tokens`"; got != want {
		t.Fatalf("table() = %q, want %q", got, want)
	}
}
