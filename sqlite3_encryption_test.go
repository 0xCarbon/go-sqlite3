// Copyright (C) 2024 0xCarbon.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

//go:build cgo
// +build cgo

package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"testing"
)

// testConnector is a minimal driver.Connector that lets tests open a *sql.DB
// with a specific SQLiteDriver configuration (e.g. EncryptionKeyBytes) without
// going through sql.Register, which panics on duplicate names.
type testConnector struct {
	d   *SQLiteDriver
	dsn string
}

func (c *testConnector) Connect(_ context.Context) (driver.Conn, error) {
	return c.d.Open(c.dsn)
}

func (c *testConnector) Driver() driver.Driver { return c.d }

func openWithKeyBytes(t *testing.T, path string, key []byte) *sql.DB {
	t.Helper()
	db := sql.OpenDB(&testConnector{
		d:   &SQLiteDriver{EncryptionKeyBytes: key},
		dsn: path,
	})
	db.SetMaxOpenConns(1)
	return db
}

// requireCodec skips the test when the linked SQLite build has no SQLCipher
// codec (e.g. -tags libsqlite3 against a plain system libsqlite3): PRAGMA
// cipher_version returns no rows there. A system SQLCipher build still runs
// the suite.
func requireCodec(t *testing.T) {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version string
	err = db.QueryRow("PRAGMA cipher_version").Scan(&version)
	if err == sql.ErrNoRows {
		t.Skip("no SQLCipher codec in this build (plain SQLite?)")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryptionKeyBytes_RoundTrip(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	// Open with EncryptionKeyBytes, write data.
	db := openWithKeyBytes(t, path, key)
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES ('hello')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with same key, verify data.
	db2 := openWithKeyBytes(t, path, key)
	var v string
	if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "hello" {
		t.Fatalf("got %q, want %q", v, "hello")
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptionKeyBytes_WrongKeyFails(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	db := openWithKeyBytes(t, path, key)
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	wrongKey := []byte("abcdef0123456789abcdef0123456789")
	db2 := openWithKeyBytes(t, path, wrongKey)
	if err := db2.Ping(); err == nil {
		t.Fatal("expected error with wrong key, got nil")
	}
	_ = db2.Close()
}

func TestEncryptionKeyBytes_PrecedenceOverString(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	// Open with EncryptionKeyBytes.
	db := openWithKeyBytes(t, path, key)
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with EncryptionKeyBytes (correct) + EncryptionKey (wrong string).
	// EncryptionKeyBytes should take precedence.
	db2 := sql.OpenDB(&testConnector{
		d: &SQLiteDriver{
			EncryptionKeyBytes: key,
			EncryptionKey:      "\"x'deadbeef'\"",
		},
		dsn: path,
	})
	db2.SetMaxOpenConns(1)
	if err := db2.Ping(); err != nil {
		t.Fatalf("EncryptionKeyBytes should take precedence: %v", err)
	}
	_ = db2.Close()
}

func TestEncryptionKeyBytes_NilMeansNoKey(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.db")

	// nil key should work as plain SQLite.
	db := openWithKeyBytes(t, path, nil)
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify file starts with SQLite magic (not encrypted).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 16 || string(data[:15]) != "SQLite format 3" {
		t.Fatal("expected plain SQLite header")
	}
}
