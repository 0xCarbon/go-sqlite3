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
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestDSNKey_RoundTrip(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")
	dsn := path + "?_key=" + hex.EncodeToString(key)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES ('dsn-key')"); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRow("PRAGMA cipher_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("PRAGMA cipher_version empty: codec not active")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := sql.Open("sqlite3", dsn+"&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	var v string
	if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "dsn-key" {
		t.Fatalf("got %q, want %q", v, "dsn-key")
	}
	if err := db2.Close(); err != nil {
		t.Fatal(err)
	}

	// The file must actually be encrypted: a plain open cannot read it.
	plain, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Query("SELECT v FROM t"); err == nil {
		plain.Close()
		t.Fatal("plain open unexpectedly read an encrypted database")
	}
	plain.Close()
}

func TestDSNKey_WrongKeyFails(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")
	wrong := []byte("ffffffffffffffffffffffffffffffff")

	db, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	bad, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(wrong))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Query("SELECT v FROM t"); err == nil {
		bad.Close()
		t.Fatal("wrong key unexpectedly read the database")
	} else {
		var serr Error
		if !errors.As(err, &serr) || serr.Code != ErrNotADB {
			t.Fatalf("got %v, want ErrNotADB", err)
		}
	}
	bad.Close()
}

func TestDSNKey_InvalidHexFails(t *testing.T) {
	requireCodec(t)
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_key=zz")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Query("SELECT 1"); err == nil {
		t.Fatal("invalid _key hex unexpectedly opened the database")
	}
}

func TestDSNKey_EmptyFails(t *testing.T) {
	requireCodec(t)
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_key=")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Query("SELECT 1"); err == nil {
		t.Fatal("empty _key unexpectedly opened the database")
	}
}

func TestDSNKey_DriverFieldTakesPrecedence(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	fieldKey := []byte("0123456789abcdef0123456789abcdef")
	dsnKey := []byte("ffffffffffffffffffffffffffffffff")

	// Driver field wins over the _key DSN parameter: the database is
	// keyed with fieldKey even though the DSN carries a different key.
	db := sql.OpenDB(&testConnector{
		d:   &SQLiteDriver{EncryptionKeyBytes: fieldKey},
		dsn: path + "?_key=" + hex.EncodeToString(dsnKey),
	})
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening with only the DSN key must fail: the file is keyed with
	// the field key.
	bad, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(dsnKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Query("SELECT v FROM t"); err == nil {
		bad.Close()
		t.Fatal("dsn key unexpectedly opened a field-keyed database")
	}
	bad.Close()

	// Reopening with the field key through the DSN works.
	ok, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(fieldKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.Query("SELECT v FROM t"); err != nil {
		ok.Close()
		t.Fatal(err)
	}
	ok.Close()
}

// TestKeyedOpenRefusedWithoutCodec verifies that a keyed open fails loudly on
// builds without the SQLCipher codec (e.g. -tags libsqlite3 against a plain
// system libsqlite3) instead of silently operating unencrypted.
func TestKeyedOpenRefusedWithoutCodec(t *testing.T) {
	probe, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	var version string
	perr := probe.QueryRow("PRAGMA cipher_version").Scan(&version)
	probe.Close()
	if perr == nil {
		t.Skip("codec available in this build; refusal path not reachable")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	db := openWithKeyBytes(t, path, key)
	_, err = db.Exec("CREATE TABLE t (v TEXT)")
	if err == nil || !strings.Contains(err.Error(), "SQLCipher codec not available") {
		db.Close()
		t.Fatalf("EncryptionKeyBytes open: got %v, want codec-unavailable refusal", err)
	}
	db.Close()

	dsn, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dsn.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "SQLCipher codec not available") {
		dsn.Close()
		t.Fatalf("_key DSN open: got %v, want codec-unavailable refusal", err)
	}
	dsn.Close()
}
