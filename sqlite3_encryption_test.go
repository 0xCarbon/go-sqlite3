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

// codecAvailable reports whether the linked SQLite build provides the
// SQLCipher codec: PRAGMA cipher_version returns a row only on codec builds.
func codecAvailable(t *testing.T) bool {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version string
	return db.QueryRow("PRAGMA cipher_version").Scan(&version) == nil
}

// requireCodec skips the test when the linked SQLite build has no SQLCipher
// codec (e.g. -tags libsqlite3 against a plain system libsqlite3). A system
// SQLCipher build still runs the suite.
func requireCodec(t *testing.T) {
	t.Helper()
	if !codecAvailable(t) {
		t.Skip("no SQLCipher codec in this build (plain SQLite?)")
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
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_key=zz")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Query("SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "Invalid _key") {
		t.Fatalf("got %v, want Invalid _key error", err)
	}
}

func TestDSNKey_EmptyFails(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_key=")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Query("SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "Invalid _key") {
		t.Fatalf("got %v, want Invalid _key error", err)
	}
}

func TestDSNKey_DuplicateFails(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	db, err := sql.Open("sqlite3",
		filepath.Join(dir, "t.db")+"?_key="+hex.EncodeToString(key)+"&_key="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Query("SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "Invalid _key: duplicate") {
		t.Fatalf("got %v, want Invalid _key: duplicate values error", err)
	}
}

func TestRawKeyLengthValidated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")

	db := openWithKeyBytes(t, path, []byte("short"))
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err == nil ||
		!strings.Contains(err.Error(), "invalid raw key length") {
		db.Close()
		t.Fatalf("EncryptionKeyBytes: got %v, want invalid raw key length error", err)
	}
	db.Close()

	bad, err := sql.Open("sqlite3", path+"?_key=00112233") // 4 bytes
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Query("SELECT 1"); err == nil ||
		!strings.Contains(err.Error(), "invalid raw key length") {
		bad.Close()
		t.Fatalf("_key DSN: got %v, want invalid raw key length error", err)
	}
	bad.Close()
}

func TestEncryptionKey_RoundTrip(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	raw := []byte("0123456789abcdef0123456789abcdef")
	// EncryptionKey receives a SQL literal. The raw-key blob form is x'...'
	// wrapped in double quotes (the consumer contract; see go-alore's
	// DeriveDBKey).
	literal := "\"x'" + hex.EncodeToString(raw) + "'\""

	db := sql.OpenDB(&testConnector{
		d:   &SQLiteDriver{EncryptionKey: literal},
		dsn: path,
	})
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('k')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with the same literal.
	db2 := sql.OpenDB(&testConnector{
		d:   &SQLiteDriver{EncryptionKey: literal},
		dsn: path,
	})
	var v string
	if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "k" {
		t.Fatalf("got %q, want %q", v, "k")
	}
	db2.Close()

	// The same key material via EncryptionKeyBytes must read the same file.
	db3 := openWithKeyBytes(t, path, raw)
	if err := db3.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	db3.Close()
}

func TestDSNKey_FileURI(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")
	uri := "file:" + path + "?_key=" + hex.EncodeToString(key) + "&cache=shared"

	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('uri')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen through a plain (non-file:) DSN with the same key: the _key
	// segment must have been stripped from the URI handed to SQLite, not
	// from the keying behavior.
	db2, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	var v string
	if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "uri" {
		t.Fatalf("got %q, want %q", v, "uri")
	}
	db2.Close()

	// A plain open cannot read the file.
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
	if codecAvailable(t) {
		t.Skip("codec available in this build; refusal path not reachable")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "t.db")
	key := []byte("0123456789abcdef0123456789abcdef")

	db := openWithKeyBytes(t, path, key)
	_, err := db.Exec("CREATE TABLE t (v TEXT)")
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

func TestStripKeyParam(t *testing.T) {
	cases := []struct{ in, want string }{
		{"_key=abcd", ""},
		{"%5Fkey=abcd", ""},
		{"%5fkey=abcd", ""},
		{"a=1&_key=abcd&b=2", "a=1&b=2"},
		{"a=1&%5Fkey=abcd&b=2", "a=1&b=2"},
		{"_key", ""},
		{"%5Fkey", ""},
		// _key-suffixed spellings are treated as the key parameter and stripped.
		{"x_key=abcd", ""},
		{"a%5Fkey=abcd", ""},
		{"ke%79=1", "ke%79=1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := stripKeyParam(c.in); got != c.want {
			t.Errorf("stripKeyParam(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDSNKey_EncodedNameFileURI(t *testing.T) {
	requireCodec(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	key := []byte("0123456789abcdef0123456789abcdef")
	uri := "file:" + path + "?%5Fkey=" + hex.EncodeToString(key)

	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('enc')"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := sql.Open("sqlite3", uri)
	if err != nil {
		t.Fatal(err)
	}
	var v string
	if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "enc" {
		t.Fatalf("got %q, want %q", v, "enc")
	}
	db2.Close()

	wrong := []byte("ffffffffffffffffffffffffffffffff")
	bad, err := sql.Open("sqlite3", "file:"+path+"?%5Fkey="+hex.EncodeToString(wrong))
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.Ping(); err == nil {
		bad.Close()
		t.Fatal("wrong encoded _key unexpectedly pinged the database")
	}
	bad.Close()
}

func TestDSNKey_ParamErrorAfterDecode(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	db, err := sql.Open("sqlite3",
		filepath.Join(dir, "t.db")+"?_key="+hex.EncodeToString(key)+"&_mutex=bogus")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Query("SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "Invalid _mutex") {
		t.Fatalf("got %v, want Invalid _mutex error", err)
	}
}

func TestDSNKey_Spellings(t *testing.T) {
	requireCodec(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	wrong := []byte("ffffffffffffffffffffffffffffffff")
	// NOTE: subtest names must not contain raw % spellings: t.TempDir()
	// embeds the sanitized name in the path and SQLite percent-decodes
	// file: URI paths, which would redirect the open to a nonexistent
	// directory.
	spellings := []struct{ label, raw string }{
		{"upper", "_KEY"},
		{"mixed", "_Key"},
		{"pct-upper", "%5FKEY"},
		{"pct-lower", "%5fkey"},
	}
	for _, sp := range spellings {
		name := sp.raw
		t.Run("file-uri/"+sp.label, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "t.db")
			uri := "file:" + path + "?" + name + "=" + hex.EncodeToString(key)
			db, err := sql.Open("sqlite3", uri)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('s')"); err != nil {
				t.Fatalf("spelling %s: %v", name, err)
			}
			db.Close()
			// Reopen with the canonical spelling must read it.
			db2, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(key))
			if err != nil {
				t.Fatal(err)
			}
			var v string
			if err := db2.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
				t.Fatalf("reopen via canonical _key after %s: %v", name, err)
			}
			db2.Close()
			// Wrong key must fail.
			bad, err := sql.Open("sqlite3", path+"?_key="+hex.EncodeToString(wrong))
			if err != nil {
				t.Fatal(err)
			}
			if err := bad.Ping(); err == nil {
				bad.Close()
				t.Fatalf("wrong key accepted after spelling %s", name)
			}
			bad.Close()
			// Plain open must not read it.
			plain, _ := sql.Open("sqlite3", path)
			if _, err := plain.Query("SELECT v FROM t"); err == nil {
				plain.Close()
				t.Fatalf("plain open read DB keyed via %s", name)
			}
			plain.Close()
		})
	}

	t.Run("doubled-question", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "t.db")
		db, err := sql.Open("sqlite3", path+"??_key="+hex.EncodeToString(key))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
			t.Fatalf("??_key spelling: %v", err)
		}
		db.Close()
		plain, _ := sql.Open("sqlite3", path)
		if _, err := plain.Query("SELECT v FROM t"); err == nil {
			plain.Close()
			t.Fatal("plain open read DB keyed via ??_key spelling")
		}
		plain.Close()
	})

	t.Run("duplicate-across-spellings", func(t *testing.T) {
		db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+
			"?_key="+hex.EncodeToString(key)+"&_KEY="+hex.EncodeToString(key))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "Invalid _key: duplicate") {
			t.Fatalf("got %v, want duplicate-values error", err)
		}
	})
}

func TestDSNKey_MisspellingRefusedWithoutCodec(t *testing.T) {
	if codecAvailable(t) {
		t.Skip("codec available in this build; refusal path not reachable")
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_KEY="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "SQLCipher codec not available") {
		t.Fatalf("got %v, want codec-unavailable refusal for misspelled _key", err)
	}
}

func TestDSNKey_SQLiteNativeKeyParamsRejected(t *testing.T) {
	dir := t.TempDir()
	for _, q := range []string{
		"key=passphrase", "hexkey=0102", "textkey=pass", "KEY=pass", "HexKey=0102", "TEXTKEY=pass",
	} {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(dir, "t.db")+"?"+q)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "is not supported") {
			t.Fatalf("file: DSN with %q: got %v, want rejection", q, err)
		}
		db.Close()
	}
	// A benign file: parameter is untouched.
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(dir, "ok.db")+"?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("benign file: param rejected: %v", err)
	}
	db.Close()
	// Non-file DSNs never reach SQLite's URI parser: key=junk there is an
	// ordinary (ignored, stripped) query parameter, not a keying attempt.
	plain, err := sql.Open("sqlite3", filepath.Join(dir, "p.db")+"?key=junk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("plain DSN with key= param failed: %v", err)
	}
	plain.Close()
}

func TestDSNEmptyPathRejected(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	db, err := sql.Open("sqlite3", "?_key="+hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "missing database path") {
		t.Fatalf("got %v, want missing-database-path error", err)
	}
	db.Close()
	// No file may have been created anywhere with the key hex in its name.
	entries, readErr := os.ReadDir(".")
	if readErr != nil {
		t.Fatal(readErr)
	}
	_ = dir
	_ = entries
	if _, err := os.Stat("?_key=" + hex.EncodeToString(key)); err == nil {
		t.Fatal("plaintext file named after the key hex was created")
	}
}

func TestDSNKey_TooLongRejected(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db")+"?_key="+strings.Repeat("ab", 200))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Query("SELECT 1"); err == nil || !strings.Contains(err.Error(), "Invalid _key: too long") {
		t.Fatalf("got %v, want Invalid _key: too long", err)
	}
}

func TestBackupAfterCloseNoPanic(t *testing.T) {
	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "src.db")
	dstPath := filepath.Join(tempDir, "dst.db")

	src, err := sql.Open("sqlite3", srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.Exec("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')"); err != nil {
		t.Fatal(err)
	}

	dst := sql.OpenDB(&testConnector{d: &SQLiteDriver{}, dsn: dstPath})
	defer dst.Close()
	srcC := sql.OpenDB(&testConnector{d: &SQLiteDriver{}, dsn: srcPath})
	defer srcC.Close()

	// Grab the raw conns to run a backup.
	var backup *SQLiteBackup
	dstConn, err := dst.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer dstConn.Close()
	srcConn, err := srcC.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer srcConn.Close()
	err = dstConn.Raw(func(dc any) error {
		return srcConn.Raw(func(sc any) error {
			var berr error
			backup, berr = dc.(*SQLiteConn).Backup("main", sc.(*SQLiteConn), "main")
			return berr
		})
	})
	if err != nil {
		t.Fatalf("backup init: %v", err)
	}
	if _, err := backup.Step(-1); err != nil {
		t.Fatalf("backup step: %v", err)
	}
	if err := backup.Close(); err != nil {
		t.Fatalf("backup close: %v", err)
	}

	// After Close the handle is nil: these must not SIGSEGV.
	if _, err := backup.Step(1); err == nil || err.(Error).Code != ErrMisuse {
		t.Fatalf("Step after Close: got %v, want ErrMisuse", err)
	}
	if backup.Remaining() != 0 {
		t.Fatal("Remaining after Close: want 0")
	}
	if backup.PageCount() != 0 {
		t.Fatal("PageCount after Close: want 0")
	}
	// Double Close must stay safe (finish on NULL is a no-op upstream of
	// the guard as well; Close is idempotent via b.b == nil).
	if err := backup.Close(); err != nil {
		t.Logf("second close: %v", err)
	}
}
