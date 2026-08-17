// Copyright (C) 2024 0xCarbon.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

//go:build cgo
// +build cgo

package sqlite3

import (
	"context"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// benchKey is fixed 32-byte raw test key material (not secret).
var benchKey = []byte("0123456789abcdef0123456789abcdef")

func benchCodecAvailable(b *testing.B) bool {
	b.Helper()
	conn, err := (&SQLiteDriver{}).Open(":memory:")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	rows, err := conn.(*SQLiteConn).query(context.Background(), "PRAGMA cipher_version", nil)
	if err != nil {
		return false
	}
	dest := make([]driver.Value, 1)
	ok := rows.Next(dest) == nil
	drainRows(b, rows)
	return ok
}

func requireCodecB(b *testing.B) {
	b.Helper()
	if !benchCodecAvailable(b) {
		b.Skip("no SQLCipher codec in this build (plain SQLite?)")
	}
}

// benchQueryRows runs one query through the raw conn (no database/sql pool
// overhead) and drains the result.
func benchQueryRows(tb testing.TB, c *SQLiteConn, query string) error {
	tb.Helper()
	rows, err := c.query(context.Background(), query, nil)
	if err != nil {
		return err
	}
	dest := make([]driver.Value, len(rows.Columns()))
	for {
		if err := rows.Next(dest); err != nil {
			break
		}
	}
	rows.Close()
	return nil
}

// benchPopulate fills a conn with a table of n rows of ~60 byte payloads.
func benchPopulate(tb testing.TB, c *SQLiteConn, n int) {
	tb.Helper()
	// The benchmark framework re-invokes a benchmark function while scaling
	// b.N, so setup must be idempotent on the same file. Note: separate
	// statements, because the Query path only executes the LAST statement of
	// a multi-statement string (inherited upstream behavior).
	if err := benchQueryRows(tb, c, "DROP TABLE IF EXISTS t"); err != nil {
		tb.Fatal(err)
	}
	if err := benchQueryRows(tb, c, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"); err != nil {
		tb.Fatal(err)
	}
	var sb strings.Builder
	const batch = 200
	for start := 0; start < n; start += batch {
		end := start + batch
		if end > n {
			end = n
		}
		sb.Reset()
		sb.WriteString("INSERT INTO t (v) VALUES ")
		for i := start; i < end; i++ {
			if i > start {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "('%060d')", i)
		}
		if err := benchQueryRows(tb, c, sb.String()); err != nil {
			tb.Fatal(err)
		}
	}
}

// BenchmarkKeyedOpenClose measures the full driver open+close cycle on an
// existing file database: plain vs keyed (driver field) vs keyed (_key DSN),
// each with and without one table scan that forces page decryption (and thus
// SQLCipher key derivation on first access).
func BenchmarkKeyedOpenClose(b *testing.B) {
	requireCodecB(b)
	dir := b.TempDir()

	cases := []struct {
		name  string
		keyed bool
		dsn   bool
		query bool
	}{
		{"plain", false, false, false},
		{"plain_query", false, false, true},
		{"keyed_field", true, false, false},
		{"keyed_field_query", true, false, true},
		{"keyed_dsn", true, true, false},
		{"keyed_dsn_query", true, true, true},
		// A non-raw-key string literal takes the PBKDF2 key-derivation path
		// (SQLCipher default 256000 iterations): the slowest possible keyed
		// open. Raw keys (x'...' form) skip the KDF.
		{"keyed_passphrase_query", false, false, true},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			path := filepath.Join(dir, tc.name+".db")
			d := &SQLiteDriver{}
			if tc.keyed {
				d.EncryptionKeyBytes = benchKey
			}
			if tc.name == "keyed_passphrase_query" {
				d.EncryptionKey = "'benchmark-passphrase'"
			}
			conn, err := d.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			benchPopulate(b, conn.(*SQLiteConn), 100)
			if err := conn.Close(); err != nil {
				b.Fatal(err)
			}

			dsn := path
			if tc.dsn {
				dsn = path + "?_key=" + hex.EncodeToString(benchKey)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				d := &SQLiteDriver{}
				if tc.keyed && !tc.dsn {
					d.EncryptionKeyBytes = benchKey
				}
				if tc.name == "keyed_passphrase_query" {
					d.EncryptionKey = "'benchmark-passphrase'"
				}
				conn, err := d.Open(dsn)
				if err != nil {
					b.Fatal(err)
				}
				if tc.query {
					if err := benchQueryRows(b, conn.(*SQLiteConn), "SELECT count(*) FROM t"); err != nil {
						b.Fatal(err)
					}
				}
				if err := conn.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWrongKeyFailure measures the cost of the wrong-key failure path:
// open succeeds (PRAGMA key is deferred), the first table access fails with
// ErrNotADB, then close. Compared against the correct-key happy path.
// through the same query path.
// from crypto cost. Relies on the scratch-only zz_exechook.go helpers.
// (rekey/copy) and to a plaintext destination (decrypt).
func BenchmarkSQLCipherExport(b *testing.B) {
	requireCodecB(b)
	dir := b.TempDir()
	srcPath := filepath.Join(dir, "src.db")
	destPath := filepath.Join(dir, "dest.db")
	const rowCount = 1000

	d := &SQLiteDriver{EncryptionKeyBytes: benchKey}
	src, err := d.Open(srcPath)
	if err != nil {
		b.Fatal(err)
	}
	defer src.Close()
	benchPopulate(b, src.(*SQLiteConn), rowCount)

	keyHex := hex.EncodeToString(benchKey)

	cases := []struct {
		name   string
		attach string
	}{
		{"to_encrypted", fmt.Sprintf("ATTACH DATABASE '%s' AS dst KEY \"x'%s'\";", destPath, keyHex)},
		{"to_plain", fmt.Sprintf("ATTACH DATABASE '%s' AS dst;", destPath)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				os.Remove(destPath)
				b.StartTimer()
				if err := benchQueryRows(b, src.(*SQLiteConn), tc.attach); err != nil {
					b.Fatal(err)
				}
				if err := benchQueryRows(b, src.(*SQLiteConn), "SELECT sqlcipher_export('dst');"); err != nil {
					b.Fatal(err)
				}
				if err := benchQueryRows(b, src.(*SQLiteConn), "DETACH DATABASE dst;"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkBackupCipher measures the online backup API (backup.go) on file
// databases: plain->plain baseline, keyed->keyed (encrypted copy), and
// keyed->plain (decrypting copy).
func BenchmarkBackupCipher(b *testing.B) {
	requireCodecB(b)
	dir := b.TempDir()
	const rowCount = 1000

	cases := []struct {
		name      string
		srcKeyed  bool
		destKeyed bool
		refused   bool
	}{
		{"plain_to_plain", false, false, false},
		{"keyed_to_keyed", true, true, false},
		// SQLCipher refuses the backup API between differently-coded
		// databases; measure the refusal cost (decrypt must go through
		// ATTACH + sqlcipher_export instead).
		{"keyed_to_plain_refused", true, false, true},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			srcPath := filepath.Join(dir, tc.name+"_src.db")
			destPath := filepath.Join(dir, tc.name+"_dest.db")

			srcDriver := &SQLiteDriver{}
			if tc.srcKeyed {
				srcDriver.EncryptionKeyBytes = benchKey
			}
			src, err := srcDriver.Open(srcPath)
			if err != nil {
				b.Fatal(err)
			}
			benchPopulate(b, src.(*SQLiteConn), rowCount)

			destDriver := &SQLiteDriver{}
			if tc.destKeyed {
				destDriver.EncryptionKeyBytes = benchKey
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				os.Remove(destPath)
				dest, err := destDriver.Open(destPath)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				bk, err := dest.(*SQLiteConn).Backup("main", src.(*SQLiteConn), "main")
				if tc.refused {
					if err == nil {
						bk.Finish()
						b.Fatal("keyed->plain backup unexpectedly succeeded")
					}
					if !strings.Contains(err.Error(), "not supported") {
						b.Fatalf("got %v, want backup-not-supported refusal", err)
					}
					b.StopTimer()
					if err := dest.Close(); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
				for {
					done, err := bk.Step(-1)
					if err != nil {
						b.Fatal(err)
					}
					if done {
						break
					}
				}
				if err := bk.Finish(); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := dest.Close(); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}

// BenchmarkStmtCacheKeyed measures the per-query cost of the statement cache
// hit path on a keyed (encrypted) file connection vs a plain one; each query
// is a rowid lookup on a small table so page decryption is in the timed path.
func BenchmarkStmtCacheKeyed(b *testing.B) {
	requireCodecB(b)
	dir := b.TempDir()

	for _, keyed := range []bool{false, true} {
		for _, cold := range []bool{false, true} {
			name := "plain"
			if keyed {
				name = "keyed"
			}
			if cold {
				name += "_cold"
			}
			d := &SQLiteDriver{}
			if keyed {
				d.EncryptionKeyBytes = benchKey
			}
			b.Run(name, func(b *testing.B) {
				path := filepath.Join(dir, name+".db")
				setup, err := d.Open(path)
				if err != nil {
					b.Fatal(err)
				}
				benchPopulate(b, setup.(*SQLiteConn), 100)
				if err := setup.Close(); err != nil {
					b.Fatal(err)
				}

				// Bench connection: same key (field) plus stmt cache via DSN.
				conn, err := d.Open(path + "?_stmt_cache_size=4")
				if err != nil {
					b.Fatal(err)
				}
				defer conn.Close()
				c := conn.(*SQLiteConn)
				if cold {
					// Shrink SQLite's page cache so lookups re-fetch pages
					// from the OS: on keyed connections each fetch decrypts.
					if err := benchQueryRows(b, c, "PRAGMA cache_size = 2"); err != nil {
						b.Fatal(err)
					}
				}

				queries := make([]string, 4)
				for i := range queries {
					queries[i] = fmt.Sprintf("SELECT v FROM t WHERE id = %d", i+1)
				}
				for _, q := range queries {
					if err := benchQueryRows(b, c, q); err != nil {
						b.Fatal(err)
					}
				}

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := benchQueryRows(b, c, queries[i%len(queries)]); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
