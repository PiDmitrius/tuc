package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIBackup(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "live.db"), filepath.Join(dir, "copy.db")
	db, err := sql.Open("sqlite3", source+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE entries (value TEXT); INSERT INTO entries VALUES ('committed')"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO entries VALUES ('uncommitted')"); err != nil {
		t.Fatal(err)
	}
	if out, err := command("backup", "-db", source, target).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	copyDB, err := sql.Open("sqlite3", target)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var value string
	err = copyDB.QueryRow("SELECT count(*), value FROM entries").Scan(&count, &value)
	copyDB.Close()
	if err != nil || count != 1 || value != "committed" {
		t.Fatalf("snapshot: %d %q %v", count, value, err)
	}
	original, _ := os.ReadFile(target)
	if out, err := command("backup", "-db", source, target).CombinedOutput(); err == nil || !strings.Contains(string(out), "destination already exists") {
		t.Fatalf("overwrite: %v %s", err, out)
	}
	after, _ := os.ReadFile(target)
	if string(original) != string(after) {
		t.Fatal("destination changed")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		name := filepath.Join(dir, "occupied"+suffix)
		if err := os.WriteFile(name, []byte("occupied"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := backup(source, filepath.Join(dir, "occupied")); err == nil {
			t.Fatal("accepted sidecar", suffix)
		}
		os.Remove(name)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "missing"), link); err != nil {
		t.Fatal(err)
	}
	if err := backup(source, link); err == nil {
		t.Fatal("accepted symlink")
	}
	for _, bad := range []string{filepath.Join(dir, "missing.db"), filepath.Join(dir, "garbage.db")} {
		if strings.HasSuffix(bad, "garbage.db") {
			os.WriteFile(bad, []byte("not SQLite"), 0600)
		}
		dest := filepath.Join(dir, "failed.db")
		if out, err := command("backup", "-db", bad, dest).CombinedOutput(); err == nil || !strings.Contains(string(out), "backup:") {
			t.Fatalf("invalid source: %v %s", err, out)
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatal("failed backup published", err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".tuc-backup-*"))
	if len(matches) != 0 {
		t.Fatal("temporary files remain", matches)
	}
}
