package main

import (
	"context"
	"database/sql"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupContinuousWrites(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "live.db"), filepath.Join(dir, "copy.db")
	db, err := sql.Open("sqlite3", source+"?_journal_mode=WAL&_busy_timeout=1000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE counter (n INTEGER); INSERT INTO counter VALUES(0); CREATE TABLE filler (data BLOB); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<128) INSERT INTO filler SELECT zeroblob(131072) FROM n"); err != nil {
		t.Fatal(err)
	}
	stop, done, started := make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		first := true
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if _, err := db.Exec("UPDATE counter SET n=n+1"); err != nil {
				done <- err
				return
			}
			if first {
				close(started)
				first = false
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base := command("backup", "-db", source, target)
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = base.Env
	out, err := cmd.CombinedOutput()
	close(stop)
	writerErr := <-done
	if err != nil || writerErr != nil {
		t.Fatal("backup under writes", err, writerErr, string(out))
	}
	copyDB, err := sql.Open("sqlite3", target)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var count int
	var check string
	if err := copyDB.QueryRow("SELECT count(*) FROM filler").Scan(&count); err != nil || count != 128 {
		t.Fatal("incomplete copy", count, err)
	}
	if err := copyDB.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		t.Fatal(check, err)
	}
	var writes int
	db.QueryRow("SELECT n FROM counter").Scan(&writes)
	if writes < 2 {
		t.Fatal("writer did not run during backup")
	}
}
