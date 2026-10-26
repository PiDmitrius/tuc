package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
	"github.com/PiDmitrius/tuc/internal/tuc"
)

func TestCLILink(t *testing.T) {
	ctx, err := mp.Open()
	if err != nil {
		t.Fatal(err)
	}
	svc, err := tuc.NewService(ctx, "http://tuc.test", filepath.Join(t.TempDir(), "db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	socket := filepath.Join(t.TempDir(), "run", "socket")
	listener, err := tuc.ListenLocal(socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- svc.ServeLocal(listener) }()
	defer func() { listener.Close(); <-done }()
	if out, err := command("link", "-socket", socket, strings.Repeat("A", 40)).CombinedOutput(); err == nil || !strings.Contains(string(out), "sealed") {
		t.Fatal("sealed link", err, string(out))
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	secret, err := tuc.NewSecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Unseal(raw, true); err != nil {
		t.Fatal(err)
	}
	id, err := svc.Create(nil, "ecdsa256", "CN=Operator", 0, 365, false)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	old := secret.Token(id, "admin", 0)
	defer secret.Clear()
	for i := 0; i < 2; i++ {
		out, err := command("link", "-socket", socket, strings.ToLower(id)).CombinedOutput()
		if err != nil {
			t.Fatal(err, string(out))
		}
		link := strings.TrimSpace(string(out))
		prefix := "http://tuc.test/" + id + "#token="
		if !strings.HasPrefix(link, prefix) {
			t.Fatal("link output", link)
		}
		token := strings.TrimPrefix(link, prefix)
		for key, want := range map[string]int{old: 403, token: 200} {
			resp, err := http.Post(srv.URL+"/"+id+"/admin", "application/json", strings.NewReader(`{"token":"`+key+`"}`))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatal("token status", resp.StatusCode, want)
			}
		}
		old = token
	}
}

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
