package main

import (
	"crypto/rand"
	"github.com/PiDmitrius/tuc/internal/mp"
	"github.com/PiDmitrius/tuc/internal/tuc"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
