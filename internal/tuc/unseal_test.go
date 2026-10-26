package tuc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
)

func unsealRaw(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(raw) })
	return raw
}

func sealedEnv(t *testing.T, previous *env) *env {
	t.Helper()
	e := &env{t: t, alg: "ecdsa256", db: filepath.Join(t.TempDir(), "tuc.db")}
	var err error
	if previous != nil {
		e.mp = previous.mp
		e.db = previous.db
	} else {
		e.mp, err = mp.Open()
		if err != nil {
			t.Fatal(err)
		}
	}
	e.svc, err = NewService(e.mp, "http://tuc.test", e.db, "")
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(e.svc.Handler())
	e.svc.base = e.srv.URL
	t.Cleanup(func() { e.srv.Close(); e.svc.Close() })
	return e
}

func databaseBytes(t *testing.T, e *env) []byte {
	t.Helper()
	if _, err := e.svc.st.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(e.db)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUnsealLifecycle(t *testing.T) {
	e := sealedEnv(t, nil)
	raw, wrong := unsealRaw(t), unsealRaw(t)
	before := databaseBytes(t, e)
	if err := e.svc.Unseal(raw, false); !errors.Is(err, ErrInitialize) {
		t.Fatalf("implicit initialization: %v", err)
	}
	if !bytes.Equal(before, databaseBytes(t, e)) || e.svc.State() != "sealed" {
		t.Fatal("failed initialization changed database or state")
	}
	if err := e.svc.Unseal(raw, true); err != nil {
		t.Fatal(err)
	}
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	token := e.svc.secret.Load().Token(root.ID, "admin", 0)
	before = databaseBytes(t, e)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := raw
			if i%2 != 0 {
				candidate = wrong
			}
			err := e.svc.Unseal(candidate, true)
			if i%2 == 0 && err != nil || i%2 != 0 && !errors.Is(err, ErrConflict) {
				t.Errorf("repeat %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if !bytes.Equal(before, databaseBytes(t, e)) {
		t.Fatal("repeat delivery changed database")
	}
	restarted := sealedEnv(t, e)
	if restarted.svc.State() != "sealed" {
		t.Fatal("restart retained readiness")
	}
	if err := restarted.svc.Unseal(wrong, true); !errors.Is(err, ErrSecret) {
		t.Fatalf("wrong secret replaced verifier: %v", err)
	}
	if !bytes.Equal(before, databaseBytes(t, e)) {
		t.Fatal("wrong delivery changed database")
	}
	if err := restarted.svc.Unseal(raw, false); err != nil {
		t.Fatal(err)
	}
	if restarted.svc.secret.Load().Token(root.ID, "admin", 0) != token {
		t.Fatal("token changed after restart")
	}
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restoredPath, databaseBytes(t, e), 0600); err != nil {
		t.Fatal(err)
	}
	restored := sealedEnv(t, &env{mp: e.mp, db: restoredPath})
	if err := restored.svc.Unseal(raw, false); err != nil {
		t.Fatal(err)
	}
	if restored.svc.secret.Load().Token(root.ID, "admin", 0) != token {
		t.Fatal("restored token changed")
	}
	if _, err := restarted.svc.st.db.Exec("DELETE FROM cas"); err != nil {
		t.Fatal(err)
	}
	empty := sealedEnv(t, e)
	if err := empty.svc.Unseal(wrong, true); !errors.Is(err, ErrSecret) {
		t.Fatalf("empty initialized database forgot its secret: %v", err)
	}
	if err := empty.svc.Unseal(raw, false); err != nil {
		t.Fatal(err)
	}
}

func TestUnsealDamagedVerifier(t *testing.T) {
	for _, change := range []string{"UPDATE unseal SET version=2", "UPDATE unseal SET uuid=x'00'", "UPDATE unseal SET sealed=zeroblob(64)"} {
		t.Run(change, func(t *testing.T) {
			e := sealedEnv(t, nil)
			raw := unsealRaw(t)
			if err := e.svc.Unseal(raw, true); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.st.db.Exec(change); err != nil {
				t.Fatal(err)
			}
			restarted := sealedEnv(t, e)
			before := databaseBytes(t, e)
			if err := restarted.svc.Unseal(raw, true); !errors.Is(err, ErrSecret) {
				t.Fatalf("damaged verifier: %v", err)
			}
			if !bytes.Equal(before, databaseBytes(t, e)) {
				t.Fatal("failed check rewrote verifier")
			}
		})
	}
}

func TestSealedHTTP(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "closed"}[closed], func(t *testing.T) {
			e := sealedEnv(t, nil)
			raw := unsealRaw(t)
			if err := e.svc.Unseal(raw, true); err != nil {
				t.Fatal(err)
			}
			root := e.create("/new", map[string]any{"subject": "CN=Root", "closed": closed})
			n, err := e.svc.open(root.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			crl, _, err := e.svc.CRL(n)
			if err != nil {
				t.Fatal(err)
			}
			der, err := e.svc.Issue(n, string(csr(t, e)))
			if err != nil {
				t.Fatal(err)
			}
			locked := sealedEnv(t, e)
			before := databaseBytes(t, e)
			paths := []struct {
				method, path string
				code         int
			}{
				{"GET", "/livez", 200}, {"GET", "/readyz", 503}, {"GET", "/", 503}, {"GET", "/" + root.ID, 503},
				{"GET", "/" + root.ID + ".crt", 200},
				{"GET", "/" + root.ID + ".crl", 200},
				{"GET", "/" + root.ID + "/cert/" + certID(der) + ".crt", 200},
				{"GET", "/.well-known/est/" + root.ID + "/cacerts", 200},
				{"GET", "/" + root.ID + "/ocsp/bad", 503}, {"POST", "/new", 503},
			}
			for _, suffix := range []string{"ocsp", "tsp", "pfx", "revoke", "admin", "new", "list", "closed", "issuance", "disabled", "certfnsh.asp", "justcert/certfnsh.asp", "badtoken/certfnsh.asp", "badtoken/justcert/certfnsh.asp", "badtoken/pfx", "badtoken/revoke"} {
				paths = append(paths, struct {
					method, path string
					code         int
				}{"POST", "/" + root.ID + "/" + suffix, 503})
			}
			for _, suffix := range []string{"simpleenroll", "simplereenroll"} {
				paths = append(paths, struct {
					method, path string
					code         int
				}{"POST", "/.well-known/est/" + root.ID + "/" + suffix, 503})
			}
			for _, p := range paths {
				req, _ := http.NewRequest(p.method, locked.srv.URL+p.path, strings.NewReader("malformed"))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != p.code {
					t.Fatalf("%s %s: %d %s", p.method, p.path, resp.StatusCode, body)
				}
				if p.code == 503 && (!strings.Contains(string(body), "sealed") || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Retry-After") == "") {
					t.Fatalf("missing sealed indication: %s", p.path)
				}
				if strings.HasSuffix(p.path, ".crl") && !bytes.Equal(body, crl) {
					t.Fatal("cached CRL changed")
				}
			}
			if !bytes.Equal(before, databaseBytes(t, e)) {
				t.Fatal("sealed HTTP changed database")
			}
			if _, err := e.svc.st.db.Exec("UPDATE crls SET this_update=0"); err != nil {
				t.Fatal(err)
			}
			resp, err := http.Get(locked.srv.URL + "/" + root.ID + ".crl")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 503 {
				t.Fatal("stale CRL served")
			}
			if err := locked.svc.Unseal(raw, false); err != nil {
				t.Fatal(err)
			}
			if resp, err := http.Get(locked.srv.URL + "/readyz"); err != nil {
				t.Fatal(err)
			} else {
				resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Fatal("not ready after unseal")
				}
			}
			locked.get(locked.srv.URL + "/" + root.ID)
		})
	}
}

func TestReadSecret(t *testing.T) {
	raw := unsealRaw(t)
	for _, in := range []string{EncodeSecret(raw), EncodeSecret(raw) + "\n"} {
		got, err := ReadSecret(strings.NewReader(in))
		if err != nil || !bytes.Equal(raw, got) {
			t.Fatalf("decode: %v", err)
		}
		clear(got)
	}
	for _, in := range []string{"", "wrong", strings.Repeat("A", 44), strings.Repeat("A", 257), EncodeSecret(raw) + "\nextra"} {
		if got, err := ReadSecret(strings.NewReader(in)); err == nil {
			clear(got)
			t.Fatal("invalid secret accepted")
		}
	}
}

func TestLocalDelivery(t *testing.T) {
	e := sealedEnv(t, nil)
	path := filepath.Join(t.TempDir(), "run", "unseal.sock")
	l, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.svc.ServeLocal(l) }()
	t.Cleanup(func() { l.Close(); <-done })
	if _, err := ListenLocal(path); err == nil {
		t.Fatal("replaced live socket")
	}
	for p, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("permissions: %v %v", info, err)
		}
	}
	if state, err := LocalRequest(path, nil, false); err != nil || state != "sealed" {
		t.Fatalf("status: %s %v", state, err)
	}
	raw := unsealRaw(t)
	if _, err := LocalRequest(path, raw, false); err == nil {
		t.Fatal("initialized without flag")
	}
	if _, err := LocalRequest(path, raw, true); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalRequest(path, raw, false); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalRequest(path, unsealRaw(t), true); err == nil {
		t.Fatal("conflicting delivery accepted")
	}
	if state, err := LocalRequest(path, nil, false); err != nil || state != "ready" {
		t.Fatalf("ready status: %s %v", state, err)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	conn.Write(make([]byte, 34))
	conn.CloseWrite()
	reply, _ := io.ReadAll(conn)
	conn.Close()
	if !bytes.Contains(reply, []byte("invalid-request")) {
		t.Fatal("oversized local request accepted")
	}
}

func TestSealedCRL(t *testing.T) {
	forAlgos(t, func(t *testing.T, e *env) {
		root := e.create("/new", map[string]any{"subject": "CN=Root"})
		n, err := e.svc.open(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		der, at, err := e.svc.CRL(n)
		if err != nil {
			t.Fatal(err)
		}
		locked := sealedEnv(t, e)
		status := func(want int) {
			t.Helper()
			resp, err := http.Get(locked.srv.URL + "/" + root.ID + ".crl")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("CRL status %d, want %d", resp.StatusCode, want)
			}
		}
		status(200)
		bad := bytes.Clone(der)
		bad[len(bad)-1] ^= 1
		if stored, err := e.svc.st.setCRL(root.ID, bad, 1, at, 0); err != nil || !stored {
			t.Fatal(stored, err)
		}
		status(503)
		from := time.Now().Add(-10 * 24 * time.Hour)
		tbs, err := crlTBS(n.alg, n.cert.RawSubject, n.cert.SubjectKeyId, 2, from, from.Add(time.Hour), nil)
		if err != nil {
			t.Fatal(err)
		}
		key, err := e.svc.key(n)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sign(key, n.alg, tbs)
		if err != nil {
			t.Fatal(err)
		}
		if stored, err := e.svc.st.setCRL(root.ID, signed(tbs, sig, n.alg), 2, from, 0); err != nil || !stored {
			t.Fatal(stored, err)
		}
		status(503)
		if stored, err := e.svc.st.setCRL(root.ID, der, 1, at, 0); err != nil || !stored {
			t.Fatal(stored, err)
		}
		if err := e.svc.st.setDisabled(root.ID, true); err != nil {
			t.Fatal(err)
		}
		status(503)
		resp, err := http.Get(locked.srv.URL + "/" + root.ID + ".crt")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 503 {
			t.Fatal("disabled certificate served")
		}
		if err := e.svc.st.setDisabled(root.ID, false); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.st.db.Exec("DELETE FROM crls"); err != nil {
			t.Fatal(err)
		}
		status(503)
	})
}

func TestLocalSocketSafety(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "socket")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLocal(path); err == nil {
		t.Fatal("replaced an ordinary file")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "keep" {
		t.Fatal("socket startup changed existing file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close()
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatalf("recover stale socket: %v", err)
	}
	listener.Close()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenLocal(path); err == nil {
		t.Fatal("accepted an exposed socket directory")
	}
}

func TestLocalSlowClient(t *testing.T) {
	e := sealedEnv(t, nil)
	path := filepath.Join(t.TempDir(), "run", "socket")
	listener, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.svc.ServeLocal(listener) }()
	defer func() { listener.Close(); <-done }()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(7 * time.Second))
	started := time.Now()
	response, err := io.ReadAll(conn)
	if err != nil || len(response) != 0 || time.Since(started) > 6*time.Second {
		t.Fatalf("slow delivery was not bounded: %v", err)
	}
	if state, err := LocalRequest(path, nil, false); err != nil || state != "sealed" {
		t.Fatalf("slow client broke service: %s %v", state, err)
	}
}

func TestUnsealMissingVerifier(t *testing.T) {
	for _, initialize := range []bool{false, true} {
		t.Run(fmt.Sprint(initialize), func(t *testing.T) {
			e := sealedEnv(t, nil)
			raw := unsealRaw(t)
			if err := e.svc.Unseal(raw, true); err != nil {
				t.Fatal(err)
			}
			e.create("/new", map[string]any{"subject": "CN=Root"})
			if _, err := e.svc.st.db.Exec("DELETE FROM unseal"); err != nil {
				t.Fatal(err)
			}
			restarted := sealedEnv(t, e)
			before := databaseBytes(t, e)
			if err := restarted.svc.Unseal(raw, initialize); !errors.Is(err, ErrSecret) {
				t.Fatalf("missing verifier accepted: %v", err)
			}
			if restarted.svc.State() != "sealed" || !bytes.Equal(before, databaseBytes(t, e)) {
				t.Fatal("refusal changed database or state")
			}
		})
	}
}
