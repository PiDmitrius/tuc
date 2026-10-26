package tuc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRotateLinks(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "closed": true})
	issue := strings.TrimPrefix(e.enrollURL(root.ID, root.Admin), root.URL+"/")
	for _, role := range []string{"issue", "admin"} {
		old := root.Admin
		if role == "issue" {
			old = issue
		}
		code, body := e.post("/"+root.ID+"/rotate", map[string]any{"token": root.Admin, "role": role})
		if code != 200 {
			t.Fatal(code, string(body))
		}
		var result struct{ Token string }
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if result.Token == old || !e.svc.checkToken(root.ID, role, result.Token) || e.svc.checkToken(root.ID, role, old) {
			t.Fatal("rotation failed", role)
		}
		if role == "issue" {
			if code, _ := e.post("/"+root.ID+"/"+old+"/pfx", map[string]any{"name": "old", "password": "test"}); code != 403 {
				t.Fatal("old issue link", code)
			}
			if code, _ := e.post("/"+root.ID+"/"+result.Token+"/pfx", map[string]any{"name": "new", "password": "test"}); code != 200 {
				t.Fatal("new issue link", code)
			}
			for _, closed := range []bool{true, false} {
				if code, _ := e.post("/"+root.ID+"/closed", map[string]any{"token": root.Admin, "closed": closed}); code != 200 {
					t.Fatal(code)
				}
				req, _ := http.NewRequest("POST", e.srv.URL+"/.well-known/est/"+root.ID+"/simpleenroll", nil)
				req.SetBasicAuth("tuc", old)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 401 {
					t.Fatal("old EST token", closed, resp.StatusCode)
				}
			}
			if !e.svc.checkToken(root.ID, "admin", root.Admin) {
				t.Fatal("issue rotation changed admin")
			}
		} else {
			if code, _ := e.post("/"+root.ID+"/admin", map[string]any{"token": old}); code != 403 {
				t.Fatal("old admin link", code)
			}
			root.Admin = result.Token
		}
	}
	st, err := openStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	gen, err := st.tokenGeneration(root.ID, "admin", false)
	if err != nil || gen != 1 {
		t.Fatal("lost generation", gen, err)
	}
}

func TestTokenGenerationMigration(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	issue := e.svc.token(root.ID, "issue")
	for _, col := range []string{"admin_gen", "issue_gen"} {
		if _, err := e.svc.st.db.Exec("ALTER TABLE cas DROP COLUMN " + col); err != nil {
			t.Fatal(err)
		}
	}
	st, err := openStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	for role, want := range map[string]string{"admin": root.Admin, "issue": issue} {
		generation, err := st.tokenGeneration(root.ID, role, false)
		if err != nil || generation != 0 || e.svc.secret.Load().Token(root.ID, role, generation) != want {
			t.Fatal("migration changed token", role, err)
		}
	}
}

func TestUnsupportedRequestKeys(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{rsaKey, ecKey, edKey} {
		request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Issue(n, string(request)); err == nil || !strings.Contains(err.Error(), "ключ CSR") {
			t.Fatalf("unsupported %T: %v", key, err)
		}
	}
}

func TestCACreationStart(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "from": -10, "days": 5, "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	id, err := e.svc.Create(n, "ecdsa256", "CN=Historic", -8, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.open(id)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if !child.cert.NotAfter.Equal(n.cert.NotAfter) || child.cert.NotBefore.Before(n.cert.NotBefore) {
		t.Fatal("period not clipped")
	}
	if _, err := e.svc.Create(n, "ecdsa256", "CN=Outside", 0, 10, false); err == nil {
		t.Fatal("accepted non-overlapping period")
	}
	if !child.cert.NotBefore.Before(time.Now()) {
		t.Fatal("lost start offset")
	}
}
