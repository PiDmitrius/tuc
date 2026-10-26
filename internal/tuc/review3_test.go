package tuc

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTLSCommandNameLimit(t *testing.T) {
	for _, fqdn := range []string{"example.test", strings.Repeat("a", 31) + ".example.test", strings.Repeat("a", 32) + ".example.test", strings.Repeat("a", 50) + ".example.test"} {
		for _, command := range []string{posixEnroll("/opt/cprocsp/bin/amd64", "rsa2048", true, true), posixEnroll("/opt/cprocsp/bin", "rsa2048", true, true), estEnroll("rsa2048", true, true)} {
			command = strings.NewReplacer(markFQDN, fqdn, markTUC, "http://example.test", markEST, "http://example.test/est").Replace(command)
			end := strings.Index(command, "cryptcp -createcert")
			if end < 0 {
				end = strings.Index(command, "openssl req")
			}
			out, err := exec.Command("sh", "-c", command[:end]+`printf '%s\n%s' "$NAME" "$FQDN"`).CombinedOutput()
			if err != nil {
				t.Fatal(err, string(out))
			}
			fields := strings.Split(string(out), "\n")
			if len(fields[0]) > 64 || fields[1] != fqdn || !strings.HasPrefix(fields[0], "TUC-") && !strings.HasPrefix(fields[0], fqdn+"-TUC-") {
				t.Errorf("TLS name: %q", out)
			}
			if len(fqdn) <= 44 && !strings.HasPrefix(fields[0], fqdn+"-TUC-") {
				t.Errorf("short DNS lost: %q", out)
			}
		}
	}
	if !strings.Contains(psEnroll("rsa2048", true, true), `if ($FQDN.Length + 1 + $NAME.Length -le 64) { $NAME = "$FQDN-$NAME" }`) {
		t.Error("PowerShell TLS CN has no length bound")
	}
}

func TestJSONContentType(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	for _, path := range []string{"/new", "/" + root.ID + "/admin", "/" + root.ID + "/pfx", "/" + root.ID + "/revoke"} {
		for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/json-invalid"} {
			resp, err := http.Post(e.srv.URL+path, ct, strings.NewReader(`{"subject":"CN=Unexpected"}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Errorf("%s %q: %d %s", path, ct, resp.StatusCode, body)
			}
		}
	}
	var count int
	if err := e.svc.st.db.QueryRow("SELECT count(*) FROM cas").Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected requests changed database", count, err)
	}
	resp, err := http.Post(e.srv.URL+"/new", "application/json; charset=utf-8", strings.NewReader(`{"subject":"CN=JSON"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestExpiredParentCreation(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.cert.NotAfter = time.Now().Add(-24 * time.Hour)
	if id, err := e.svc.Create(n, "ecdsa256", "CN=Child", 0, 365, false); err == nil {
		t.Fatal("created below expired parent", id)
	}
}

func TestEmptySubjectRequest(t *testing.T) {
	if err := checkName([]byte{0x30, 0}); err == nil {
		t.Error("empty Subject accepted")
	}
	e := newEnv(t)
	e.alg = "ecdsa256"
	e.subj = "/"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	request := csr(t, e)
	if cert, err := e.svc.Issue(n, string(request)); err == nil {
		t.Fatal("issued empty Subject", len(cert))
	}
}

func TestGOSTChainHint(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=GOST", "algo": "gost256"})
	child := e.create("/"+root.ID+"/new", map[string]any{"subject": "CN=RSA", "algo": "rsa2048", "token": root.Admin})
	if !bytes.Contains(e.get(child.URL), []byte(`"gostChain":true`)) {
		t.Fatal("RSA CA lost GOST ancestor requirement")
	}
}
