package tuc

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIndependentAdmin(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	child := e.create("/"+root.ID+"/new", map[string]any{"subject": "CN=Child", "token": root.Admin})
	for _, path := range []string{"admin", "closed", "issuance", "new", "revoke", "rotate", "list", "disabled"} {
		if code, _ := e.post("/"+child.ID+"/"+path, map[string]any{"token": root.Admin}); code != 403 {
			t.Errorf("ancestor access %s: %d", path, code)
		}
	}
	if code, _ := e.post("/"+child.ID+"/admin", map[string]any{"token": child.Admin}); code != 200 {
		t.Fatal(code)
	}
}

func TestServiceRevocation(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, svc := range []service{serviceTSA, serviceOCSP} {
		key, old, err := e.svc.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		if code, _ := e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(old)}); code != 200 {
			t.Fatal(code)
		}
		key, fresh, err := e.svc.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		if bytes.Equal(old, fresh) {
			t.Fatal("reused revoked service certificate", svc)
		}
		if at, err := e.svc.st.revokedAt(n.id, certID(fresh)); err != nil || at != nil {
			t.Fatal("replacement is revoked", err)
		}
	}
}

func TestCACreationDays(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	for _, path := range []string{"/new", "/" + root.ID + "/new"} {
		for _, days := range []int{-1, 36501, 2932897, int(^uint(0) >> 1)} {
			if code, body := e.post(path, map[string]any{"token": root.Admin, "subject": "CN=Bounds", "days": days}); code != 400 || !strings.Contains(string(body), "36500") {
				t.Errorf("days %d: %d %s", days, code, body)
			}
		}
	}
}

func TestCRLConditionalRevocation(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	der := e.get(root.URL + ".crt")
	for i := 0; i < 2; i++ {
		leaf, err := e.enroll(root.URL, der)
		if err != nil {
			t.Fatal(err)
		}
		e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(leaf)})
		resp, err := http.Get(root.URL + ".crl")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tag := resp.Header.Get("ETag")
		if tag == "" || resp.Header.Get("Last-Modified") != "" {
			t.Fatal("CRL must use a number ETag instead of Last-Modified")
		}
		request, _ := http.NewRequest("GET", root.URL+".crl", nil)
		request.Header.Set("If-None-Match", tag)
		same, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		same.Body.Close()
		if same.StatusCode != 304 {
			t.Fatal("same CRL not cached", same.StatusCode)
		}
		next, err := e.enroll(root.URL, der)
		if err != nil {
			t.Fatal(err)
		}
		e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(next)})
		request.Header.Set("If-Modified-Since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
		changed, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		current, _ := io.ReadAll(changed.Body)
		changed.Body.Close()
		if changed.StatusCode != 200 || changed.Header.Get("ETag") == tag || bytes.Equal(current, body) {
			t.Fatal("changed CRL hidden by a conditional response")
		}
	}
}

func TestCRLConcurrentRevocation(t *testing.T) {
	e := newEnv(t)
	e.alg = "rsa4096"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	e.alg = "ecdsa256"
	rootDER := e.get(root.URL + ".crt")
	operator, err := openStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	defer operator.db.Close()
	for i := 0; i < 40; i++ {
		leaf, err := e.enroll(root.URL, rootDER)
		if err != nil {
			t.Fatal(err)
		}
		e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(leaf)})
		second, err := e.enroll(root.URL, rootDER)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(root.URL + ".crl")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		time.Sleep(time.Duration(i%5) * time.Millisecond)
		if i%2 == 0 {
			e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(second)})
		} else if err := operator.revoke(root.ID, certID(second)); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		crl, err := x509.ParseRevocationList(e.get(root.URL + ".crl"))
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(second)
		found := false
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("concurrent revocation missing at iteration %d", i)
		}
	}
}

func TestCryptoProDN(t *testing.T) {
	for _, test := range []struct{ name, dn string }{
		{`Plain User`, `CN=Plain User`}, {`Probe, Person`, `CN="Probe, Person"`},
		{`a"b`, `CN="a""b"`}, {`a\b`, `CN=a\b`}, {` +;=<># `, `CN=" +;=<># "`}, {`a'b`, `CN=a'b`},
	} {
		name := test.name
		for _, script := range []string{posixVerify("/unused"), strings.ReplaceAll(posixRevoke("/unused"), markTUC, "http://tuc.test")} {
			dir := t.TempDir()
			stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGS\"\necho 'Certificate chain: Verified successfully'\n"
			for _, tool := range []string{"cryptcp", "certmgr", "curl"} {
				if err := os.WriteFile(filepath.Join(dir, tool), []byte(stub), 0700); err != nil {
					t.Fatal(err)
				}
			}
			args := filepath.Join(dir, "args")
			// curl leaves the signing command's argument capture intact.
			os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\nexit 0\n"), 0700)
			cmd := exec.Command("sh", "-ec", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "NAME="+name, "PATH="+dir+":"+os.Getenv("PATH"), "ARGS="+args)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v %s", err, out)
			}
			argv, err := os.ReadFile(args)
			want := "-dn\n" + test.dn + "\n"
			if err != nil || !strings.Contains(string(argv), want) {
				t.Fatalf("DN for %q: %s (%v)", name, argv, err)
			}
		}
	}
	for _, script := range []string{psVerify(), psRevoke()} {
		if !strings.Contains(script, `.Replace('"', '""')`) || strings.Contains(script, `-dn "CN=$NAME"`) || !strings.Contains(script, "-dn $DN") {
			t.Fatal("PowerShell DN escaping absent")
		}
	}
}

func TestFutureCACRLCache(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Future", "algo": "ecdsa256", "from": 1})
	if until := time.Until(time.Now().UTC().Truncate(time.Hour).Add(time.Hour)); until < 3*time.Second {
		time.Sleep(until)
	}
	var tag string
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}
		resp, err := http.Get(root.URL + ".crl")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatal(resp.StatusCode, err, string(body))
		}
		current := resp.Header.Get("ETag")
		if current == "" || i > 0 && current != tag {
			t.Fatalf("request %d: CRL ETag changed from %q to %q", i+1, tag, current)
		}
		tag = current
	}
}
