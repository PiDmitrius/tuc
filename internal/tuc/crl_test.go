package tuc

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

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
