package tuc

import (
	"crypto/x509"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishURLs(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	if e.svc.publicationURL("id") != e.svc.caURL("id") {
		t.Fatal("default publication differs from base")
	}
	s, err := NewService(e.mp, "https://pages.example", filepath.Join(t.TempDir(), "pub.db"), "http://publish.example/")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Unseal(unsealRaw(t), true); err != nil {
		t.Fatal(err)
	}
	root, err := s.Create(nil, "ecdsa256", "CN=Root", 0, 3650, false)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := s.open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	child, err := s.Create(parent, "rsa2048", "CN=Child", 0, 365, false)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.open(child)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	check := func(der []byte, id string) {
		t.Helper()
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.IssuingCertificateURL) != 1 || c.IssuingCertificateURL[0] != "http://publish.example/"+id+".crt" || len(c.CRLDistributionPoints) != 1 || c.CRLDistributionPoints[0] != "http://publish.example/"+id+".crl" || len(c.OCSPServer) != 1 || c.OCSPServer[0] != "http://publish.example/"+id+"/ocsp" {
			t.Fatalf("publication URLs: %v %v %v", c.IssuingCertificateURL, c.CRLDistributionPoints, c.OCSPServer)
		}
	}
	check(n.der, root)
	leaf, err := s.Issue(n, string(csr(t, e)))
	if err != nil {
		t.Fatal(err)
	}
	check(leaf, child)
	for _, svc := range []service{serviceTSA, serviceOCSP} {
		key, der, err := s.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		if svc == serviceTSA {
			check(der, child)
		} else {
			c, err := x509.ParseCertificate(der)
			if err != nil || len(c.IssuingCertificateURL) != 1 || c.IssuingCertificateURL[0] != "http://publish.example/"+child+".crt" {
				t.Fatal("responder AIA", err)
			}
		}
	}
	req := httptest.NewRequest("GET", "/"+child, nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, want := range []string{"https://pages.example/" + child, "https://pages.example/.well-known/est/" + child} {
		if !strings.Contains(w.Body.String(), want) {
			t.Error("page URL missing", want)
		}
	}
	if strings.Contains(w.Body.String(), "http://publish.example") {
		t.Error("publication URL replaced page commands")
	}
}
