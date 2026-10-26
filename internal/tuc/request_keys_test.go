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
	"strings"
	"testing"
)

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
		if _, err := e.svc.Issue(n, string(request), purpose{}); err == nil || !strings.Contains(err.Error(), "ключ CSR") {
			t.Fatalf("unsupported %T: %v", key, err)
		}
	}
}
