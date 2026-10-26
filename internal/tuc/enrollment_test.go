package tuc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	b64 "encoding/base64"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func requestWithExtensions(t *testing.T, exts []pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf"}, ExtraExtensions: exts}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEnrollmentTemplates(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	marshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	eku := func(oids ...asn1.ObjectIdentifier) pkix.Extension {
		return pkix.Extension{Id: oidEKU, Critical: true, Value: marshal(oids)}
	}
	san := func(names ...asn1.RawValue) pkix.Extension { return pkix.Extension{Id: oidSAN, Value: marshal(names)} }
	dns := func(s string) asn1.RawValue { return asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(s)} }
	for _, c := range []struct {
		name     string
		exts     []pkix.Extension
		dns      []string
		tls, bad bool
	}{
		{name: "user"},
		{name: "service roles ignored", exts: []pkix.Extension{eku(oidOCSPSigning, oidTimeStamping, asn1.ObjectIdentifier{2, 5, 29, 37, 0})}},
		{name: "SAN alone ignored", exts: []pkix.Extension{san(dns("leaf.example"))}},
		{name: "unknown extensions ignored", exts: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0xff}}, {Id: oidKeyUsage, Value: []byte{0xff}}, {Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: marshal(struct{ CA bool }{true})}}},
		{name: "server", exts: []pkix.Extension{eku(oidServerAuth), san(dns("leaf.example"))}, dns: []string{"leaf.example"}, tls: true},
		{name: "client and forbidden roles", exts: []pkix.Extension{eku(oidClientAuth, oidOCSPSigning, oidTimeStamping, asn1.ObjectIdentifier{2, 5, 29, 37, 0}), san(dns("LEAF.example"), dns("leaf.example"), dns("other.example"), asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte{127, 0, 0, 1}})}, dns: []string{"leaf.example", "other.example"}, tls: true},
		{name: "TLS without DNS", exts: []pkix.Extension{eku(oidServerAuth)}, bad: true},
		{name: "TLS with only IP", exts: []pkix.Extension{eku(oidServerAuth), san(asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte{127, 0, 0, 1}})}, bad: true},
		{name: "invalid DNS", exts: []pkix.Extension{eku(oidServerAuth), san(dns("bad_name"))}, bad: true},
		{name: "wildcard", exts: []pkix.Extension{eku(oidServerAuth), san(dns("*.example"))}, bad: true},
		{name: "trailing dot", exts: []pkix.Extension{eku(oidServerAuth), san(dns("leaf.example."))}, bad: true},
		{name: "non-ASCII DNS", exts: []pkix.Extension{eku(oidServerAuth), san(dns("K.example"))}, bad: true},
		{name: "long label", exts: []pkix.Extension{eku(oidServerAuth), san(dns(strings.Repeat("a", 64) + ".example"))}, bad: true},
		{name: "bad SAN", exts: []pkix.Extension{eku(oidServerAuth), {Id: oidSAN, Value: []byte{0xff}}}, bad: true},
		{name: "bad EKU", exts: []pkix.Extension{{Id: oidEKU, Value: []byte{0xff}}}, bad: true},
		{name: "empty EKU", exts: []pkix.Extension{eku()}, bad: true},
		{name: "duplicate SAN", exts: []pkix.Extension{eku(oidServerAuth), san(dns("a.example")), san(dns("b.example"))}, bad: true},
		{name: "duplicate EKU", exts: []pkix.Extension{eku(oidServerAuth), eku(oidClientAuth), san(dns("a.example"))}, bad: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			der, err := e.svc.Issue(n, string(requestWithExtensions(t, c.exts)))
			if c.bad {
				if err == nil {
					t.Fatal("ambiguous or malformed hints accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject.CommonName != "leaf" || cert.IsCA || !slices.Equal(cert.DNSNames, c.dns) || len(cert.IPAddresses) != 0 || len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 {
				t.Fatalf("unexpected certificate: subject=%s CA=%v DNS=%v IP=%v EKU=%v unknown=%v critical=%v", cert.Subject, cert.IsCA, cert.DNSNames, cert.IPAddresses, cert.ExtKeyUsage, cert.UnknownExtKeyUsage, cert.UnhandledCriticalExtensions)
			}
			wantEKU := []x509.ExtKeyUsage(nil)
			if c.tls {
				wantEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			}
			if !slices.Equal(cert.ExtKeyUsage, wantEKU) {
				t.Fatalf("EKU %v, want %v", cert.ExtKeyUsage, wantEKU)
			}
			for _, ext := range cert.Extensions {
				if !ext.Id.Equal(oidKeyUsage) && !ext.Id.Equal(oidSAN) && !ext.Id.Equal(oidEKU) && !ext.Id.Equal(oidSKI) && !ext.Id.Equal(oidAKI) && !ext.Id.Equal(oidAIA) && !ext.Id.Equal(oidCDP) {
					t.Fatalf("unexpected extension %v", ext.Id)
				}
			}
		})
	}
}

func TestRequestSignature(t *testing.T) {
	forAlgos(t, func(t *testing.T, e *env) {
		root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
		der, err := unarmor(csr(t, e))
		if err != nil {
			t.Fatal(err)
		}
		changedSubject := bytes.Replace(der, []byte("leaf"), []byte("leag"), 1)
		changedSig := bytes.Clone(der)
		changedSig[len(changedSig)-1] ^= 1
		for _, bad := range [][]byte{changedSig, changedSubject, append(bytes.Clone(der), 0)} {
			for _, path := range []string{"/.well-known/est/" + root.ID + "/simpleenroll", "/.well-known/est/" + root.ID + "/simplereenroll", "/" + root.ID + "/certfnsh.asp"} {
				body, contentType := bad, "application/pkcs10"
				if strings.HasSuffix(path, ".asp") {
					body = []byte(url.Values{"CertRequest": {b64.StdEncoding.EncodeToString(bad)}}.Encode())
					contentType = "application/x-www-form-urlencoded"
				}
				resp, err := http.Post(e.srv.URL+path, contentType, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				out, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if !strings.Contains(string(out), "подпись CSR") {
					t.Fatalf("%s accepted invalid request or gave unclear error: %d %s", path, resp.StatusCode, out)
				}
			}
		}
		n, err := e.svc.open(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		var count int
		if err := e.svc.st.db.QueryRow("SELECT count(*) FROM certs WHERE ca = ?", root.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rejected request changed database: count=%d err=%v", count, err)
		}
		if _, err := e.svc.Issue(n, string(der)); err != nil {
			t.Fatalf("valid request: %v", err)
		}
	})
}
