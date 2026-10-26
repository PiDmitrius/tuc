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
	server, client, both := purpose{server: true}, purpose{client: true}, purpose{true, true}
	ip := asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte{127, 0, 0, 1}}
	for _, c := range []struct {
		name string
		exts []pkix.Extension
		u    purpose
		dns  []string
		bad  bool
	}{
		{name: "user"},
		{name: "requested EKU ignored", exts: []pkix.Extension{eku(oidServerAuth, oidOCSPSigning, asn1.ObjectIdentifier{2, 5, 29, 37, 0}), san(dns("leaf.example"))}},
		{name: "malformed EKU ignored", exts: []pkix.Extension{{Id: oidEKU, Value: []byte{0xff}}, eku()}},
		{name: "unknown extensions ignored", exts: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0xff}}, {Id: oidKeyUsage, Value: []byte{0xff}}, {Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: marshal(struct{ CA bool }{true})}}},
		{name: "server", exts: []pkix.Extension{eku(oidClientAuth), san(dns("leaf.example"))}, u: server, dns: []string{"leaf.example"}},
		{name: "client without DNS", u: client},
		{name: "client with DNS", exts: []pkix.Extension{san(dns("leaf.example"))}, u: client, dns: []string{"leaf.example"}},
		{name: "server and client", exts: []pkix.Extension{san(dns("LEAF.example"), dns("leaf.example"), dns("other.example"), ip)}, u: both, dns: []string{"leaf.example", "other.example"}},
		{name: "server without DNS", u: server, bad: true},
		{name: "server with only IP", exts: []pkix.Extension{san(ip)}, u: server, bad: true},
		{name: "invalid DNS", exts: []pkix.Extension{san(dns("bad_name"))}, u: client, bad: true},
		{name: "wildcard", exts: []pkix.Extension{san(dns("*.example"))}, u: server, bad: true},
		{name: "trailing dot", exts: []pkix.Extension{san(dns("leaf.example."))}, u: server, bad: true},
		{name: "non-ASCII DNS", exts: []pkix.Extension{san(dns("\u212a.example"))}, u: server, bad: true},
		{name: "long label", exts: []pkix.Extension{san(dns(strings.Repeat("a", 64) + ".example"))}, u: server, bad: true},
		{name: "bad SAN", exts: []pkix.Extension{{Id: oidSAN, Value: []byte{0xff}}}, u: server, bad: true},
		{name: "duplicate SAN", exts: []pkix.Extension{san(dns("a.example")), san(dns("b.example"))}, bad: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			der, err := e.svc.Issue(n, string(requestWithExtensions(t, c.exts)), c.u)
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
			var wantEKU []x509.ExtKeyUsage
			if c.u.server {
				wantEKU = append(wantEKU, x509.ExtKeyUsageServerAuth)
			}
			if c.u.client {
				wantEKU = append(wantEKU, x509.ExtKeyUsageClientAuth)
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
		if _, err := e.svc.Issue(n, string(der), purpose{}); err != nil {
			t.Fatalf("valid request: %v", err)
		}
	})
}

func TestEnrollPaths(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	for _, c := range []struct{ path, want string }{
		{"", "sPKCS7"}, {"/justcert", "sPKCS7"}, {"/tls-client", "sPKCS7"},
		{"/tls-client/tls-server/justcert", "для TLS-сервера требуется DNS-имя"}, {"/justcert/tls-server", "для TLS-сервера требуется DNS-имя"},
		{"/tls-client/tls-client", "повторная опция"}, {"/tls", "not the issue token"},
	} {
		body := url.Values{"CertRequest": {b64.StdEncoding.EncodeToString(requestWithExtensions(t, nil))}}.Encode()
		resp, err := http.Post(e.srv.URL+"/"+root.ID+c.path+"/certfnsh.asp", "application/x-www-form-urlencoded", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(out), c.want) {
			t.Errorf("%q: %d %s", c.path, resp.StatusCode, out)
		}
	}
	for label, code := range map[string]int{root.ID: 200, root.ID + "+tls-server+tls-client": 200, root.ID + "+justcert": 400, root.ID + "+tls-server+tls-server": 400, root.ID + "+": 400} {
		resp, err := http.Get(e.srv.URL + "/.well-known/est/" + label + "/cacerts")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != code {
			t.Errorf("EST label %q: %d", label, resp.StatusCode)
		}
	}
}
