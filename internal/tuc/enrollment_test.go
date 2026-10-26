package tuc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
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
		{name: "invalid DNS", exts: []pkix.Extension{san(dns("bad_name"))}, u: server, bad: true},
		{name: "invalid DNS skipped for a client", exts: []pkix.Extension{san(dns("bad_name"))}, u: client},
		{name: "wildcard", exts: []pkix.Extension{san(dns("*.example"))}, u: server, bad: true},
		{name: "trailing dot", exts: []pkix.Extension{san(dns("leaf.example."))}, u: server, bad: true},
		{name: "non-ASCII DNS", exts: []pkix.Extension{san(dns("\u212a.example"))}, u: server, bad: true},
		{name: "long label", exts: []pkix.Extension{san(dns(strings.Repeat("a", 64) + ".example"))}, u: server, bad: true},
		{name: "bad SAN", exts: []pkix.Extension{{Id: oidSAN, Value: []byte{0xff}}}, u: server, bad: true},
		{name: "first readable SAN", exts: []pkix.Extension{{Id: oidSAN, Value: []byte{0xff}}, san(dns("bad_name")), san(dns("a.example")), san(dns("b.example"))}, u: server, dns: []string{"a.example"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			der, err := e.svc.Issue(n, string(requestWithExtensions(t, c.exts)), c.u)
			if c.bad {
				if err == nil {
					t.Fatal("a server without a valid DNS name issued")
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

// cryptcp 5.0.13484 -creatrqst -altname tuc.tuc: SAN in the Microsoft
// extension request attribute.
const cryptcpMSRequest = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIIBEDCBvgIBADAZMRcwFQYDVQQDEw5wcm9iZS1hZDI4OWFkZTBmMB8GCCqFAwcB
AQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEAneAcf13HJgpdyaOR0sJPYjBCm
cAgyLYIFAKSNKZidXbvnKSzBYI6regdeOxss0mh5WWWy7hxwFkSLbDP7hjtfoDYw
NAYKKwYBBAGCNwIBDjEmMCQwDgYDVR0PAQH/BAQDAgP4MBIGA1UdEQQLMAmCB3R1
Yy50dWMwCgYIKoUDBwEBAwIDQQDFGpTjRedx2a+v0iEALAMsPejVxglrKh4a836U
0Y/BJrs/j2cXCP4W/w9Ps5Mu6HObVlrB0KSgoZw0ulrOp9l7
-----END NEW CERTIFICATE REQUEST-----`

func TestMicrosoftExtensionRequest(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "gost256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	der, err := e.svc.Issue(n, cryptcpMSRequest, purpose{server: true})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !slices.Equal(cert.DNSNames, []string{"tuc.tuc"}) || !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("%v %v %v", err, cert.DNSNames, cert.ExtKeyUsage)
	}
}

// requestWithRawExtensions is a signed request whose extension request holds
// exts as they are.
func requestWithRawExtensions(t *testing.T, exts ...[]byte) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := asn1.Marshal(pkix.Name{CommonName: "leaf"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	var info cryptobyte.Builder
	info.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(0)
		b.AddBytes(subject)
		b.AddBytes(spki)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidExtensionReq)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						for _, e := range exts {
							b.AddBytes(e)
						}
					})
				})
			})
		})
	})
	tbs := info.BytesOrPanic()
	h := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2})
		})
		b.AddASN1BitString(sig)
	})
	return b.BytesOrPanic()
}

func TestRequestSANSkipping(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	sanExt := func(extra []byte, names ...string) []byte {
		var v cryptobyte.Builder
		v.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, name := range names {
				b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte(name)) })
			}
		})
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidSAN)
			b.AddASN1OctetString(v.BytesOrPanic())
			b.AddBytes(extra)
		})
		return b.BytesOrPanic()
	}
	null := []byte{5, 0}
	brokenSAN := extension(oidSAN, false, func(b *cryptobyte.Builder) { b.AddBytes([]byte{0xff}) })
	for _, c := range []struct {
		name string
		exts [][]byte
		dns  string
		err  string
	}{
		{"element of another type before SAN", [][]byte{null, sanExt(nil, "good.example")}, "good.example", ""},
		{"SAN with trailing data skipped", [][]byte{sanExt(null, "wrong.example"), sanExt(nil, "good.example")}, "good.example", ""},
		{"invalid DNS reported over a later broken SAN", [][]byte{sanExt(nil, "bad_name"), brokenSAN}, "", "некорректное DNS-имя"},
	} {
		der, err := e.svc.Issue(n, string(requestWithRawExtensions(t, c.exts...)), purpose{server: true})
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || !slices.Equal(cert.DNSNames, []string{c.dns}) {
			t.Errorf("%s: %v %v", c.name, err, cert.DNSNames)
		}
	}
}
