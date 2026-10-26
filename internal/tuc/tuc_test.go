package tuc

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type env struct {
	t       *testing.T
	srv     *httptest.Server
	mp      *mp.Ctx
	svc     *Service
	alg     algo // of the CAs and enroll requests
	keyFile string
	db      string   // path of the database
	subj    string   // of the next enroll request; /CN=leaf by default
	certs   [][]byte // of the last enroll response
}

func newEnv(t *testing.T) *env {
	ctx, err := mp.Open()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	rand.Read(raw)
	secret, err := NewSecret(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, mp: ctx, alg: algos[0]}
	var h http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	e.db = filepath.Join(t.TempDir(), "tuc.db")
	s, err := NewService(ctx, e.srv.URL, e.db, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.unsealSecret(secret, true); err != nil {
		t.Fatal(err)
	}
	h = s.Handler()
	e.svc = s
	return e
}

func (e *env) post(path string, body any) (int, []byte) {
	b, _ := json.Marshal(body)
	return e.postType(path, "application/json", b)
}

func (e *env) postRaw(path string, body []byte) (int, []byte) {
	return e.postType(path, "application/octet-stream", body)
}

func (e *env) postType(path, contentType string, body []byte) (int, []byte) {
	resp, err := http.Post(e.srv.URL+path, contentType, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *env) get(u string) []byte {
	resp, err := http.Get(u)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s: %d %s", u, resp.StatusCode, out)
	}
	return out
}

type created struct{ ID, Admin, URL string }

func (e *env) create(path string, req map[string]any) created {
	if _, ok := req["algo"]; !ok {
		req["algo"] = e.alg
	}
	code, out := e.post(path, req)
	if code != http.StatusOK {
		e.t.Fatalf("POST %s: %d %s", path, code, out)
	}
	var c created
	if err := json.Unmarshal(out, &c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// revocable makes the CAs of c issue with CRL and OCSP URLs.
func (e *env) revocable(c ...created) {
	for _, x := range c {
		e.issuance(x, issuance{CRL: true, OCSP: true, Days: 365})
	}
}

func (e *env) issuance(c created, i issuance) {
	if code, out := e.post("/"+c.ID+"/issuance", map[string]any{"token": c.Admin, "issuance": i}); code != http.StatusOK {
		e.t.Fatalf("issuance: %d %s", code, out)
	}
}

// enrollURL is the cryptcp -ca URL of the CA id for its admin token.
func (e *env) enrollURL(id, token string) string {
	code, out := e.post("/"+id+"/admin", map[string]any{"token": token})
	if code != http.StatusOK {
		e.t.Fatalf("admin: %d %s", code, out)
	}
	var a struct{ Enroll string }
	json.Unmarshal(out, &a)
	return a.Enroll
}

var sPKCS7 = regexp.MustCompile(`sPKCS7=sPKCS7 & "([A-Za-z0-9+/=]+)"`)

// forAlgos runs f for each algorithm on a new env.
func forAlgos(t *testing.T, f func(t *testing.T, e *env)) {
	for _, a := range algos {
		t.Run(string(a), func(t *testing.T) {
			e := newEnv(t)
			e.alg = a
			f(t, e)
		})
	}
}

// enroll posts a PKCS#10 request of e.alg made by the openssl CLI to an enroll
// URL as cryptcp does, checks that the issuing CA ca signed the response,
// and returns the issued certificate; its key is in e.keyFile.
func (e *env) enroll(enrollURL string, ca []byte) ([]byte, error) {
	// cryptcp sends the PEM on one line
	oneLine := strings.ReplaceAll(string(csr(e.t, e)), "\n", "")
	resp, err := http.PostForm(enrollURL+"/certfnsh.asp", url.Values{"CertRequest": {oneLine}, "Mode": {"newreq"}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	var b64s strings.Builder
	for _, m := range sPKCS7.FindAllStringSubmatch(string(page), -1) {
		b64s.WriteString(m[1])
	}
	if b64s.Len() == 0 {
		return nil, fmt.Errorf("rejected: %s", page)
	}
	der, err := b64.StdEncoding.DecodeString(b64s.String())
	if err != nil {
		e.t.Fatal(err)
	}
	content, _, err := e.mp.VerifyCMS(der, ca)
	if err != nil {
		e.t.Fatalf("enroll response signature: %v", err)
	}
	if !bytes.Equal(content, pkiResponse()) {
		e.t.Fatalf("enroll response content %x", content)
	}
	e.certs = certsOf(e.t, der)
	for _, c := range e.certs {
		if xc, err := x509.ParseCertificate(c); err == nil && !xc.IsCA {
			return c, nil
		}
	}
	e.t.Fatal("no leaf certificate in the enroll response")
	return nil, nil
}

// csr is a PEM PKCS#10 request of e.alg with e.subj made by the openssl CLI;
// its key is in e.keyFile.
func csr(t *testing.T, e *env) []byte {
	dir := t.TempDir()
	e.keyFile = filepath.Join(dir, "key.pem")
	subj := e.subj
	if subj == "" {
		subj = "/CN=leaf"
	}
	args := append([]string{"req", "-new"}, strings.Fields(algoDefs[e.alg].openssl)...)
	cmd := exec.Command("openssl", append(args, "-nodes", "-keyout", e.keyFile, "-subj", subj,
		"-addext", "keyUsage=digitalSignature", "-addext", "basicConstraints=CA:TRUE",
		"-addext", "subjectAltName=DNS:leaf.example", "-addext", "extendedKeyUsage=serverAuth,clientAuth")...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl req: %v", err)
	}
	return out
}

// certsOf returns the certificates of a CMS SignedData.
func certsOf(t *testing.T, der []byte) [][]byte {
	in := cryptobyte.String(der)
	var ci, sd, certs cryptobyte.String
	if !in.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.SkipASN1(cbasn1.OBJECT_IDENTIFIER) ||
		!ci.ReadASN1(&sd, cbasn1.Tag(0).ContextSpecific().Constructed()) || !sd.ReadASN1(&sd, cbasn1.SEQUENCE) ||
		!sd.SkipASN1(cbasn1.INTEGER) || !sd.SkipASN1(cbasn1.SET) || !sd.SkipASN1(cbasn1.SEQUENCE) ||
		!sd.ReadASN1(&certs, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		t.Fatal("bad CMS SignedData")
	}
	var out [][]byte
	for !certs.Empty() {
		var c cryptobyte.String
		if !certs.ReadASN1Element(&c, cbasn1.SEQUENCE) {
			t.Fatal("bad certificate in CMS")
		}
		out = append(out, c)
	}
	return out
}

// opensslVerify checks leaf with the openssl CLI on the GOST engine,
// including the root's self-signature and, with crls, every CRL.
func opensslVerify(t *testing.T, root, inter, leaf []byte, crls ...[]byte) error {
	dir := t.TempDir()
	write := func(name string, der []byte, form string) string {
		p := filepath.Join(dir, name)
		cmd := exec.Command("openssl", form, "-inform", "DER", "-out", p)
		cmd.Stdin = bytes.NewReader(der)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl %s: %v %s", form, err, out)
		}
		return p
	}
	args := []string{"verify", "-check_ss_sig", "-CAfile", write("root.pem", root, "x509"),
		"-untrusted", write("inter.pem", inter, "x509")}
	if len(crls) > 0 {
		args = append(args, "-crl_check_all")
		for i, c := range crls {
			args = append(args, "-CRLfile", write(fmt.Sprintf("%d.crl", i), c, "crl"))
		}
	}
	args = append(args, write("leaf.pem", leaf, "x509"))
	if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// signedBy is a CMS SignedData of text by the certificate cert with the key in
// keyFile, made by the openssl CLI, in DER or, pem, in PEM.
func signedBy(t *testing.T, cert []byte, keyFile, text string, pem bool) []byte {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cert.der"), cert, 0o644)
	os.WriteFile(filepath.Join(dir, "text"), []byte(text), 0o644)
	form := "DER"
	if pem {
		form = "PEM"
	}
	out, err := exec.Command("sh", "-c", "cd "+dir+" && openssl x509 -inform DER -in cert.der -out cert.pem && "+
		"openssl cms -sign -signer cert.pem -inkey "+keyFile+" -binary -nodetach -outform "+form+" -in text").Output()
	if err != nil {
		t.Fatalf("openssl cms: %v", err)
	}
	return out
}

func TestHierarchy(t *testing.T) { forAlgos(t, testHierarchy) }

func testHierarchy(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root,O=TUC,C=RU,INN=001234567890", "days": 30})
	e.revocable(root)
	if code, _ := e.post("/"+root.ID+"/new", map[string]any{"token": "x", "subject": "CN=Inter"}); code != http.StatusForbidden {
		t.Fatalf("intermediate without the admin token: %d", code)
	}
	// The intermediate has the next algorithm: each chain mixes two
	other := algos[0]
	for i, a := range algos[:len(algos)-1] {
		if a == e.alg {
			other = algos[i+1]
		}
	}
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter", "days": 60, "closed": true, "algo": other})
	e.revocable(inter)

	if !regexp.MustCompile(`^[0-9A-F]{40}$`).MatchString(inter.ID) || !regexp.MustCompile(`^[a-z2-7]{32}$`).MatchString(inter.Admin) {
		t.Fatalf("id %s is not upper-case hex or token %s not base32", inter.ID, inter.Admin)
	}
	if !bytes.Equal(e.get(e.srv.URL+"/"+strings.ToLower(inter.ID)+".crt"), e.get(inter.URL+".crt")) {
		t.Fatal("a lower-case id does not find the CA")
	}
	rootDER, interDER := e.get(root.URL+".crt"), e.get(inter.URL+".crt")

	if resp, err := http.Get(inter.URL + ".crl"); err != nil || resp.Header.Get("Content-Disposition") != `attachment; filename="crl-`+inter.ID+`.crl"` {
		t.Fatalf("CRL file name: %v", err)
	}
	if resp, err := http.Get(inter.URL + ".crt"); err != nil || resp.Header.Get("Cache-Control") != immutable {
		t.Fatalf("a CA certificate is not cached: %v", err)
	}
	if certID(interDER) != inter.ID || certID(rootDER) != root.ID {
		t.Fatal("a CA id is not the SHA-1 of its certificate")
	}
	rc, _ := x509.ParseCertificate(rootDER)
	ic, _ := x509.ParseCertificate(interDER)
	if algoOf(rc) != e.alg || algoOf(ic) != other {
		t.Fatalf("CA keys %s and %s, want %s and %s", algoOf(rc), algoOf(ic), e.alg, other)
	}
	if !ic.NotAfter.Equal(rc.NotAfter) {
		t.Fatalf("intermediate outlives its root: %v > %v", ic.NotAfter, rc.NotAfter)
	}
	if len(ic.CRLDistributionPoints) != 1 || ic.CRLDistributionPoints[0] != root.URL+".crl" {
		t.Fatalf("intermediate CDP %v", ic.CRLDistributionPoints)
	}

	if _, err := e.enroll(inter.URL, interDER); err == nil {
		t.Fatal("a closed CA issued without the issue token")
	}
	enroll := e.enrollURL(inter.ID, inter.Admin)
	leaf, err := e.enroll(enroll+"/tls-server/tls-client", interDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.certs) != 2 || !slices.ContainsFunc(e.certs, func(c []byte) bool { return bytes.Equal(c, rootDER) }) {
		t.Fatalf("enroll response: %d certificates, want the leaf and the root without the intermediate of another algorithm", len(e.certs))
	}
	if _, err := e.enroll(enroll+"/justcert", interDER); err != nil || len(e.certs) != 1 {
		t.Fatalf("justcert response: %v, %d certificates, want 1", err, len(e.certs))
	}
	lc, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if lc.IsCA || lc.BasicConstraintsValid || lc.KeyUsage&x509.KeyUsageDigitalSignature == 0 || lc.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		t.Fatalf("leaf took basicConstraints from the request or lost its key usage: CA=%v KU=%v", lc.IsCA, lc.KeyUsage)
	}
	if len(lc.DNSNames) != 1 || lc.DNSNames[0] != "leaf.example" || len(lc.ExtKeyUsage) != 2 {
		t.Fatalf("leaf lost the requested SAN or EKU: %v %v", lc.DNSNames, lc.ExtKeyUsage)
	}
	if lc.CRLDistributionPoints[0] != inter.URL+".crl" || lc.IssuingCertificateURL[0] != inter.URL+".crt" {
		t.Fatalf("leaf URLs %v %v", lc.CRLDistributionPoints, lc.IssuingCertificateURL)
	}

	verify := func(want bool, what string) {
		t.Helper()
		crls := [][]byte{e.get(root.URL + ".crl"), e.get(inter.URL + ".crl")}
		errMP := e.mp.VerifyChain(leaf, [][]byte{rootDER}, [][]byte{interDER}, crls)
		errCLI := opensslVerify(t, rootDER, interDER, leaf, crls...)
		if (errMP == nil) != want || (errCLI == nil) != want {
			t.Fatalf("%s: want valid=%v, minipki: %v, openssl: %v", what, want, errMP, errCLI)
		}
	}
	verify(true, "issued chain")

	// The intermediate's admin sees what it issued; the root's admin does too
	code, out := e.post("/"+inter.ID+"/list", map[string]any{"token": inter.Admin, "q": "leaf"})
	var rows []certRow
	json.Unmarshal(out, &rows)
	if code != http.StatusOK || len(rows) != 2 || rows[0].Subject != "CN=leaf" {
		t.Fatalf("list: %d %s", code, out)
	}
	if code, _ := e.post("/"+inter.ID+"/revoke", map[string]any{"token": inter.Admin, "cert": certID(leaf)}); code != http.StatusOK {
		t.Fatalf("revoke by the root admin: %d", code)
	}
	verify(false, "revoked leaf")
	if !bytes.Equal(e.get(inter.URL+"/cert/"+certID(leaf)+".crt"), leaf) {
		t.Fatal("download of an issued certificate")
	}

	leaf, err = e.enroll(enroll, interDER)
	if err != nil {
		t.Fatal(err)
	}
	verify(true, "second leaf")
	// A disabled intermediate answers 503 to every service, its owner still
	// manages it; enabled, it serves again
	status := func(method, u string) int {
		t.Helper()
		req, _ := http.NewRequest(method, u, strings.NewReader("x"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	setDisabled := func(on bool) {
		t.Helper()
		if code, out := e.post("/"+inter.ID+"/disabled", map[string]any{"token": inter.Admin, "disabled": on}); code != http.StatusOK {
			t.Fatalf("disabled %v: %d %s", on, code, out)
		}
	}
	services := [][2]string{{"GET", inter.URL + ".crt"}, {"GET", inter.URL + ".crl"}, {"POST", inter.URL + "/ocsp"}, {"POST", inter.URL + "/tsp"},
		{"POST", enroll + "/certfnsh.asp"}, {"POST", e.srv.URL + "/.well-known/est/" + inter.ID + "/simpleenroll"},
		{"GET", e.srv.URL + "/.well-known/est/" + inter.ID + "/cacerts"}, {"POST", inter.URL + "/pfx"}, {"POST", inter.URL + "/revoke"}}
	setDisabled(true)
	for _, sv := range services {
		if code := status(sv[0], sv[1]); code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s of a disabled CA: %d", sv[0], sv[1], code)
		}
	}
	if code, _ := e.post("/"+inter.ID+"/new", map[string]any{"token": inter.Admin, "subject": "CN=Child"}); code != http.StatusServiceUnavailable {
		t.Fatalf("a child of a disabled CA: %d", code)
	}
	if code, _ := e.post("/"+inter.ID+"/admin", map[string]any{"token": inter.Admin}); code != http.StatusOK || status("GET", inter.URL) != http.StatusOK {
		t.Fatal("a disabled CA is not managed")
	}
	setDisabled(false)
	if code := status("GET", inter.URL+".crt"); code != http.StatusOK {
		t.Fatalf("an enabled CA: %d", code)
	}

	// The operator deletes the intermediate: it is gone and revoked by its root
	if err := Delete(e.db, strings.ToLower(inter.ID)); err != nil {
		t.Fatal(err)
	}
	if code := status("GET", inter.URL+".crt"); code != http.StatusNotFound {
		t.Fatalf("a deleted CA is served: %d", code)
	}
	crls := [][]byte{e.get(root.URL + ".crl")}
	if err := e.mp.VerifyChain(interDER, [][]byte{rootDER}, nil, crls); err == nil {
		t.Fatal("a deleted intermediate is not revoked by its root")
	}
}

func TestOCSP(t *testing.T) { forAlgos(t, testOCSP) }

// testOCSP asks the responders of a root and an intermediate with the
// openssl CLI, by POST and GET, with SHA-1 CertIDs and those of the hash
// of the CA signature.
func testOCSP(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	e.revocable(root)
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter"})
	e.revocable(inter)
	rootDER, interDER := e.get(root.URL+".crt"), e.get(inter.URL+".crt")
	leaf, err := e.enroll(inter.URL, interDER)
	if err != nil {
		t.Fatal(err)
	}
	if lc, _ := x509.ParseCertificate(leaf); len(lc.OCSPServer) != 1 || lc.OCSPServer[0] != inter.URL+"/ocsp" {
		t.Fatalf("leaf OCSP URL %v", lc.OCSPServer)
	}
	dir := t.TempDir()
	file := func(name string, der []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		return p
	}
	rootPEM, interPEM, leafPEM := file("root.pem", rootDER), file("inter.pem", interDER), file("leaf.pem", leaf)
	hash := "-sha256"
	if e.alg.Family() == "gost" {
		hash = "-md_gost12_256"
	}
	status := func(want string, args ...string) {
		t.Helper()
		args = append([]string{"ocsp", "-CAfile", rootPEM, "-verify_other", interPEM}, args...)
		out, err := exec.Command("openssl", args...).CombinedOutput()
		if err != nil || !strings.HasPrefix(string(out), "Response verify OK\n") || strings.Contains(string(out), "WARNING") ||
			!regexp.MustCompile(`(?m)^\S+: `+want+`$`).Match(out) {
			t.Fatalf("openssl %s: want %s, got %v\n%s", strings.Join(args, " "), want, err, out)
		}
	}
	status("good", "-issuer", interPEM, "-cert", leafPEM, "-url", inter.URL+"/ocsp")
	status("good", hash, "-issuer", interPEM, "-cert", leafPEM, "-url", inter.URL+"/ocsp")
	status("good", hash, "-issuer", rootPEM, "-cert", interPEM, "-url", root.URL+"/ocsp")
	status("unknown", "-issuer", interPEM, "-serial", "0x1234", "-url", inter.URL+"/ocsp")

	// GET with base64 as is and URL-encoded
	reqFile, respFile := filepath.Join(dir, "req.der"), filepath.Join(dir, "resp.der")
	if out, err := exec.Command("openssl", "ocsp", hash, "-issuer", interPEM, "-cert", leafPEM, "-no_nonce", "-reqout", reqFile).CombinedOutput(); err != nil {
		t.Fatalf("openssl ocsp -reqout: %v %s", err, out)
	}
	req, _ := os.ReadFile(reqFile)
	enc := b64.StdEncoding.EncodeToString(req)
	for _, path := range []string{enc, url.PathEscape(enc)} {
		os.WriteFile(respFile, e.get(inter.URL+"/ocsp/"+path), 0o644)
		status("good", "-respin", respFile, "-no_nonce", hash, "-issuer", interPEM, "-cert", leafPEM)
	}

	if code, out := e.postRaw("/"+inter.ID+"/ocsp", []byte("not a request")); code != http.StatusOK || !bytes.Equal(out, ocspError(ocspMalformed)) {
		t.Fatalf("malformed request: %d %x", code, out)
	}
	if code, _ := e.post("/"+inter.ID+"/revoke", map[string]any{"token": inter.Admin, "cert": certID(leaf)}); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	status("revoked", hash, "-issuer", interPEM, "-cert", leafPEM, "-url", inter.URL+"/ocsp")

	// The OCSP responder of the CA signs, one for all requests, trusted
	// without a revocation check
	var responders []string
	for range 2 {
		out, err := exec.Command("sh", "-c", "openssl ocsp -issuer "+interPEM+" -cert "+leafPEM+" -url "+inter.URL+"/ocsp -noverify -resp_text").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Subject: CN=Inter OCSP") || !strings.Contains(string(out), "OCSP Signing") ||
			!strings.Contains(string(out), "OCSP No Check") {
			t.Fatalf("OCSP responder: %v %s", err, out)
		}
		responders = append(responders, regexp.MustCompile(`Serial Number:\s*\S+`).FindString(string(out)))
	}
	if responders[0] != responders[1] {
		t.Fatalf("OCSP responders %q", responders)
	}
}

func TestPFX(t *testing.T) { forAlgos(t, testPFX) }

// testPFX takes a PKCS#12 of a key the CA makes of the next algorithm, as
// the openssl CLI reads it, at an open and a closed CA.
func testPFX(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	other := algos[(slices.Index(algos, e.alg)+1)%len(algos)]
	post := func(path string, req map[string]any) (int, []byte) {
		t.Helper()
		return e.post(path, req)
	}
	code, p12 := post("/"+root.ID+"/pfx", map[string]any{"name": "pfx leaf", "algo": other, "tlsServer": true, "tlsClient": true, "fqdn": "pfx.example", "password": "pw"})
	if code != http.StatusOK {
		t.Fatalf("pfx: %d %s", code, p12)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "p.pfx"), p12, 0o644)
	out, err := exec.Command("sh", "-c", "cd "+dir+" && openssl pkcs12 -in p.pfx -passin pass:pw -nokeys -clcerts -out leaf.pem && "+
		"openssl pkcs12 -in p.pfx -passin pass:pw -nocerts -nodes | openssl pkey -pubout -outform DER -out key.pub && "+
		"openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform DER | cmp - key.pub && "+
		"openssl pkcs12 -in p.pfx -passin pass:pw -nokeys -cacerts | openssl x509 -outform DER").CombinedOutput()
	if err != nil || !bytes.HasSuffix(out, e.get(root.URL+".crt")) {
		t.Fatalf("openssl reads the PKCS#12: %v %s", err, out)
	}
	pemLeaf, _ := os.ReadFile(filepath.Join(dir, "leaf.pem"))
	b, _ := pem.Decode(pemLeaf)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || c.Subject.CommonName != "pfx leaf" || len(c.DNSNames) != 1 || c.DNSNames[0] != "pfx.example" ||
		len(c.ExtKeyUsage) != 2 || algoOf(c) != other {
		t.Fatalf("PFX certificate: %v %+v", err, c)
	}
	page := e.get(root.URL)
	pfx64 := "printf %s '" + b64.StdEncoding.EncodeToString(p12) + "'"
	imp := strings.NewReplacer("NAME=''", "NAME=p", "PASS=''", "PASS=pw", "printf %s ''", pfx64).Replace(pageCommand(t, page, `data-os="openssl" data-tool="openssl" class="import off"`))
	imported := exec.Command("sh", "-c", imp+` &&
openssl x509 -in p.crt -pubkey -noout | openssl pkey -pubin -outform DER > crt.pub && openssl pkey -in p.key -pubout -outform DER | cmp - crt.pub &&
[ "$(grep -c "BEGIN CERTIFICATE" p.crt)" = 2 ] && [ "$(stat -c %a p.key)" = 600 ]`)
	imported.Dir = dir
	if out, err := imported.CombinedOutput(); err != nil {
		t.Fatalf("page import command for OpenSSL: %v %s", err, out)
	}
	revoke := strings.NewReplacer("PASS=''", "PASS=pw", "printf %s ''", pfx64).Replace(pageCommand(t, page, `data-os="pfx" data-tool="pfx" class="revoke off"`))
	cmd := exec.Command("sh", "-c", revoke)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), `"revoked"`) {
		t.Fatalf("page revoke command for a PFX: %v %s", err, out)
	}
	// The PFX command issues and installs in one go, leaving only the result
	install := strings.NewReplacer("NAME=''", "NAME=q", "PASS=''", "PASS=pw2", "--data-binary ''", `--data-binary '{"name":"q","password":"pw2"}'`).
		Replace(pageCommand(t, page, `data-os="openssl" data-tool="openssl" class="pfxcmd off"`))
	installed := exec.Command("sh", "-c", install+` &&
openssl x509 -in q.crt -pubkey -noout | openssl pkey -pubin -outform DER > q.pub && openssl pkey -in q.key -pubout -outform DER | cmp - q.pub`)
	installed.Dir = t.TempDir()
	if out, err := installed.CombinedOutput(); err != nil {
		t.Fatalf("page PFX command for OpenSSL: %v %s", err, out)
	}
	for _, bad := range []map[string]any{{"name": "x"}, {"name": "", "password": "pw"}, {"name": "x", "password": "pw", "tlsServer": true, "fqdn": "bad name"}} {
		if code, _ := post("/"+root.ID+"/pfx", bad); code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, code)
		}
	}
	closed := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Closed", "closed": true})
	if code, _ := post("/"+closed.ID+"/pfx", map[string]any{"name": "x", "password": "pw"}); code != http.StatusForbidden {
		t.Fatalf("pfx at a closed CA without the issue token: %d", code)
	}
	if code, _ := post(strings.TrimPrefix(e.enrollURL(closed.ID, closed.Admin), e.srv.URL)+"/pfx", map[string]any{"name": "x", "password": "pw"}); code != http.StatusOK {
		t.Fatalf("pfx at a closed CA with the issue token: %d", code)
	}
}

func TestTSP(t *testing.T) { forAlgos(t, testTSP) }

// testTSP has the openssl CLI verify time-stamps of a CA by its
// time-stamping certificate, made once with CRL and OCSP URLs.
func testTSP(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.get(root.URL + ".crt")}), 0o644)
	hash := "-sha256"
	if e.alg.Family() == "gost" {
		hash = "-md_gost12_256"
	}
	var signers []string
	for i := range 2 {
		q := filepath.Join(dir, fmt.Sprintf("q%d.tsq", i))
		if out, err := exec.Command("sh", "-c", "cd "+dir+" && echo data > d && openssl ts -query -data d "+hash+" -cert -out "+q).CombinedOutput(); err != nil {
			t.Fatalf("ts -query: %v %s", err, out)
		}
		req, _ := os.ReadFile(q)
		resp, err := http.Post(root.URL+"/tsp", "application/timestamp-query", bytes.NewReader(req))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		r := filepath.Join(dir, fmt.Sprintf("r%d.tsr", i))
		os.WriteFile(r, body, 0o644)
		out, err := exec.Command("sh", "-c", "cd "+dir+" && openssl ts -verify -in "+r+" -queryfile "+q+" -CAfile root.pem && "+
			"openssl ts -reply -in "+r+" -token_out | openssl pkcs7 -inform DER -print_certs | openssl x509 -subject -noout -ext crlDistributionPoints,authorityInfoAccess").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Verification: OK") || !strings.Contains(string(out), "OCSP - URI:"+root.URL+"/ocsp") ||
			!strings.Contains(string(out), root.URL+".crl") {
			t.Fatalf("openssl verifies the time-stamp: %v %s", err, out)
		}
		signers = append(signers, regexp.MustCompile(`subject=.*`).FindString(string(out)))
	}
	if signers[0] != signers[1] || signers[0] != "subject=CN=Root TSP" {
		t.Fatalf("time-stamping certificates %q", signers)
	}
	if code, out := e.postRaw("/"+root.ID+"/tsp", []byte("not a request")); code != http.StatusOK || len(out) == 0 {
		t.Fatalf("bad request: %d", code)
	}
}

func TestKeyUsage(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, c := range []struct {
		alg       algo
		requested string // keyUsage of the request, none if empty
		want      x509.KeyUsage
	}{
		{"ecdsa256", "", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyAgreement},
		{"ecdsa256", "digitalSignature,keyEncipherment,keyCertSign", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyAgreement},
		{"rsa2048", "", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
		{"rsa2048", "keyEncipherment,keyAgreement,cRLSign", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment},
		{"gost256", "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement},
	} {
		dir := t.TempDir()
		args := append([]string{"req", "-new"}, strings.Fields(algoDefs[c.alg].openssl)...)
		args = append(args, "-nodes", "-keyout", filepath.Join(dir, "k"), "-subj", "/CN=ku")
		if c.requested != "" {
			args = append(args, "-addext", "keyUsage="+c.requested)
		}
		req, err := exec.Command("openssl", args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		der, err := e.svc.Issue(n, string(req), purpose{})
		if err != nil {
			t.Fatalf("%s %q: %v", c.alg, c.requested, err)
		}
		if lc, _ := x509.ParseCertificate(der); lc.KeyUsage != c.want {
			t.Fatalf("%s %q: key usage %b, want %b", c.alg, c.requested, lc.KeyUsage, c.want)
		}
	}
	req, _ := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", filepath.Join(t.TempDir(), "k"), "-subj", "/CN=ku", "-addext", "keyUsage=keyEncipherment").Output()
	if _, err := e.svc.Issue(n, string(req), purpose{}); err != nil {
		t.Fatalf("requested key usage must be ignored: %v", err)
	}
}

// TestKeyOnce: a CA certifies a key once, also after a revocation; another
// CA does too. Certificates stored without the key hash get it.
func TestKeyOnce(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	other := e.create("/new", map[string]any{"subject": "CN=Other"})
	req := csr(t, e)
	open := func(id string) *node {
		n, err := e.svc.open(id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(n.Close)
		return n
	}
	rn, on := open(root.ID), open(other.ID)
	der, err := e.svc.Issue(rn, string(req), purpose{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Issue(rn, string(req), purpose{}); !errors.Is(err, errKeyReused) {
		t.Fatalf("a second certificate of a key: %v", err)
	}
	e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(der)})
	if _, err := e.svc.Issue(rn, string(req), purpose{}); !errors.Is(err, errKeyReused) {
		t.Fatalf("a key of a revoked certificate: %v", err)
	}
	if _, err := e.svc.Issue(on, string(req), purpose{}); err != nil {
		t.Fatalf("the key at another CA: %v", err)
	}

}

// TestUsage: a use of a CA marks it, hourly, and a root has the last use
// of the CAs under it.
func TestUsage(t *testing.T) {
	e := newEnv(t)
	idle := e.create("/new", map[string]any{"subject": "CN=Idle"})
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter"})
	e.svc.st.db.Exec(`UPDATE cas SET used = 0, created = created - 86400`)
	e.get(inter.URL + ".crt")
	us, err := e.svc.st.usages()
	if err != nil || len(us) != 2 || us[0].id != idle.ID || us[1].id != root.ID || us[1].cas != 2 || us[1].certs != 1 ||
		time.Since(us[1].used) > time.Minute || time.Since(us[0].used) < 23*time.Hour {
		t.Fatalf("usages: %v %+v", err, us)
	}
	e.svc.st.db.Exec(`UPDATE cas SET used = used - 600 WHERE id = ?`, inter.ID)
	e.get(inter.URL + ".crt")
	if us2, _ := e.svc.st.usages(); !us2[1].used.Equal(us[1].used.Add(-600 * time.Second)) {
		t.Fatalf("a use within the hour is written: %v", us2[1].used)
	}
}

func TestIssuance(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "days": 400})
	rootDER := e.get(root.URL + ".crt")
	issue := func(i issuance) *x509.Certificate {
		t.Helper()
		e.issuance(root, i)
		leaf, err := e.enroll(root.URL, rootDER)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(leaf)
		if len(c.IssuingCertificateURL) != 1 || c.IssuingCertificateURL[0] != root.URL+".crt" {
			t.Fatalf("CA issuers URL %v", c.IssuingCertificateURL)
		}
		return c
	}
	leaf, err := e.enroll(root.URL, rootDER)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := x509.ParseCertificate(leaf); len(c.CRLDistributionPoints) != 1 || len(c.OCSPServer) != 1 ||
		c.NotAfter.Sub(c.NotBefore) != 365*24*time.Hour+backdate {
		t.Fatalf("by default a leaf with CRL and OCSP for a year: %v %v %v — %v", c.CRLDistributionPoints, c.OCSPServer, c.NotBefore, c.NotAfter)
	}
	if c := issue(issuance{Days: 365}); len(c.CRLDistributionPoints) != 0 || len(c.OCSPServer) != 0 {
		t.Fatalf("neither CRL nor OCSP: %v %v", c.CRLDistributionPoints, c.OCSPServer)
	}
	if c := issue(issuance{CRL: true, Days: 365}); len(c.CRLDistributionPoints) != 1 || len(c.OCSPServer) != 0 {
		t.Fatalf("CRL only: %v %v", c.CRLDistributionPoints, c.OCSPServer)
	}
	if c := issue(issuance{OCSP: true, Days: 365}); len(c.CRLDistributionPoints) != 0 || len(c.OCSPServer) != 1 {
		t.Fatalf("OCSP only: %v %v", c.CRLDistributionPoints, c.OCSPServer)
	}
	if c := issue(issuance{From: -10, Days: 5}); !c.NotAfter.Before(time.Now().AddDate(0, 0, -4)) {
		t.Fatalf("an expired leaf ends %v", c.NotAfter)
	}
	if c := issue(issuance{From: 3, Days: 5}); !c.NotBefore.After(time.Now().AddDate(0, 0, 2)) {
		t.Fatalf("a leaf not yet valid starts %v", c.NotBefore)
	}
	e.issuance(root, issuance{From: 500, Days: 5})
	if _, err := e.enroll(root.URL, rootDER); err == nil {
		t.Fatal("a leaf issued beyond the CA")
	}
	if code, _ := e.post("/"+root.ID+"/issuance", map[string]any{"token": root.Admin, "issuance": issuance{Days: 0}}); code != http.StatusBadRequest {
		t.Fatalf("zero days: %d", code)
	}
	code, out := e.post("/"+root.ID+"/admin", map[string]any{"token": root.Admin})
	var a struct{ Issuance issuance }
	if json.Unmarshal(out, &a); code != http.StatusOK || a.Issuance != (issuance{From: 500, Days: 5}) {
		t.Fatalf("admin details: %d %s", code, out)
	}

}

func TestCRLPublishing(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	get := func() (*x509.RevocationList, []byte, string) {
		resp, err := http.Get(root.URL + ".crl")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		der, _ := io.ReadAll(resp.Body)
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		return crl, der, resp.Header.Get("ETag")
	}
	crl, der, modified := get()
	rc, _ := x509.ParseCertificate(e.get(root.URL + ".crt"))
	if !crl.ThisUpdate.Equal(rc.NotBefore.Add(backdate)) || crl.NextUpdate.Sub(crl.ThisUpdate) != crlLifetime {
		t.Fatalf("the first CRL is not of when the CA was made or not valid for a week: %v — %v", crl.ThisUpdate, crl.NextUpdate)
	}
	if _, again, _ := get(); !bytes.Equal(again, der) {
		t.Fatal("a CRL is signed anew for each request")
	}
	req, _ := http.NewRequest("GET", root.URL+".crl", nil)
	req.Header.Set("If-None-Match", modified)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNotModified {
		t.Fatalf("a CRL fetched again since it was published: %v", err)
	}

	leaf, err := e.enroll(root.URL, e.get(root.URL+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(leaf)})
	revoked, _, _ := get()
	lc, _ := x509.ParseCertificate(leaf)
	if revoked.Number.Cmp(crl.Number) <= 0 || len(revoked.RevokedCertificateEntries) != 1 || revoked.RevokedCertificateEntries[0].SerialNumber.Cmp(lc.SerialNumber) != 0 {
		t.Fatal("a revocation is not published at once in a CRL of a greater number")
	}
	if at := revoked.RevokedCertificateEntries[0].RevocationTime; !revoked.ThisUpdate.Equal(at) {
		t.Fatalf("a CRL after a revocation is not of its time: %v, revoked %v", revoked.ThisUpdate, at)
	}
	e.svc.st.db.Exec(`UPDATE crls SET this_update = this_update - ?`, int64(crlRepublish/time.Second))
	if daily, _, _ := get(); daily.Number.Cmp(revoked.Number) <= 0 {
		t.Fatal("an hour-old CRL is not published anew")
	}
}

func TestMaxLevel(t *testing.T) {
	e := newEnv(t)
	c := e.create("/new", map[string]any{"subject": "CN=L1"})
	admin := c.Admin
	for l := 2; l <= maxLevel; l++ {
		c = e.create("/"+c.ID+"/new", map[string]any{"token": admin, "subject": fmt.Sprintf("CN=L%d", l)})
		admin = c.Admin
	}
	if code, out := e.post("/"+c.ID+"/new", map[string]any{"token": admin, "subject": "CN=deeper"}); code != http.StatusBadRequest {
		t.Fatalf("a CA below level %d: %d %s", maxLevel, code, out)
	}
	if page := e.get(c.URL); bytes.Contains(page, []byte(`id="child-open"`)) || !bytes.Contains(page, []byte("Последний уровень иерархии")) {
		t.Fatal("the page of the deepest CA offers to create a CA under it")
	}
}

func TestRevokeSelf(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter"})
	if code, _ := e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "self": true}); code != http.StatusBadRequest {
		t.Fatalf("a root revoked itself: %d", code)
	}
	if code, out := e.post("/"+inter.ID+"/revoke", map[string]any{"token": inter.Admin, "self": true}); code != http.StatusOK {
		t.Fatalf("an intermediate revoked by its own admin: %d %s", code, out)
	}
	if err := e.mp.VerifyChain(e.get(inter.URL+".crt"), [][]byte{e.get(root.URL + ".crt")}, nil, [][]byte{e.get(root.URL + ".crl")}); err == nil {
		t.Fatal("the revoked intermediate still verifies")
	}
	if !bytes.Contains(e.get(inter.URL), []byte("Отозван")) {
		t.Fatal("the page of a revoked intermediate does not say so")
	}
}

func TestClosedToggle(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	rootDER := e.get(root.URL + ".crt")
	if code, _ := e.post("/"+root.ID+"/closed", map[string]any{"token": root.Admin, "closed": true}); code != http.StatusOK {
		t.Fatal("close")
	}
	if _, err := e.enroll(root.URL, rootDER); err == nil {
		t.Fatal("a closed CA issued without the issue token")
	}
	if _, err := e.enroll(e.enrollURL(root.ID, root.Admin), rootDER); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeBySigner(t *testing.T) { forAlgos(t, testRevokeBySigner) }

func testRevokeBySigner(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	other := e.create("/new", map[string]any{"subject": "CN=Other"})
	rootDER := e.get(root.URL + ".crt")
	leaf, err := e.enroll(root.URL, rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key := e.keyFile
	otherLeaf, err := e.enroll(other.URL+"/", e.get(other.URL+".crt")) // cryptcp -ca with a trailing slash
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		what string
		body []byte
		code int
	}{
		{"a certificate of another CA", signedBy(t, otherLeaf, e.keyFile, "revoke", false), http.StatusForbidden},
		{"another text", signedBy(t, leaf, key, "a contract", false), http.StatusForbidden},
		{"not a signature", []byte("not a signature"), http.StatusBadRequest},
	} {
		if code, out := e.postRaw("/"+root.ID+"/revoke", bad.body); code != bad.code {
			t.Fatalf("%s: %d %s", bad.what, code, out)
		}
	}
	if code, out := e.postRaw("/"+root.ID+"/revoke", signedBy(t, leaf, key, "revoke\n", true)); code != http.StatusOK {
		t.Fatalf("PEM signature of revoke by the holder: %d %s", code, out)
	}
	if err := e.mp.VerifyChain(leaf, [][]byte{rootDER}, nil, [][]byte{e.get(root.URL + ".crl")}); err == nil {
		t.Fatal("the leaf revoked by its holder still verifies")
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t)
	if code, _ := e.post("/new", map[string]any{"subject": "CN=Root", "algo": "dsa"}); code != http.StatusBadRequest {
		t.Fatalf("a root of an unknown algorithm: %d", code)
	}
	for _, subject := range []string{
		"CN=" + strings.Repeat("я", 65),
		strings.Repeat("O=a,", 8) + "CN=b",
		"CN=Test,C=Россия",
		"CN=Test,INN=12a",
	} {
		if code, _ := e.post("/new", map[string]any{"subject": subject}); code != http.StatusBadRequest {
			t.Fatalf("CA name %.20q…: %d", subject, code)
		}
	}
	root := e.create("/new", map[string]any{"subject": "CN=" + strings.Repeat("я", 64)})
	e.subj = strings.Repeat("/OU=a", 8) + "/CN=x"
	if _, err := e.enroll(root.URL, e.get(root.URL+".crt")); err == nil {
		t.Fatal("issued for a name over the limits")
	}
}

func TestPages(t *testing.T) {
	e := newEnv(t)
	if index := e.get(e.srv.URL + "/"); !bytes.Contains(index, []byte(`id="root"`)) || !bytes.Contains(index, []byte(`value="CN=Тестовый УЦ (уровень 1) (`)) {
		t.Fatal("no root form with a test name on the index page")
	}
	root := e.create("/new", map[string]any{"subject": "CN=Корень,O=TUC"})
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter,O=<b>x</b>", "closed": true})
	page := e.get(inter.URL + "/")
	for _, want := range []string{"<title>Inter</title>", "Подчинённый УЦ", `href="/` + root.ID + `"`, "Выпуск по ссылке", inter.ID,
		`<span data-tuc>` + inter.URL + `</span>`, `data-purpose="both" data-response="cert"`, "&lt;b&gt;x&lt;/b&gt;"} {
		if !bytes.Contains(page, []byte(want)) {
			t.Fatalf("CA page lacks %q", want)
		}
	}
	if bytes.Contains(page, []byte(inter.Admin)) || bytes.Contains(page, []byte(root.Admin)) || bytes.Contains(page, []byte("<b>x</b>")) {
		t.Fatal("CA page shows a token or unescaped name")
	}
	resp, _ := http.Get(e.srv.URL + "/" + strings.Repeat("A", 40))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !bytes.Contains(body, []byte("УЦ не найден")) {
		t.Fatalf("missing CA page: %d", resp.StatusCode)
	}
}

func TestListFlags(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter"})
	e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Тестовый"})
	rows := func(q string) []certRow {
		_, out := e.post("/"+root.ID+"/list", map[string]any{"token": root.Admin, "q": q})
		var r []certRow
		json.Unmarshal(out, &r)
		return r
	}
	if r := rows("ТЕСТОВЫЙ"); len(r) != 1 {
		t.Fatalf("search of a Cyrillic name in another case: %+v", r)
	}
	if r := rows("inter"); len(r) != 1 {
		t.Fatalf("search in another case: %+v", r)
	}
	colons := strings.Join(regexp.MustCompile(`..`).FindAllString(strings.ToLower(inter.ID), -1), ":")
	if r := rows(colons); len(r) != 1 || !r[0].CA || !r[0].Live || len(r[0].DER) == 0 || r[0].NotBefore.IsZero() || !r[0].NotBefore.Before(r[0].NotAfter) {
		t.Fatalf("search by SHA-1 with colons: %+v", r)
	}
	if err := Delete(e.db, inter.ID); err != nil {
		t.Fatal(err)
	}
	if r := rows("inter"); len(r) != 1 || !r[0].CA || r[0].Live || r[0].Revoked == nil {
		t.Fatalf("a deleted intermediate: %+v", r)
	}
}

func TestParseName(t *testing.T) {
	for _, bad := range []string{"", "CN", "XX=1", "CN=", "1=x"} {
		if _, err := ParseName(bad); err == nil {
			t.Errorf("ParseName(%q) accepted", bad)
		}
	}
	der, err := ParseName(`CN=a\,b,1.2.3.4=v,O=Org`)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(der, []byte("a,b")) {
		t.Fatalf("escaped comma lost: %x", der)
	}
}

func TestSecret(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	s, _ := NewSecret(raw)
	sealed := s.Encrypt([]byte("key"))
	if plain, err := s.Decrypt(sealed); err != nil || string(plain) != "key" {
		t.Fatalf("round trip: %v %q", err, plain)
	}
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 1
		if _, err := s.Decrypt(bad); err == nil {
			t.Fatalf("changed at byte %d, decrypts", i)
		}
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("MINIPKI_GOST_ENGINE") == "" {
		fmt.Println("MINIPKI_GOST_ENGINE is not set")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// pageCommand is the text of the first command of a CA page with the pre
// attributes attrs.
func pageCommand(t *testing.T, page []byte, attrs string) string {
	m := regexp.MustCompile(`(?s)<pre ` + regexp.QuoteMeta(attrs) + `[^>]*>(.*?)</pre>`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("no command %s on the page", attrs)
	}
	return html.UnescapeString(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(string(m[1]), ""))
}

func TestEST(t *testing.T) { forAlgos(t, testEST) }

func testEST(t *testing.T, e *env) {
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	inter := e.create("/"+root.ID+"/new", map[string]any{"token": root.Admin, "subject": "CN=Inter", "closed": true})
	rootDER, interDER := e.get(root.URL+".crt"), e.get(inter.URL+".crt")
	est := e.srv.URL + "/.well-known/est/" + inter.ID
	p7, err := b64.StdEncoding.DecodeString(string(e.get(est + "/cacerts")))
	if err != nil {
		t.Fatal(err)
	}
	if c := certsOf(t, p7); len(c) != 2 || !bytes.Equal(c[0], interDER) || !bytes.Equal(c[1], rootDER) {
		t.Fatal("cacerts is not the intermediate and its root")
	}

	page := e.get(inter.URL)
	enroll := pageCommand(t, page, `data-os="openssl" data-tool="openssl" data-purpose="user" data-response="chain"`)
	revoke := pageCommand(t, page, `data-os="openssl" data-tool="openssl" class="revoke off"`)
	dir := t.TempDir()
	run := func(script string) error {
		cmd := exec.Command("sh", "-c", script)
		cmd.Dir, cmd.Env = dir, append(os.Environ(), "USER=tester")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	if err := run(enroll); err == nil {
		t.Fatal("EST issued for a closed CA without the issue token")
	}
	issue := e.enrollURL(inter.ID, inter.Admin)[len(inter.URL)+1:]
	withToken := func(cmd string) string { return strings.Replace(cmd, "EST=http://", "EST=http://tuc:"+issue+"@", 1) }
	if err := run(withToken(enroll) + "\necho \"$NAME\" > name"); err != nil {
		t.Fatalf("page EST command: %v", err)
	}
	name, _ := os.ReadFile(filepath.Join(dir, "name"))
	pemCerts, _ := os.ReadFile(filepath.Join(dir, strings.TrimSpace(string(name))+".crt"))
	var certs [][]byte
	for b, rest := pem.Decode(pemCerts); b != nil; b, rest = pem.Decode(rest) {
		certs = append(certs, b.Bytes)
	}
	if len(certs) != 3 || !bytes.Equal(certs[1], interDER) || !bytes.Equal(certs[2], rootDER) {
		t.Fatalf("%d certificates, want the leaf, the intermediate and the root", len(certs))
	}
	crls := func() [][]byte { return [][]byte{e.get(root.URL + ".crl"), e.get(inter.URL + ".crl")} }
	if err := e.mp.VerifyChain(certs[0], [][]byte{rootDER}, [][]byte{interDER}, crls()); err != nil {
		t.Fatal(err)
	}
	tls := pageCommand(t, page, `data-os="openssl" data-tool="openssl" data-purpose="both" data-response="chain"`)
	if err := run(withToken(strings.Replace(tls, "<FQDN>", "srv.example", 1))); err != nil {
		t.Fatalf("page EST command for TLS: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "srv.example-TUC-*.crt")); len(m) != 1 {
		t.Fatal("no TLS certificate")
	} else {
		b, _ := os.ReadFile(m[0])
		p, rest := pem.Decode(b)
		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil || len(c.DNSNames) != 1 || c.DNSNames[0] != "srv.example" || len(c.ExtKeyUsage) != 2 {
			t.Fatalf("TLS certificate: %v %+v", err, c)
		}
		if p, _ := pem.Decode(rest); p == nil {
			t.Fatal("the TLS certificate came without the chain")
		}
	}
	// The page check: the chain, CRL and OCSP, good and then revoked
	check := pageCommand(t, page, `data-os="openssl" data-tool="openssl" class="verify off"`)
	verify := func() string {
		cmd := exec.Command("sh", "-c", "NAME="+strings.TrimSpace(string(name))+"\n"+check)
		cmd.Dir = dir
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	if out := verify(); strings.Count(out, ".leaf.pem: OK") != 2 || !strings.Contains(out, ".leaf.pem: good") || !strings.Contains(out, "Response verify OK") {
		t.Fatalf("page check of a good certificate:\n%s", out)
	}
	if err := run("NAME=" + strings.TrimSpace(string(name)) + "\n" + revoke); err != nil {
		t.Fatalf("page revoke command: %v", err)
	}
	if out := verify(); strings.Count(out, ".leaf.pem: OK") != 1 || !strings.Contains(out, "certificate revoked") || !strings.Contains(out, ".leaf.pem: revoked") {
		t.Fatalf("page check of a revoked certificate:\n%s", out)
	}
	if err := e.mp.VerifyChain(certs[0], [][]byte{rootDER}, [][]byte{interDER}, crls()); err == nil {
		t.Fatal("the leaf revoked with the page command still verifies")
	}

	req, _ := http.NewRequest("POST", est+"/simplereenroll", bytes.NewReader(csr(t, e)))
	req.SetBasicAuth("", issue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/pkcs7-mime; smime-type=certs-only" {
		t.Fatalf("simplereenroll: %d %s", resp.StatusCode, body)
	}

	// The page check finds the intermediate revoked by its root by the CRL of
	// the whole chain
	time.Sleep(time.Second)
	if err := run(withToken(enroll) + "\necho \"$NAME\" > name"); err != nil {
		t.Fatalf("page EST command: %v", err)
	}
	name, _ = os.ReadFile(filepath.Join(dir, "name"))
	if out := verify(); strings.Count(out, ".leaf.pem: OK") != 2 {
		t.Fatalf("page check of a second certificate:\n%s", out)
	}
	if code, out := e.post("/"+inter.ID+"/revoke", map[string]any{"token": inter.Admin, "self": true}); code != http.StatusOK {
		t.Fatalf("revoke the intermediate: %d %s", code, out)
	}
	if out := verify(); !strings.Contains(out, "error 23 at 1 depth lookup: certificate revoked") {
		t.Fatalf("page check under a revoked intermediate:\n%s", out)
	}
}

func TestPageVerifyWithoutRevocationURLs(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=No revocation URLs"})
	e.issuance(root, issuance{Days: 365})
	page := e.get(root.URL)
	enroll := pageCommand(t, page, `data-os="openssl" data-tool="openssl" data-purpose="user" data-response="chain"`)
	check := pageCommand(t, page, `data-os="openssl" data-tool="openssl" class="verify off"`)
	cmd := exec.Command("sh", "-c", enroll+"\n"+check)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte(".leaf.pem: OK")) || !bytes.Contains(out, []byte("нет CDP")) || !bytes.Contains(out, []byte("нет адреса OCSP")) || bytes.Contains(out, []byte("Error parsing URL")) {
		t.Fatalf("page verification without revocation URLs: %v\n%s", err, out)
	}
}

// A PFX names its certificate, whose status the CA tells from then on.
func TestCertStatus(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	body, _ := json.Marshal(map[string]any{"name": "status", "password": "pw"})
	resp, err := http.Post(e.srv.URL+"/"+root.ID+"/pfx", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	id := resp.Header.Get("X-TUC-Certificate")
	if resp.StatusCode != http.StatusOK || len(id) != 40 {
		t.Fatalf("PFX: %d, certificate %q", resp.StatusCode, id)
	}
	status := func(cert string) (int, string) {
		r, err := http.Get(e.srv.URL + "/" + root.ID + "/cert/" + cert + "/status")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, strings.TrimSpace(string(b))
	}
	if code, got := status(id); code != http.StatusOK || got != `{"revoked":null}` {
		t.Fatalf("status before revocation: %d %s", code, got)
	}
	if code, b := e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": id}); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, b)
	}
	if code, got := status(strings.ToLower(id)); code != http.StatusOK || !strings.HasPrefix(got, `{"revoked":"`) {
		t.Fatalf("status after revocation: %d %s", code, got)
	}
	if code, _ := status(strings.Repeat("0", 40)); code != http.StatusNotFound {
		t.Fatalf("status of a certificate the CA did not issue: %d", code)
	}
}
