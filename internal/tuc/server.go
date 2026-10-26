package tuc

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Handler serves the pages, the public endpoints (enroll, revoke by the
// holder, CA certificate, CRL) and the admin endpoints of the pages, which
// take the admin token of that CA:
//
//	GET  /                                   page to create a root CA
//	POST /new                                create a root CA
//	GET  /{id}                               page of a CA; with #token=<admin> its admin's
//	GET  /{id}.crt, /{id}.crl                CA certificate, CRL
//	POST /{id}/ocsp, GET /{id}/ocsp/{request}
//	                                         OCSP (RFC 6960) of what the CA issued, the request in
//	                                         the body or URL-encoded base64 in the path
//	GET  /{id}/cert/{sha1}.crt               a certificate the CA issued; also .cer or bare
//	POST /{id}[/{issue}][/justcert]/certfnsh.asp
//	                                         issue a leaf certificate to cryptcp -ca /{id}[/{issue}][/justcert]
//	POST /{id}[/{issue}]/pfx                 {"name", "algo", "tls", "fqdn", "password"}: a key made by
//	                                         the CA and a leaf certificate of it in a PKCS#12
//	POST /{id}/tsp                           time-stamp (RFC 3161) by the time-stamping
//	                                         certificate of the CA
//	POST /{id}[/{issue}]/revoke              revoke: the certificate that signed "revoke", a CMS
//	                                         SignedData in the body, or {"token", "cert"}, or the CA
//	                                         itself at its issuer, {"token", "self": true}
//	GET  /.well-known/est/{id}/cacerts       EST (RFC 7030): the CA chain
//	POST /.well-known/est/{id}/simpleenroll, /simplereenroll
//	                                         EST: issue a leaf certificate; a CA that issues by
//	                                         link takes the issue token as the HTTP Basic password
//	POST /{id}/admin                         {"token"}: admin details
//	POST /{id}/rotate                        {"token", "role": "admin" or "issue"}: replace a link
//	POST /{id}/new                           {"token", "subject", "from", "days", "closed"}: create a CA under id
//	POST /{id}/list                          {"token", "q", "offset"}: certificates the CA issued
//	POST /{id}/closed                        {"token", "closed"}
//	POST /{id}/issuance                      {"token", "issuance": {"crl", "ocsp", "from", "days"}}:
//	                                         CRL and OCSP URLs in what the CA issues, the start of
//	                                         a leaf in days from its issue, which may be negative,
//	                                         and its days
//	POST /{id}/disabled                      {"token", "disabled"}: a disabled CA answers 503 to
//	                                         its services; its admin requests work
func (s *Service) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /livez", s.health)
	m.HandleFunc("GET /readyz", s.health)
	m.HandleFunc("GET /{$}", s.indexPage)
	m.HandleFunc("POST /new", s.create)
	m.HandleFunc("GET /{id}", s.caGet)
	m.HandleFunc("GET /{id}/cert/{cert}", s.issuedCert)
	m.HandleFunc("POST /{id}/ocsp", s.ocsp)
	m.HandleFunc("GET /{id}/ocsp/{req...}", s.ocsp)
	m.HandleFunc("POST /{id}/certfnsh.asp", s.enroll)
	m.HandleFunc("POST /{id}/justcert/certfnsh.asp", s.enroll)
	m.HandleFunc("POST /{id}/{issue}/certfnsh.asp", s.enroll)
	m.HandleFunc("POST /{id}/{issue}/justcert/certfnsh.asp", s.enroll)
	m.HandleFunc("GET /.well-known/est/{id}/cacerts", s.estCACerts)
	m.HandleFunc("POST /.well-known/est/{id}/simpleenroll", s.estEnroll)
	m.HandleFunc("POST /.well-known/est/{id}/simplereenroll", s.estEnroll)
	m.HandleFunc("POST /{id}/pfx", s.pfx)
	m.HandleFunc("POST /{id}/{issue}/pfx", s.pfx)
	m.HandleFunc("POST /{id}/tsp", s.tsp)
	m.HandleFunc("POST /{id}/revoke", s.revoke)
	m.HandleFunc("POST /{id}/{issue}/revoke", s.revoke)
	m.HandleFunc("POST /{id}/admin", s.admin)
	m.HandleFunc("POST /{id}/rotate", s.rotate)
	m.HandleFunc("POST /{id}/new", s.create)
	m.HandleFunc("POST /{id}/list", s.list)
	m.HandleFunc("POST /{id}/closed", s.setClosed)
	m.HandleFunc("POST /{id}/issuance", s.setIssuance)
	m.HandleFunc("POST /{id}/disabled", s.setDisabled)
	return logged(tidy(s.gate(m)))
}

// tidy drops empty path segments, as cryptcp -ca with a trailing slash
// makes, and a trailing slash.
func tidy(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var parts []string
		for _, p := range strings.Split(r.URL.Path, "/") {
			if p != "" {
				parts = append(parts, p)
			}
		}
		r.URL.Path = "/" + strings.Join(parts, "/")
		r.URL.RawPath = ""
		h.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// logged logs each request with the issue token, a secret, left out of its
// path.
func logged(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{w, http.StatusOK}
		h.ServeHTTP(sw, r)
		parts := strings.Split(r.URL.Path, "/")
		for i, p := range parts {
			if i == 2 && len(p) > 16 && !idRe.MatchString(p) {
				parts[i] = "…"
			}
		}
		log.Printf("%s %s %s %d", r.RemoteAddr, r.Method, strings.Join(parts, "/"), sw.status)
	})
}

type request struct {
	Token    string    `json:"token"`
	From     int       `json:"from"`
	Role     string    `json:"role"`
	Subject  string    `json:"subject"`
	Algo     algo      `json:"algo"`
	Days     int       `json:"days"`
	Closed   bool      `json:"closed"`
	Disabled bool      `json:"disabled"`
	Cert     string    `json:"cert"`
	Q        string    `json:"q"`
	Self     bool      `json:"self"`
	Offset   int       `json:"offset"`
	Issuance *issuance `json:"issuance"`
	Name     string    `json:"name"`
	TLS      bool      `json:"tls"`
	FQDN     string    `json:"fqdn"`
	Password string    `json:"password"`
}

func fail(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// node opens the CA of the request path; the caller closes it.
func (s *Service) node(w http.ResponseWriter, r *http.Request) *node {
	var n *node
	var err error
	if s.secret.Load() == nil {
		n, err = s.openNode(r.PathValue("id"))
	} else {
		n, err = s.open(r.PathValue("id"))
	}
	switch {
	case errors.Is(err, errNotFound):
		fail(w, http.StatusNotFound, errors.New("no such CA"))
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
	}
	return n
}

var errDisabled = errors.New("this CA is disabled")

// serving opens the CA of the request path for a service of it, which a
// disabled CA does not give; the caller closes it.
func (s *Service) serving(w http.ResponseWriter, r *http.Request) *node {
	n := s.node(w, r)
	if n != nil && n.disabled {
		n.Close()
		fail(w, http.StatusServiceUnavailable, errDisabled)
		return nil
	}
	return n
}

func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, errors.New("нужен Content-Type: application/json"))
		return false
	}
	return true
}

func readRequest(w http.ResponseWriter, r *http.Request) (*request, bool) {
	if !requireJSON(w, r) {
		return nil, false
	}
	var req request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return nil, false
	}
	return &req, true
}

// administered opens the CA of the request path for a request with its
// admin token; the caller closes it.
func (s *Service) administered(w http.ResponseWriter, r *http.Request) (*node, *request) {
	req, ok := readRequest(w, r)
	if !ok {
		return nil, nil
	}
	n := s.node(w, r)
	if n == nil {
		return nil, nil
	}
	if !s.IsAdmin(n, req.Token) {
		n.Close()
		fail(w, http.StatusForbidden, errors.New("not the admin token of this CA"))
		return nil, nil
	}
	return n, req
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	var parent *node
	var req *request
	if r.PathValue("id") != "" {
		if parent, req = s.administered(w, r); parent == nil {
			return
		}
		defer parent.Close()
		if parent.disabled {
			fail(w, http.StatusServiceUnavailable, errDisabled)
			return
		}
	} else {
		var ok bool
		if req, ok = readRequest(w, r); !ok {
			return
		}
	}
	if req.Days == 0 {
		req.Days = 3650
	}
	id, err := s.Create(parent, req.Algo, req.Subject, req.From, req.Days, req.Closed)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, map[string]string{"id": id, "admin": s.token(id, "admin"), "url": s.caURL(id)})
}

func (s *Service) admin(w http.ResponseWriter, r *http.Request) {
	n, _ := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	issue := s.token(n.id, "issue")
	enroll := s.caURL(n.id)
	if n.closed {
		enroll += "/" + issue
	}
	reply(w, map[string]any{"admin": s.token(n.id, "admin"), "issue": issue, "closed": n.closed, "disabled": n.disabled, "enroll": enroll, "issuance": n.iss})
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	n, req := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	rows, err := s.st.certs(n.id, strings.TrimSpace(req.Q), max(req.Offset, 0), 100)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []certRow{}
	}
	reply(w, rows)
}

func (s *Service) setClosed(w http.ResponseWriter, r *http.Request) {
	n, req := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	if err := s.st.setClosed(n.id, req.Closed); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	reply(w, map[string]bool{"closed": req.Closed})
}

func (s *Service) setDisabled(w http.ResponseWriter, r *http.Request) {
	n, req := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	if err := s.st.setDisabled(n.id, req.Disabled); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	reply(w, map[string]bool{"disabled": req.Disabled})
}

func (s *Service) setIssuance(w http.ResponseWriter, r *http.Request) {
	n, req := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	if req.Issuance == nil {
		fail(w, http.StatusBadRequest, errors.New("no issuance"))
		return
	}
	if err := s.SetIssuance(n, *req.Issuance); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, req.Issuance)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	n := s.node(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	if trimmed := strings.TrimSpace(string(body)); trimmed == "" || trimmed[0] != '{' {
		if n.disabled {
			fail(w, http.StatusServiceUnavailable, errDisabled)
			return
		}
		cms, err := unarmor(body)
		if err != nil {
			fail(w, http.StatusBadRequest, errors.New("the body is neither JSON nor a CMS SignedData in DER, PEM or base64"))
			return
		}
		id, err := s.RevokeSigner(n, cms)
		if err != nil {
			fail(w, http.StatusForbidden, err)
			return
		}
		reply(w, map[string]string{"revoked": id})
		return
	}
	if !requireJSON(w, r) {
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if !s.IsAdmin(n, req.Token) {
		fail(w, http.StatusForbidden, errors.New("not the admin token of this CA"))
		return
	}
	issuer, cert := n.id, strings.ToUpper(req.Cert)
	if req.Self {
		if n.parent == nil {
			fail(w, http.StatusBadRequest, errors.New("a root CA has no issuer to revoke it"))
			return
		}
		issuer, cert = n.parent.id, n.id
	}
	switch err := s.revokeCertificate(issuer, cert); {
	case errors.Is(err, errNotFound):
		fail(w, http.StatusNotFound, errors.New("this CA issued no such certificate"))
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
	default:
		reply(w, map[string]string{"revoked": cert})
	}
}

// caGet serves at /{id} the page of the CA, at /{id}.crt its certificate and
// at /{id}.crl its CRL.
func (s *Service) caGet(w http.ResponseWriter, r *http.Request) {
	id, ext, _ := strings.Cut(r.PathValue("id"), ".")
	switch ext {
	case "crt":
		r.SetPathValue("id", id)
		s.caCert(w, r)
	case "crl":
		r.SetPathValue("id", id)
		s.crl(w, r)
	default:
		s.caPage(w, r)
	}
}

// file answers with a DER object of contentType, saved as name, last
// modified at modified if that is not zero.
func file(w http.ResponseWriter, r *http.Request, contentType, name string, modified time.Time, der []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, modified, bytes.NewReader(der))
}

// immutable caches a certificate, which its address names by its SHA-1.
const immutable = "public, max-age=604800, immutable"

func (s *Service) caCert(w http.ResponseWriter, r *http.Request) {
	if n := s.serving(w, r); n != nil {
		defer n.Close()
		w.Header().Set("Cache-Control", immutable)
		file(w, r, "application/pkix-cert", "ca-"+n.id+".crt", time.Time{}, n.der)
	}
}

func (s *Service) issuedCert(w http.ResponseWriter, r *http.Request) {
	n := s.serving(w, r)
	if n == nil {
		return
	}
	n.Close()
	id, _, _ := strings.Cut(strings.ToUpper(r.PathValue("cert")), ".")
	der, err := s.st.certDER(strings.ToUpper(r.PathValue("id")), id)
	if err != nil {
		fail(w, http.StatusNotFound, errors.New("no such certificate"))
		return
	}
	w.Header().Set("Cache-Control", immutable)
	file(w, r, "application/pkix-cert", "cert-"+id+".crt", time.Time{}, der)
}

func (s *Service) crl(w http.ResponseWriter, r *http.Request) {
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	sealed := s.secret.Load() == nil
	var der []byte
	var err error
	if sealed {
		der, _, err = s.savedCRL(n)
	} else {
		der, _, err = s.CRL(n)
	}
	if err != nil {
		if sealed {
			sealedReply(w, r)
		} else {
			fail(w, http.StatusInternalServerError, err)
		}
		return
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil || parsed.Number == nil {
		fail(w, http.StatusInternalServerError, errors.New("CRL has no valid number"))
		return
	}
	w.Header().Set("ETag", `"`+parsed.Number.String()+`"`)
	file(w, r, "application/pkix-crl", "crl-"+n.id+".crl", time.Time{}, der)
}

// ocsp answers an OCSP request; a GET reads it from the path as sent, which
// tidy may change: base64 has "/" and may have "//".
func (s *Service) ocsp(w http.ResponseWriter, r *http.Request) {
	var req []byte
	var err error
	if r.Method == http.MethodGet {
		_, enc, _ := strings.Cut(strings.SplitN(r.RequestURI, "?", 2)[0], "/ocsp/")
		if enc, err = url.PathUnescape(enc); err == nil {
			req, err = base64.StdEncoding.DecodeString(enc)
		}
	} else {
		req, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	}
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	resp := ocspError(ocspMalformed)
	if err == nil {
		resp = s.OCSP(n, req)
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(resp)
}

// fileName matches what a file name of a certificate name leaves out.
var fileName = regexp.MustCompile(`[^\pL\pN._-]+`)

// pfx issues a key and its certificate in a PKCS#12, as enroll issues: at
// a closed CA only with its issue token.
func (s *Service) pfx(w http.ResponseWriter, r *http.Request) {
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	req, ok := readRequest(w, r)
	if !ok {
		return
	}
	if issue := r.PathValue("issue"); issue != "" {
		if !s.checkToken(n.id, "issue", issue) {
			fail(w, http.StatusForbidden, errors.New("not the issue token of this CA"))
			return
		}
	} else if n.closed {
		fail(w, http.StatusForbidden, errors.New("this CA issues only with its issue token"))
		return
	}
	p12, err := s.IssuePFX(n, req.Algo, strings.TrimSpace(req.Name), req.TLS, strings.TrimSpace(req.FQDN), req.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	file(w, r, "application/x-pkcs12", fileName.ReplaceAllString(strings.TrimSpace(req.Name), "_")+".pfx", time.Time{}, p12)
}

func (s *Service) tsp(w http.ResponseWriter, r *http.Request) {
	req, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	resp, err := s.TSP(n, req)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Write(resp)
}

// enroll answers as the Microsoft CA web enrollment page of the CryptoPro test
// CA that cryptcp -createcert -ca reads: a signed CMC response with the
// certificate and its chain, or only the certificate at /justcert, in sPKCS7
// lines of a script. A page without them is a rejection.
func (s *Service) enroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	reject := func(err error) {
		log.Printf("enroll: %v", err)
		fmt.Fprintf(w, "<HTML><Body>%s</Body></HTML>\n", html.EscapeString(err.Error()))
	}
	n, err := s.open(r.PathValue("id"))
	if err != nil {
		reject(err)
		return
	}
	defer n.Close()
	if n.disabled {
		http.Error(w, errDisabled.Error(), http.StatusServiceUnavailable)
		return
	}
	if issue := r.PathValue("issue"); issue != "" {
		if !s.checkToken(n.id, "issue", issue) {
			reject(errors.New("not the issue token of this CA"))
			return
		}
	} else if n.closed {
		reject(errors.New("this CA issues only with its issue token"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	cert, err := s.Issue(n, r.PostFormValue("CertRequest"))
	if err != nil {
		reject(err)
		return
	}
	resp, err := s.EnrollResponse(n, cert, !strings.HasSuffix(r.URL.Path, "/justcert/certfnsh.asp"))
	if err != nil {
		reject(err)
		return
	}
	p7 := base64.StdEncoding.EncodeToString(resp)
	var b strings.Builder
	b.WriteString("<HTML><Script Language=\"VBScript\">\n\tsPKCS7=\"\"\n")
	for len(p7) > 0 {
		k := min(64, len(p7))
		fmt.Fprintf(&b, "\tsPKCS7=sPKCS7 & \"%s\" & vbNewLine\n", p7[:k])
		p7 = p7[k:]
	}
	b.WriteString("</Script></HTML>\n")
	w.Write([]byte(b.String()))
}

func (s *Service) rotate(w http.ResponseWriter, r *http.Request) {
	n, req := s.administered(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	generation, err := s.st.tokenGeneration(n.id, req.Role, true)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply(w, map[string]string{"token": s.secret.Load().Token(n.id, req.Role, generation)})
}
