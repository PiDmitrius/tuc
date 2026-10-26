// Package tuc is a test certification authority with GOST, RSA and ECDSA
// keys: CAs, what they issued
// and revocations live in SQLite, CA keys encrypted with the service secret.
package tuc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// maxLevel is the deepest CA: certview shows a chain of up to 9
	// certificates, a leaf under 8 CAs, without a depth warning.
	maxLevel = 8
	// A CRL is published hourly and on a revocation and is valid for a week,
	// as the CRLs of public issuing CAs: a CRL newer than a time-stamp is
	// there within an hour.
	crlLifetime  = 7 * 24 * time.Hour
	crlRepublish = time.Hour
	backdate     = time.Minute
)

type Service struct {
	secret    atomic.Pointer[Secret]
	unsealMu  sync.Mutex
	mp        *mp.Ctx
	base      string // URL prefix of the pages and issuance
	publish   string // URL prefix of certificate publication
	st        *store
	serviceMu sync.Mutex // makes a service certificate once
	crlMu     sync.Mutex // serializes CRL publication and revocation
}

func NewService(ctx *mp.Ctx, base, db, publish string) (*Service, error) {
	st, err := openStore(db)
	if err != nil {
		return nil, err
	}
	publication := base
	if publish != "" {
		publication = publish
	}
	return &Service{mp: ctx, base: strings.TrimRight(base, "/"), publish: strings.TrimRight(publication, "/"), st: st}, nil
}

// node is a CA opened up to its root; its key is decrypted at the first
// signature, by key.
type node struct {
	id       string
	closed   bool
	disabled bool // its services answer 503
	iss      issuance
	der      []byte
	cert     *x509.Certificate
	alg      algo
	sealed   []byte
	key      *mp.Key
	parent   *node
}

// key is the key of n.
func (s *Service) key(n *node) (*mp.Key, error) {
	if n.key == nil {
		raw, err := s.secret.Load().Decrypt(n.sealed)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		if n.key, err = s.importKey(n.alg, raw); err != nil {
			return nil, err
		}
	}
	return n.key, nil
}

// level is 1 for a root and one more for each CA below.
func (n *node) level() int {
	l := 0
	for ; n != nil; n = n.parent {
		l++
	}
	return l
}

// Close closes the keys of n and of the CAs above it.
func (n *node) Close() {
	for ; n != nil; n = n.parent {
		if n.key != nil {
			n.key.Close()
		}
	}
}

func (s *Service) caURL(id string) string { return s.base + "/" + id }

func (s *Service) publicationURL(id string) string { return s.publish + "/" + id }

func (s *Service) estURL(id string) string { return s.base + "/.well-known/est/" + id }

// certID is the SHA-1 of a certificate in upper-case hex, as certview
// writes it.
func certID(der []byte) string {
	h := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// hexSerial writes a serial number in upper-case hex.
func hexSerial(n *big.Int) string { return strings.ToUpper(n.Text(16)) }

var idRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)

// open opens the CA id, which marks it used; the caller closes it.
func (s *Service) open(id string) (*node, error) {
	n, err := s.openNode(id)
	if err == nil {
		err = s.st.touch(n.id, time.Now())
	}
	if err != nil && n != nil {
		n.Close()
		return nil, err
	}
	return n, err
}

func (s *Service) openNode(id string) (_ *node, err error) {
	if !idRe.MatchString(id) {
		return nil, errNotFound
	}
	id = strings.ToUpper(id)
	r, err := s.st.ca(id)
	if err != nil {
		return nil, err
	}
	n := &node{id: id, closed: r.closed, disabled: r.disabled, iss: r.issuance, der: r.cert, sealed: r.key}
	defer func() {
		if err != nil {
			n.Close()
		}
	}()
	if r.parent != "" {
		if n.parent, err = s.openNode(r.parent); err != nil {
			return nil, err
		}
	}
	if n.cert, err = x509.ParseCertificate(r.cert); err != nil {
		return nil, err
	}
	n.alg = algoOf(n.cert)
	return n, nil
}

// newKey makes a key of a and its stored form: the raw GOST key or PKCS#8.
func (s *Service) newKey(a algo) (*mp.Key, []byte, error) {
	var priv any
	var err error
	switch a.Family() {
	case "gost":
		k, err := s.mp.GenerateKey(a.Bits())
		if err != nil {
			return nil, nil, err
		}
		return k, k.Raw(), nil
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, a.Bits())
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(map[int]elliptic.Curve{256: elliptic.P256(), 384: elliptic.P384(), 521: elliptic.P521()}[a.Bits()], rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	k, err := s.importKey(a, der)
	if err != nil {
		clear(der)
		return nil, nil, err
	}
	return k, der, nil
}

// sign is the signatureValue of tbs by k, a key of a.
func sign(k *mp.Key, a algo, tbs []byte) ([]byte, error) {
	if d := algoDefs[a].digest; d != "" {
		return k.SignDigest(d, tbs)
	}
	return k.Sign(tbs)
}

func (s *Service) importKey(a algo, stored []byte) (*mp.Key, error) {
	if a.Family() == "gost" {
		return s.mp.ImportKey(stored)
	}
	return s.mp.ImportPKCS8(stored)
}

func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = b[0]&0x7f | 0x40
	return new(big.Int).SetBytes(b), nil
}

// Create makes a CA with a key of a, by default the algorithm of parent or
// else the first one, issued by parent, or a root when parent is nil, valid
// from days after creation for days days, within its parent, and returns its id.
func (s *Service) Create(parent *node, a algo, subject string, from, days int, closed bool) (string, error) {
	name, err := ParseName(subject)
	if err != nil {
		return "", err
	}
	if from < -36500 || from > 36500 {
		return "", errors.New("начало — от -36500 до 36500 дней")
	}
	if days <= 0 || days > 36500 {
		return "", errors.New("срок — от 1 до 36500 дней")
	}
	if parent != nil {
		if parent.level() >= maxLevel {
			return "", fmt.Errorf("глубина иерархии — не больше %d уровней", maxLevel)
		}
	}
	if a == "" {
		a = algos[0]
		if parent != nil {
			a = parent.alg
		}
	}
	if _, ok := algoDefs[a]; !ok {
		return "", errors.New("неизвестный алгоритм")
	}
	key, raw, err := s.newKey(a)
	if err != nil {
		return "", err
	}
	defer key.Close()
	defer clear(raw)
	spki, err := key.SPKI()
	if err != nil {
		return "", err
	}
	ski, err := keyID(spki)
	if err != nil {
		return "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, from)
	t := &certTemplate{
		serial: serial, alg: a, subject: name, issuer: name,
		notBefore: now.Add(-backdate), notAfter: now.AddDate(0, 0, days),
		spki: spki, ca: true, ski: ski, aki: ski,
	}
	signer, parentID := key, ""
	if parent != nil {
		if t.notBefore.Before(parent.cert.NotBefore) {
			t.notBefore = parent.cert.NotBefore
		}
		t.issuer, t.aki, t.issuerURL, t.crl, t.ocsp = parent.cert.RawSubject, parent.cert.SubjectKeyId, s.publicationURL(parent.id), parent.iss.CRL, parent.iss.OCSP
		if t.notAfter.After(parent.cert.NotAfter) {
			t.notAfter = parent.cert.NotAfter
		}
		if !t.notAfter.After(t.notBefore) {
			return "", errors.New("срок выпуска УЦ лежит за пределами срока родительского УЦ")
		}
		if signer, err = s.key(parent); err != nil {
			return "", err
		}
		parentID, t.alg = parent.id, parent.alg
	}
	tbs, err := t.tbs()
	if err != nil {
		return "", err
	}
	sig, err := sign(signer, t.alg, tbs)
	if err != nil {
		return "", err
	}
	der := signed(tbs, sig, t.alg)
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", fmt.Errorf("the CA certificate would not parse: %w", err)
	}
	id := certID(der)
	err = s.st.addCA(&caRow{id: id, parent: parentID, cert: der, key: s.secret.Load().Encrypt(raw), closed: closed},
		&certRow{ID: id, Serial: hexSerial(t.serial), Subject: nameString(name), NotAfter: t.notAfter, CA: true})
	return id, err
}

// pemMarker matches PEM BEGIN and END lines, which cryptcp sends with the
// base64 between them on the same line.
var pemMarker = regexp.MustCompile(`-----[A-Z0-9 ]+-----`)

// unarmor reads DER, or PEM or bare base64 of it.
func unarmor(in []byte) ([]byte, error) {
	if len(in) > 0 && in[0] == 0x30 {
		return in, nil
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(pemMarker.ReplaceAllString(string(in), "")), ""))
}

// parseRequest reads a PKCS#10 request.
func parseRequest(der []byte) (subject, spki []byte, attrs []cryptobyte.String, err error) {
	bad := errors.New("bad PKCS#10 request")
	s := cryptobyte.String(der)
	var req, info, set cryptobyte.String
	var subj, key cryptobyte.String
	if !s.ReadASN1(&req, cbasn1.SEQUENCE) || !req.ReadASN1(&info, cbasn1.SEQUENCE) ||
		!info.SkipASN1(cbasn1.INTEGER) ||
		!info.ReadASN1Element(&subj, cbasn1.SEQUENCE) ||
		!info.ReadASN1Element(&key, cbasn1.SEQUENCE) {
		return nil, nil, nil, bad
	}
	if info.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		if !info.ReadASN1(&set, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, nil, nil, bad
		}
		for !set.Empty() {
			var a cryptobyte.String
			if !set.ReadASN1(&a, cbasn1.SEQUENCE) {
				return nil, nil, nil, bad
			}
			attrs = append(attrs, a)
		}
	}
	return subj, key, attrs, nil
}

// Issue verifies a PKCS#10 request and issues with the user or TLS template.
func (s *Service) Issue(n *node, request string, u purpose) ([]byte, error) {
	der, err := unarmor([]byte(request))
	if err != nil {
		return nil, errors.New("не удалось прочитать CSR")
	}

	subject, spki, attrs, err := parseRequest(der)
	if err != nil {
		return nil, err
	}
	if err := checkName(subject); err != nil {
		return nil, err
	}
	if !supportedRequestKey(spki) {
		return nil, errors.New("ключ CSR: нужны RSA 2048/3072/4096, P-256/384/521 или ГОСТ 256/512")
	}
	if err := s.mp.VerifyRequest(der); err != nil {
		return nil, errors.New("неверная подпись CSR или некорректный запрос")
	}
	extra, err := requestTemplate(attrs, u)
	if err != nil {
		return nil, err
	}
	return s.issueLeaf(n, subject, spki, extra)
}

// issueLeaf makes a leaf certificate of n for subject and spki with the
// extensions extra, its key usages those the key can have, as n issues.
func (s *Service) issueLeaf(n *node, subject, spki []byte, extra []cryptobyte.String) ([]byte, error) {
	extra = append(extra, leafKeyUsage(spki))
	start := time.Now().UTC().Truncate(time.Second).AddDate(0, 0, n.iss.From)
	t := &certTemplate{
		subject: subject, spki: spki, notBefore: start.Add(-backdate), notAfter: start.AddDate(0, 0, n.iss.Days),
		issuerURL: s.publicationURL(n.id), crl: n.iss.CRL, ocsp: n.iss.OCSP, extra: extra,
	}
	if t.notAfter.After(n.cert.NotAfter) {
		t.notAfter = n.cert.NotAfter
	}
	if !t.notAfter.After(t.notBefore) {
		return nil, errors.New("срок выпуска УЦ лежит за пределами его собственного срока")
	}
	return s.issueCert(n, t)
}

// issueCert completes t with a random serial, the key identifiers and n as
// the issuer, signs it with n and stores it under n.
func (s *Service) issueCert(n *node, t *certTemplate) ([]byte, error) {
	ski, err := keyID(t.spki)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	t.serial, t.ski, t.alg, t.issuer, t.aki = serial, ski, n.alg, n.cert.RawSubject, n.cert.SubjectKeyId
	tbs, err := t.tbs()
	if err != nil {
		return nil, err
	}
	key, err := s.key(n)
	if err != nil {
		return nil, err
	}
	sig, err := sign(key, n.alg, tbs)
	if err != nil {
		return nil, err
	}
	der := signed(tbs, sig, n.alg)
	err = s.st.addCert(n.id, &certRow{ID: certID(der), Serial: hexSerial(serial), Subject: nameString(t.subject), NotAfter: t.notAfter}, der)
	return der, err
}

// EnrollResponse is a CMS SignedData of a CMC PKIResponse signed by the CA n,
// as the CryptoPro test CA answers, with the certificate cert and, withChain,
// the certificates of n and the CAs above it of the algorithm of their
// issuer.
func (s *Service) EnrollResponse(n *node, cert []byte, withChain bool) ([]byte, error) {
	certs := [][]byte{cert}
	for c := n; withChain && c != nil; c = c.parent {
		// cryptcp installs no response with a CA certificate issued by a CA
		// of another algorithm (0x80090008), but takes it by AIA
		if c.parent == nil || c.parent.alg == c.alg {
			certs = append(certs, c.der)
		}
	}
	key, err := s.key(n)
	if err != nil {
		return nil, err
	}
	return key.SignCMS(n.der, oidPKIResponse, pkiResponse(), certs)
}

// CRL is the current CRL of the CA n and its thisUpdate: the one published
// last, or a new one if a revocation made that stale or it is an hour old.
// A CRL is made when first asked for, but its thisUpdate is when it became
// due, as a CA that publishes ahead has it: the last revocation or the last
// hour since the CA was made, never later than the client asking, which
// CryptoPro CSP needs.
func (s *Service) CRL(n *node) ([]byte, time.Time, error) {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	for {
		der, number, at, err := s.st.crl(n.id)
		if err != nil {
			return nil, time.Time{}, err
		}
		rows, err := s.st.revoked(n.id)
		if err != nil {
			return nil, time.Time{}, err
		}
		now := time.Now().UTC().Truncate(time.Second)
		made := n.cert.NotBefore.Add(backdate)
		if made.After(now) {
			made = now.Truncate(crlRepublish)
		}
		due := made.Add(now.Sub(made) / crlRepublish * crlRepublish)
		if len(rows) > 0 && rows[len(rows)-1].at.After(due) {
			due = rows[len(rows)-1].at.UTC()
		}
		if due.After(now) {
			due = now
		}
		if der != nil && !at.IsZero() && !due.After(at) {
			return der, at, nil
		}
		list := make([]revoked, 0, len(rows))
		for _, r := range rows {
			serial, ok := new(big.Int).SetString(r.serial, 16)
			if !ok {
				return nil, time.Time{}, fmt.Errorf("bad serial %q", r.serial)
			}
			list = append(list, revoked{serial, r.at})
		}
		at = due
		number = max(number+1, at.Unix())
		tbs, err := crlTBS(n.alg, n.cert.RawSubject, n.cert.SubjectKeyId, number, at, at.Add(crlLifetime), list)
		if err != nil {
			return nil, time.Time{}, err
		}
		key, err := s.key(n)
		if err != nil {
			return nil, time.Time{}, err
		}
		sig, err := sign(key, n.alg, tbs)
		if err != nil {
			return nil, time.Time{}, err
		}
		der = signed(tbs, sig, n.alg)
		stored, err := s.st.setCRL(n.id, der, number, at, len(rows))
		if err != nil {
			return nil, time.Time{}, err
		}
		if stored {
			return der, at, nil
		}
	}
}

func (s *Service) revokeCertificate(ca, id string) error {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return s.st.revoke(ca, id)
}

// RevokeSigner revokes the certificate that signed cms, a CMS SignedData of
// the word "revoke" that carries that certificate, when the CA n issued it.
func (s *Service) RevokeSigner(n *node, cms []byte) (string, error) {
	content, signer, err := s.mp.VerifyCMS(cms, nil)
	if err != nil {
		return "", fmt.Errorf("signature: %w", err)
	}
	if strings.TrimSpace(string(content)) != "revoke" {
		return "", errors.New(`the signed text must be "revoke"`)
	}
	id := certID(signer)
	if err := s.revokeCertificate(n.id, id); err != nil {
		if errors.Is(err, errNotFound) {
			return "", errors.New("the signer certificate is not one this CA issued")
		}
		return "", err
	}
	return id, nil
}

// SetIssuance sets how the CA n issues from now on.
func (s *Service) SetIssuance(n *node, i issuance) error {
	if i.Days < 1 || i.Days > 36500 || i.From < -36500 || i.From > 36500 {
		return errors.New("срок — от 1 до 36500 дней, начало — не дальше 36500 дней")
	}
	return s.st.setIssuance(n.id, i)
}

// IsAdmin reports whether token is the admin token of n.
func (s *Service) IsAdmin(n *node, token string) bool { return s.checkToken(n.id, "admin", token) }

func (s *Service) token(id, role string) string {
	generation, err := s.st.tokenGeneration(id, role, false)
	if err != nil {
		return ""
	}
	return s.secret.Load().Token(id, role, generation)
}

func (s *Service) checkToken(id, role, token string) bool {
	expected := s.token(id, role)
	return expected != "" && hmac.Equal([]byte(expected), []byte(token))
}
