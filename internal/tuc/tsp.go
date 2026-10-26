package tuc

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/PiDmitrius/tuc/internal/mp"
	"golang.org/x/crypto/cryptobyte"
)

// oidTSAPolicy is the time-stamping policy of TUC, anyPolicy: CryptoPro
// CSP truncates an OID arc beyond 32 bits, so a UUID OID breaks the
// signature of a time-stamp it decodes.
const oidTSAPolicy = "2.5.29.32.0"

// TSP answers a time-stamp request to the CA n with a response signed by
// the time-stamping certificate of n, made at the first request.
func (s *Service) TSP(n *node, req []byte) ([]byte, error) {
	key, cert, err := s.service(n, serviceTSA)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	var chain [][]byte
	for c := n; c != nil; c = c.parent {
		chain = append(chain, c.der)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	return key.TSPReply(cert, chain, oidTSAPolicy, algoDefs[n.alg].digest, serial.Bytes(), req)
}

// service is a certificate of n for a service, which n issues at the first
// need, after revocation, or when it has a month left and n lasts longer.
type service string

const (
	// valid as long as n, with its CRL and OCSP URLs whatever n issues
	// with, as CAdES-X Long checks its revocation
	serviceTSA service = "tsa"
	// for 90 days, to be trusted without a revocation check
	// (id-pkix-ocsp-nocheck), as CryptoPro CSP needs for CAdES-X Long, so
	// that the key of n signs no OCSP response
	serviceOCSP service = "ocsp"
)

// service is the key and certificate of n for svc, both of the algorithm of n.
func (s *Service) service(n *node, svc service) (*mp.Key, []byte, error) {
	s.serviceMu.Lock()
	defer s.serviceMu.Unlock()
	cert, sealed, err := s.st.service(n.id, string(svc))
	if err != nil {
		return nil, nil, err
	}
	if c, err := x509.ParseCertificate(cert); err == nil {
		revoked, err := s.st.revokedAt(n.id, certID(cert))
		if err != nil {
			return nil, nil, err
		}
		if revoked == nil && c.NotAfter.After(c.NotBefore) && !c.NotBefore.Before(n.cert.NotBefore) && !c.NotAfter.After(n.cert.NotAfter) && (time.Until(c.NotAfter) > 30*24*time.Hour || !n.cert.NotAfter.After(c.NotAfter)) {
			raw, err := s.secret.Load().Decrypt(sealed)
			if err != nil {
				return nil, nil, err
			}
			defer clear(raw)
			key, err := s.importKey(n.alg, raw)
			return key, cert, err
		}
	}
	key, raw, err := s.newKey(n.alg)
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	spki, err := key.SPKI()
	if err == nil {
		now := time.Now().UTC().Truncate(time.Second)
		t := &certTemplate{spki: spki, notBefore: now.Add(-backdate), notAfter: n.cert.NotAfter, issuerURL: s.publicationURL(n.id)}
		switch svc {
		case serviceTSA:
			t.subject, t.crl, t.ocsp = nameCN(n.cert.Subject.CommonName+" TSP"), true, true
			t.extra = []cryptobyte.String{keyUsageExt(keyUsageService), ekuExt(true, oidTimeStamping)}
		case serviceOCSP:
			t.subject = nameCN(n.cert.Subject.CommonName + " OCSP")
			if end := now.AddDate(0, 0, 90); end.Before(t.notAfter) {
				t.notAfter = end
			}
			t.extra = []cryptobyte.String{keyUsageExt(keyUsageService), ekuExt(false, oidOCSPSigning),
				extension(oidOCSPNoCheck, false, func(b *cryptobyte.Builder) { b.AddASN1NULL() })}
		}
		if now.Before(n.cert.NotBefore) {
			t.notBefore = n.cert.NotBefore
			if svc == serviceOCSP {
				t.notAfter = t.notBefore.AddDate(0, 0, 90)
				if t.notAfter.After(n.cert.NotAfter) {
					t.notAfter = n.cert.NotAfter
				}
			}
		} else if !now.Before(n.cert.NotAfter) {
			t.notBefore = n.cert.NotBefore
			if svc == serviceOCSP {
				if start := n.cert.NotAfter.AddDate(0, 0, -90); start.After(t.notBefore) {
					t.notBefore = start
				}
			}
		}
		if t.notBefore.Before(n.cert.NotBefore) {
			t.notBefore = n.cert.NotBefore
		}
		if !t.notAfter.After(t.notBefore) {
			err = errors.New("срок сертификата службы не пересекается со сроком УЦ")
		} else if cert, err = s.issueCert(n, t); err == nil {
			err = s.st.setService(n.id, string(svc), cert, s.secret.Load().Encrypt(raw))
		}
	}
	if err != nil {
		key.Close()
		return nil, nil, err
	}
	return key, cert, nil
}
