package tuc

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OCSP (RFC 6960) as all clients use it: the CertIDs of the request with
// any of the hashes OpenSSL has and a nonce, answered by a BasicOCSPResponse
// that the OCSP responder of the CA signs, with its certificate, which
// ocsputil of CryptoPro looks for the signer in. A signature on the request
// is ignored.

var (
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
)

// OCSPResponseStatus values
const (
	ocspMalformed = 1
	ocspInternal  = 2
)

type certIDReq struct {
	raw               cryptobyte.String // the CertID, which the response repeats
	hash              string            // dotted OID
	nameHash, keyHash []byte
	serial            *big.Int
}

// parseOCSPRequest reads the CertIDs of an OCSPRequest and its nonce
// extension, as a whole.
func parseOCSPRequest(der []byte) (ids []certIDReq, nonce []byte, err error) {
	bad := errors.New("bad OCSP request")
	in := cryptobyte.String(der)
	var req, tbs, list cryptobyte.String
	if !in.ReadASN1(&req, cbasn1.SEQUENCE) || !in.Empty() || !req.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, nil, bad
	}
	tbs.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed())
	tbs.SkipOptionalASN1(cbasn1.Tag(1).ContextSpecific().Constructed())
	if !tbs.ReadASN1(&list, cbasn1.SEQUENCE) || list.Empty() {
		return nil, nil, bad
	}
	for !list.Empty() {
		var one, raw, outer, c, alg cryptobyte.String
		var oid asn1.ObjectIdentifier
		id := certIDReq{serial: new(big.Int)}
		if !list.ReadASN1(&one, cbasn1.SEQUENCE) || !one.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
			return nil, nil, bad
		}
		id.raw, outer = raw, raw
		if !outer.ReadASN1(&c, cbasn1.SEQUENCE) || !c.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) ||
			!c.ReadASN1Bytes(&id.nameHash, cbasn1.OCTET_STRING) || !c.ReadASN1Bytes(&id.keyHash, cbasn1.OCTET_STRING) ||
			!c.ReadASN1Integer(id.serial) || !c.Empty() {
			return nil, nil, bad
		}
		id.hash = oid.String()
		ids = append(ids, id)
	}
	var tagged, exts cryptobyte.String
	if tbs.PeekASN1Tag(cbasn1.Tag(2).ContextSpecific().Constructed()) {
		if !tbs.ReadASN1(&tagged, cbasn1.Tag(2).ContextSpecific().Constructed()) || !tagged.ReadASN1(&exts, cbasn1.SEQUENCE) {
			return nil, nil, bad
		}
	}
	for !exts.Empty() {
		var ext, e cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !exts.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
			return nil, nil, bad
		}
		if c := ext; !c.ReadASN1(&e, cbasn1.SEQUENCE) || !e.ReadASN1ObjectIdentifier(&oid) {
			return nil, nil, bad
		}
		if oid.Equal(oidOCSPNonce) {
			nonce = ext
		}
	}
	if !tbs.Empty() {
		return nil, nil, bad
	}
	return ids, nonce, nil
}

// ocspError is an OCSPResponse of a status other than successful.
func ocspError(status int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Enum(int64(status)) })
	return b.BytesOrPanic()
}

// OCSP answers an OCSPRequest to the CA n with an OCSPResponse: good or
// revoked for what n issued, unknown for anything else, valid as long as a
// CRL.
func (s *Service) OCSP(n *node, req []byte) []byte {
	ids, nonce, err := parseOCSPRequest(req)
	if err != nil {
		return ocspError(ocspMalformed)
	}
	resp, err := s.ocspResponse(n, ids, nonce)
	if err != nil {
		return ocspError(ocspInternal)
	}
	return resp
}

func (s *Service) ocspResponse(n *node, ids []certIDReq, nonce []byte) ([]byte, error) {
	bits, err := keyBits(n.cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err
	}
	rkey, rcert, err := s.service(n, serviceOCSP)
	if err != nil {
		return nil, err
	}
	defer rkey.Close()
	rspki, err := rkey.SPKI()
	if err != nil {
		return nil, err
	}
	kid, err := keyID(rspki)
	if err != nil {
		return nil, err
	}
	type status struct {
		issued  bool
		revoked *time.Time
	}
	statuses := make([]status, len(ids))
	for i, id := range ids {
		name, err1 := s.mp.Digest(id.hash, n.cert.RawSubject)
		key, err2 := s.mp.Digest(id.hash, bits)
		if err1 != nil || err2 != nil || !bytes.Equal(name, id.nameHash) || !bytes.Equal(key, id.keyHash) {
			continue
		}
		st := &statuses[i]
		if st.issued, st.revoked, err = s.st.status(n.id, hexSerial(id.serial)); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddASN1OctetString(kid) })
		b.AddASN1GeneralizedTime(now)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for i, id := range ids {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(id.raw)
					switch st := statuses[i]; {
					case st.revoked != nil:
						b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
							b.AddASN1GeneralizedTime(*st.revoked)
						})
					case st.issued:
						b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(*cryptobyte.Builder) {})
					default:
						b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(*cryptobyte.Builder) {})
					}
					// thisUpdate is now: CAdES-X Long of CryptoPro CSP takes
					// no status older than its time-stamp
					b.AddASN1GeneralizedTime(now)
					b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1GeneralizedTime(now.Add(crlLifetime))
					})
				})
			}
		})
		if nonce != nil {
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(nonce) })
			})
		}
	})
	tbs, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	sig, err := sign(rkey, n.alg, tbs)
	if err != nil {
		return nil, err
	}
	var out cryptobyte.Builder
	out.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Enum(0)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidOCSPBasic)
				b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddBytes(tbs)
						addAlgo(b, n.alg)
						b.AddASN1BitString(sig)
						b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(rcert) })
						})
					})
				})
			})
		})
	})
	return out.Bytes()
}
