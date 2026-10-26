// Package mp binds the MiniPKI signing keys and the checks the tests need.
package mp

/*
#cgo LDFLAGS: -lminipki -lcrypto
#include <stdlib.h>
#include <minipki.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type Ctx struct{ c C.MP_CTX }

// Key must be closed.
type Key struct{ k C.MP_KEY }

func rcErr(fn string, rc C.int32_t) error {
	if rc == C.MP_OK {
		return nil
	}
	return fmt.Errorf("%s: minipki error %d", fn, int(rc))
}

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// Open needs MINIPKI_GOST_ENGINE to name the GOST engine.
func Open() (*Ctx, error) {
	var c C.MP_CTX
	if err := rcErr("mp_open", C.mp_open(C.MP_TYPE_OPENSSL, &c)); err != nil {
		return nil, err
	}
	return &Ctx{c}, nil
}

// VerifyRequest checks a DER PKCS#10 request's signature with its public key.
func (x *Ctx) VerifyRequest(der []byte) error {
	return rcErr("mp_request_verify", C.mp_request_verify(x.c, ptr(der), C.size_t(len(der))))
}

// Digest hashes data with the digest of the dotted OID alg; an error for a
// digest OpenSSL does not have.
func (x *Ctx) Digest(alg string, data []byte) ([]byte, error) {
	ca := C.CString(alg)
	defer C.free(unsafe.Pointer(ca))
	var md [C.MP_DIGEST_MAX]C.uint8_t
	var n C.size_t
	if err := rcErr("mp_digest", C.mp_digest(x.c, ca, ptr(data), C.size_t(len(data)), &md[0], &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(&md[0]), C.int(n)), nil
}

func (x *Ctx) key(make func(*C.MP_KEY) C.int32_t, fn string) (*Key, error) {
	var k C.MP_KEY
	if err := rcErr(fn, make(&k)); err != nil {
		return nil, err
	}
	return &Key{k}, nil
}

// GenerateKey makes a GOST key of bits 256 or 512.
func (x *Ctx) GenerateKey(bits int) (*Key, error) {
	return x.key(func(k *C.MP_KEY) C.int32_t { return C.mp_key_generate_gost(x.c, C.int32_t(bits), k) }, "mp_key_generate_gost")
}

// ImportKey reads the raw form of a GOST key, 32 or 64 bytes.
func (x *Ctx) ImportKey(raw []byte) (*Key, error) {
	if len(raw) != C.MP_KEY_RAW_LEN && len(raw) != C.MP_KEY_RAW_LEN_512 {
		return nil, errors.New("bad key length")
	}
	return x.key(func(k *C.MP_KEY) C.int32_t {
		return C.mp_key_import(x.c, ptr(raw), C.size_t(len(raw)), k)
	}, "mp_key_import")
}

// ImportPKCS8 reads an RSA or ECDSA key.
func (x *Ctx) ImportPKCS8(der []byte) (*Key, error) {
	return x.key(func(k *C.MP_KEY) C.int32_t {
		return C.mp_key_import_pkcs8(x.c, ptr(der), C.size_t(len(der)), k)
	}, "mp_key_import_pkcs8")
}

func (k *Key) Close() {
	if k.k != nil {
		C.mp_key_close(k.k)
		k.k = nil
	}
}

func (k *Key) Raw() []byte {
	var p *C.uint8_t
	var n C.size_t
	C.mp_key_raw(k.k, &p, &n)
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

// SignDigest returns the X.509 signatureValue of data over the digest of
// the dotted OID alg.
func (k *Key) SignDigest(alg string, data []byte) ([]byte, error) {
	ca := C.CString(alg)
	defer C.free(unsafe.Pointer(ca))
	var p *C.uint8_t
	var n C.size_t
	if err := rcErr("mp_key_sign_digest", C.mp_key_sign_digest(k.k, ca, ptr(data), C.size_t(len(data)), &p, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// SPKI is the SubjectPublicKeyInfo DER.
func (k *Key) SPKI() ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := rcErr("mp_key_spki", C.mp_key_spki(k.k, &p, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// Sign returns the X.509 signatureValue of data.
func (k *Key) Sign(data []byte) ([]byte, error) {
	var p *C.uint8_t
	var n C.size_t
	if err := rcErr("mp_key_sign", C.mp_key_sign(k.k, ptr(data), C.size_t(len(data)), &p, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// VerifyChain checks leaf up to roots, including the signatures of
// self-signed roots, with or without CRLs for every certificate.
func (x *Ctx) VerifyChain(leaf []byte, roots, intermediates, crls [][]byte) error {
	flags := C.uint32_t(C.MP_VERIFY_CHECK_SS_SIG)
	if len(crls) > 0 {
		flags |= C.MP_VERIFY_CRL_CHECK
	}
	var cert C.MP_CERT
	if err := rcErr("mp_cert_parse", C.mp_cert_parse(x.c, ptr(leaf), C.size_t(len(leaf)), &cert)); err != nil {
		return err
	}
	defer C.mp_cert_close(cert)
	var st C.MP_STORE
	if err := rcErr("mp_store_new", C.mp_store_new(x.c, &st)); err != nil {
		return err
	}
	defer C.mp_store_close(st)
	for _, d := range roots {
		if err := rcErr("mp_store_add_root", C.mp_store_add_root(st, ptr(d), C.size_t(len(d)))); err != nil {
			return err
		}
	}
	for _, d := range intermediates {
		if err := rcErr("mp_store_add_intermediate", C.mp_store_add_intermediate(st, ptr(d), C.size_t(len(d)))); err != nil {
			return err
		}
	}
	for _, d := range crls {
		if err := rcErr("mp_store_add_crl", C.mp_store_add_crl(st, ptr(d), C.size_t(len(d)))); err != nil {
			return err
		}
	}
	if err := rcErr("mp_store_set_flags", C.mp_store_set_flags(st, flags)); err != nil {
		return err
	}
	var chain C.MP_CHAIN
	rc := C.mp_verify(st, cert, &chain)
	if rc != C.MP_OK {
		var code, depth C.int32_t
		var msg *C.uint8_t
		var n C.size_t
		C.mp_verify_last_error(st, &code, &depth, &msg, &n)
		return fmt.Errorf("mp_verify %d at depth %d: %s", int(rc), int(depth), C.GoStringN((*C.char)(unsafe.Pointer(msg)), C.int(n)))
	}
	C.mp_chain_close(chain)
	return nil
}

// VerifyCMS checks a DER CMS SignedData with one signer against the signer
// certificate, the one given or else the one it carries, and returns its
// content and that certificate.
func (x *Ctx) VerifyCMS(der, signer []byte) (content, cert []byte, err error) {
	var cms C.MP_CMS
	if err := rcErr("mp_cms_verify", C.mp_cms_verify(x.c, ptr(der), C.size_t(len(der)), ptr(signer), C.size_t(len(signer)), &cms)); err != nil {
		return nil, nil, err
	}
	defer C.mp_cms_close(cms)
	var p *C.uint8_t
	var n C.size_t
	C.mp_cms_content(cms, &p, &n)
	content = C.GoBytes(unsafe.Pointer(p), C.int(n))
	C.mp_cms_signer(cms, &p, &n)
	return content, C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// certList is certs in C memory, as Go memory holding Go pointers must not
// be passed to C; free releases it.
type certList struct {
	ptrs **C.uint8_t
	lens *C.size_t
	n    int
}

func newCertList(certs [][]byte) *certList {
	n := len(certs)
	l := &certList{
		ptrs: (**C.uint8_t)(C.malloc(C.size_t(max(n, 1)) * C.size_t(unsafe.Sizeof((*C.uint8_t)(nil))))),
		lens: (*C.size_t)(C.malloc(C.size_t(max(n, 1)) * C.size_t(unsafe.Sizeof(C.size_t(0))))),
		n:    n,
	}
	ptrs, lens := unsafe.Slice(l.ptrs, n), unsafe.Slice(l.lens, n)
	for i, c := range certs {
		ptrs[i] = (*C.uint8_t)(C.CBytes(c))
		lens[i] = C.size_t(len(c))
	}
	return l
}

func (l *certList) free() {
	for _, p := range unsafe.Slice(l.ptrs, l.n) {
		C.free(unsafe.Pointer(p))
	}
	C.free(unsafe.Pointer(l.ptrs))
	C.free(unsafe.Pointer(l.lens))
}

// PKCS12 is a PKCS#12 of k with its certificate cert and certs under
// password, for a GOST key as CryptoPro CSP imports it.
func (k *Key) PKCS12(cert []byte, certs [][]byte, password string) ([]byte, error) {
	l := newCertList(certs)
	defer l.free()
	pw := C.CString(password)
	defer func() {
		clear(unsafe.Slice((*byte)(unsafe.Pointer(pw)), len(password)))
		C.free(unsafe.Pointer(pw))
	}()
	var p *C.uint8_t
	var n C.size_t
	if err := rcErr("mp_key_pkcs12", C.mp_key_pkcs12(k.k, ptr(cert), C.size_t(len(cert)), l.ptrs, l.lens, C.size_t(l.n), pw, &p, &n)); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// TSPReply is a time-stamp response to req by k, whose certificate signer
// is for time-stamping, with certs, under the dotted OID policy, signed
// over the digest of the dotted OID digest or, with "", the one of Sign,
// with the big-endian serial.
func (k *Key) TSPReply(signer []byte, certs [][]byte, policy, digest string, serial, req []byte) ([]byte, error) {
	l := newCertList(certs)
	defer l.free()
	pol := C.CString(policy)
	defer C.free(unsafe.Pointer(pol))
	var dg *C.char
	if digest != "" {
		dg = C.CString(digest)
		defer C.free(unsafe.Pointer(dg))
	}
	var p *C.uint8_t
	var n C.size_t
	rc := C.mp_key_tsp_reply(k.k, ptr(signer), C.size_t(len(signer)), l.ptrs, l.lens, C.size_t(l.n), pol, dg,
		ptr(serial), C.size_t(len(serial)), ptr(req), C.size_t(len(req)), &p, &n)
	if err := rcErr("mp_key_tsp_reply", rc); err != nil {
		return nil, err
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// SignCMS signs content of contentType, a dotted OID, with k, whose
// certificate is signer, into a CMS SignedData holding exactly certs.
func (k *Key) SignCMS(signer []byte, contentType string, content []byte, certs [][]byte) ([]byte, error) {
	ct := C.CString(contentType)
	defer C.free(unsafe.Pointer(ct))
	l := newCertList(certs)
	defer l.free()
	var cms C.MP_CMS
	rc := C.mp_cms_sign(k.k, ptr(signer), C.size_t(len(signer)), ct, ptr(content), C.size_t(len(content)),
		l.ptrs, l.lens, C.size_t(l.n), &cms)
	if err := rcErr("mp_cms_sign", rc); err != nil {
		return nil, err
	}
	defer C.mp_cms_close(cms)
	var p *C.uint8_t
	var n C.size_t
	C.mp_cms_der(cms, &p, &n)
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), nil
}

// VerifyCRL verifies a CRL with its issuer's public key.
func (x *Ctx) VerifyCRL(der, issuer []byte) error {
	var crl C.MP_CRL
	if err := rcErr("mp_crl_parse", C.mp_crl_parse(x.c, ptr(der), C.size_t(len(der)), &crl)); err != nil {
		return err
	}
	defer C.mp_crl_close(crl)
	var cert C.MP_CERT
	if err := rcErr("mp_cert_parse", C.mp_cert_parse(x.c, ptr(issuer), C.size_t(len(issuer)), &cert)); err != nil {
		return err
	}
	defer C.mp_cert_close(cert)
	return rcErr("mp_crl_verify", C.mp_crl_verify(crl, cert))
}
