package tuc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidKeyGost256   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidKeyGost512   = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}
	oidSignGost256  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}
	oidSignRSA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignECDSA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignECDSA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignECDSA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignGost512  = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}
	oidBasicConstr  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSKI          = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI          = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCDP          = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidCRLNumber    = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidAIA          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidSAN          = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidEKU          = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidOCSP         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidCAIssuers    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	oidExtensionReq = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	keyUsageCA      = []byte{0x01, 0x06} // keyCertSign, cRLSign
)

// Attribute names of a distinguished name and the ASN.1 string tag of their
// values.
var nameAttrs = map[string]struct {
	oid asn1.ObjectIdentifier
	tag cbasn1.Tag
}{
	"CN":           {asn1.ObjectIdentifier{2, 5, 4, 3}, cbasn1.UTF8String},
	"SN":           {asn1.ObjectIdentifier{2, 5, 4, 4}, cbasn1.UTF8String},
	"SERIALNUMBER": {asn1.ObjectIdentifier{2, 5, 4, 5}, cbasn1.PrintableString},
	"C":            {asn1.ObjectIdentifier{2, 5, 4, 6}, cbasn1.PrintableString},
	"L":            {asn1.ObjectIdentifier{2, 5, 4, 7}, cbasn1.UTF8String},
	"ST":           {asn1.ObjectIdentifier{2, 5, 4, 8}, cbasn1.UTF8String},
	"S":            {asn1.ObjectIdentifier{2, 5, 4, 8}, cbasn1.UTF8String},
	"STREET":       {asn1.ObjectIdentifier{2, 5, 4, 9}, cbasn1.UTF8String},
	"O":            {asn1.ObjectIdentifier{2, 5, 4, 10}, cbasn1.UTF8String},
	"OU":           {asn1.ObjectIdentifier{2, 5, 4, 11}, cbasn1.UTF8String},
	"T":            {asn1.ObjectIdentifier{2, 5, 4, 12}, cbasn1.UTF8String},
	"G":            {asn1.ObjectIdentifier{2, 5, 4, 42}, cbasn1.UTF8String},
	"E":            {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, cbasn1.IA5String},
	"INN":          {asn1.ObjectIdentifier{1, 2, 643, 3, 131, 1, 1}, cbasn1.Tag(18)},
	"OGRN":         {asn1.ObjectIdentifier{1, 2, 643, 100, 1}, cbasn1.Tag(18)},
	"SNILS":        {asn1.ObjectIdentifier{1, 2, 643, 100, 3}, cbasn1.Tag(18)},
	"INNLE":        {asn1.ObjectIdentifier{1, 2, 643, 100, 4}, cbasn1.Tag(18)},
	"OGRNIP":       {asn1.ObjectIdentifier{1, 2, 643, 100, 5}, cbasn1.Tag(18)},
}

// ParseName encodes "CN=Root,O=Org" as a DER Name with one attribute per RDN
// in the written order; "\," and "\\" escape inside values, and an attribute
// may be a dotted OID, then with a UTF8String value.
func ParseName(s string) ([]byte, error) {
	if strings.ContainsFunc(s, unicode.IsControl) {
		return nil, errors.New("недопустимые символы в имени")
	}
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("укажите имя УЦ")
	}
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case s[i] == ',':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	parts = append(parts, cur.String())
	if len(parts) > maxNameAttrs {
		return nil, fmt.Errorf("в имени не больше %d атрибутов", maxNameAttrs)
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, p := range parts {
			k, v, ok := strings.Cut(p, "=")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if !ok || k == "" || v == "" {
				b.SetError(fmt.Errorf("неверный атрибут имени %q: нужен вид CN=значение", p))
				return
			}
			if utf8.RuneCountInString(v) > maxNameValue {
				b.SetError(fmt.Errorf("значение атрибута — не больше %d символов", maxNameValue))
				return
			}
			a, known := nameAttrs[strings.ToUpper(k)]
			if !known {
				oid, err := parseOID(k)
				if err != nil {
					b.SetError(fmt.Errorf("неизвестный атрибут имени %q", k))
					return
				}
				a.oid, a.tag = oid, cbasn1.UTF8String
			}
			if !allowed(a.tag, v) {
				b.SetError(fmt.Errorf("недопустимые символы в значении атрибута %s", k))
				return
			}
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(a.oid)
					b.AddASN1(a.tag, func(b *cryptobyte.Builder) { b.AddBytes([]byte(v)) })
				})
			})
		}
	})
	der, err := b.Bytes()
	if err == nil && len(der) > maxNameDER {
		err = fmt.Errorf("имя длиннее %d байт", maxNameDER)
	}
	return der, err
}

// allowed reports whether v fits the ASN.1 string type tag.
func allowed(tag cbasn1.Tag, v string) bool {
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
		switch tag {
		case cbasn1.PrintableString:
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.ContainsRune(" '()+,-./:=?", c)) {
				return false
			}
		case cbasn1.Tag(18): // NumericString
			if !('0' <= c && c <= '9' || c == ' ') {
				return false
			}
		case cbasn1.IA5String:
			if c > 0x7f {
				return false
			}
		}
	}
	return true
}

// Limits of names, of CAs and of requests: a name of X.520 lengths is
// enough for any test.
const (
	maxNameAttrs = 8
	maxNameValue = 64
	maxNameDER   = 512
	maxExtension = 1024
)

// checkName checks a DER Name of a request against the limits of names.
func checkName(der []byte) error {
	if len(der) > maxNameDER {
		return fmt.Errorf("имя длиннее %d байт", maxNameDER)
	}
	in := cryptobyte.String(der)
	var rdns cryptobyte.String
	if !in.ReadASN1(&rdns, cbasn1.SEQUENCE) {
		return errors.New("bad name")
	}
	n := 0
	for !rdns.Empty() {
		var set cryptobyte.String
		if !rdns.ReadASN1(&set, cbasn1.SET) {
			return errors.New("bad name")
		}
		for !set.Empty() {
			var atv, value cryptobyte.String
			var tag cbasn1.Tag
			if n++; n > maxNameAttrs {
				return fmt.Errorf("в имени не больше %d атрибутов", maxNameAttrs)
			}
			if !set.ReadASN1(&atv, cbasn1.SEQUENCE) || !atv.SkipASN1(cbasn1.OBJECT_IDENTIFIER) || !atv.ReadAnyASN1(&value, &tag) {
				return errors.New("bad name")
			}
			decoded, err := nameValue(tag, value)
			if err != nil {
				return err
			}
			if !allowed(cbasn1.UTF8String, decoded) {
				return errors.New("недопустимые символы в имени")
			}
			if utf8.RuneCountInString(decoded) > maxNameValue {
				return fmt.Errorf("значение атрибута — не больше %d символов", maxNameValue)
			}
		}
	}
	if n == 0 {
		return errors.New("Subject должен содержать хотя бы один атрибут")
	}
	return nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, f := range strings.Split(s, ".") {
		var n int
		if _, err := fmt.Sscanf(f, "%d", &n); err != nil || fmt.Sprint(n) != f {
			return nil, errors.New("bad OID")
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, errors.New("bad OID")
	}
	return oid, nil
}

// keyBits are the subjectPublicKey bits of an SPKI.
func keyBits(spki []byte) ([]byte, error) {
	in := cryptobyte.String(spki)
	var seq cryptobyte.String
	var bits asn1.BitString
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.SkipASN1(cbasn1.SEQUENCE) || !seq.ReadASN1BitString(&bits) {
		return nil, errors.New("bad SubjectPublicKeyInfo")
	}
	return bits.Bytes, nil
}

// keyID is the SHA-1 of the subjectPublicKey bits of an SPKI.
func keyID(spki []byte) ([]byte, error) {
	bits, err := keyBits(spki)
	if err != nil {
		return nil, err
	}
	h := sha1.Sum(bits)
	return h[:], nil
}

func addTime(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC().Truncate(time.Second)
	if t.Year() >= 1950 && t.Year() < 2050 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}

// algo is the key algorithm of a CA, which sets the signature algorithm of
// what it signs; each CA of a chain has its own.
type algo string

// algoDef is an algorithm: its names, its signature algorithm with its
// digest where it is not the one of mp_key_sign, and the options that make a
// key of it in cryptcp and openssl req.
type algoDef struct {
	name, long string
	sig        asn1.ObjectIdentifier
	digest     string
	cryptcp    string // the provider type, and the key size and hash where the CryptoPro defaults differ
	openssl    string
}

const (
	hashSHA256 = " -hashalg 2.16.840.1.101.3.4.2.1"
	hashSHA384 = " -hashalg 2.16.840.1.101.3.4.2.2"
	hashSHA512 = " -hashalg 2.16.840.1.101.3.4.2.3"
)

// algos are the algorithms in the order a form lists them, the default first.
var algos = []algo{"gost256", "gost512", "rsa2048", "rsa3072", "rsa4096", "ecdsa256", "ecdsa384", "ecdsa521"}

// algoDefs: cryptcp takes the size of an EC public key, twice the curve's
var algoDefs = map[algo]algoDef{
	"gost256":  {"ГОСТ 256", "ГОСТ Р 34.10-2012, 256 бит", oidSignGost256, "", "", "-newkey gost2012_256 -pkeyopt paramset:A"},
	"gost512":  {"ГОСТ 512", "ГОСТ Р 34.10-2012, 512 бит", oidSignGost512, "", " -provtype 81", "-newkey gost2012_512 -pkeyopt paramset:A"},
	"rsa2048":  {"RSA 2048", "RSA 2048, SHA-256", oidSignRSA256, "", " -provtype 24 -keysize 2048" + hashSHA256, "-newkey rsa:2048"},
	"rsa3072":  {"RSA 3072", "RSA 3072, SHA-256", oidSignRSA256, "", " -provtype 24 -keysize 3072" + hashSHA256, "-newkey rsa:3072"},
	"rsa4096":  {"RSA 4096", "RSA 4096, SHA-256", oidSignRSA256, "", " -provtype 24 -keysize 4096" + hashSHA256, "-newkey rsa:4096"},
	"ecdsa256": {"ECDSA P-256", "ECDSA P-256, SHA-256", oidSignECDSA256, "", " -provtype 16" + hashSHA256, "-newkey ec -pkeyopt ec_paramgen_curve:P-256"},
	"ecdsa384": {"ECDSA P-384", "ECDSA P-384, SHA-384", oidSignECDSA384, "2.16.840.1.101.3.4.2.2", " -provtype 16 -keysize 768" + hashSHA384, "-newkey ec -pkeyopt ec_paramgen_curve:P-384"},
	"ecdsa521": {"ECDSA P-521", "ECDSA P-521, SHA-512", oidSignECDSA512, "2.16.840.1.101.3.4.2.3", " -provtype 16 -keysize 1056" + hashSHA512, "-newkey ec -pkeyopt ec_paramgen_curve:P-521"},
}

func (a algo) Name() string { return algoDefs[a].name }

func (a algo) Long() string { return algoDefs[a].long }

// Family is gost, rsa or ecdsa.
func (a algo) Family() string { return strings.TrimRight(string(a), "0123456789") }

// Bits is the key size of RSA and GOST, the curve size of ECDSA.
func (a algo) Bits() int {
	n, _ := strconv.Atoi(strings.TrimLeft(string(a), "abcdefghijklmnopqrstuvwxyz"))
	return n
}

// algoOf is the algorithm of the key of c, "" for one TUC does not make.
func algoOf(c *x509.Certificate) algo {
	var a algo
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		a = algo(fmt.Sprintf("rsa%d", k.N.BitLen()))
	case *ecdsa.PublicKey:
		a = algo(fmt.Sprintf("ecdsa%d", k.Curve.Params().BitSize))
	default:
		in := cryptobyte.String(c.RawSubjectPublicKeyInfo)
		var spki, alg cryptobyte.String
		var oid asn1.ObjectIdentifier
		if in.ReadASN1(&spki, cbasn1.SEQUENCE) && spki.ReadASN1(&alg, cbasn1.SEQUENCE) && alg.ReadASN1ObjectIdentifier(&oid) {
			switch {
			case oid.Equal(oidKeyGost256):
				a = "gost256"
			case oid.Equal(oidKeyGost512):
				a = "gost512"
			}
		}
	}
	if _, ok := algoDefs[a]; !ok {
		return ""
	}
	return a
}

// addAlgo adds the signature algorithm of a CA key of a.
func addAlgo(b *cryptobyte.Builder, a algo) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(algoDefs[a].sig)
		if a.Family() == "rsa" {
			b.AddASN1NULL()
		}
	})
}

func addExt(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, critical bool, value func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1(cbasn1.OCTET_STRING, value)
	})
}

func addKeyIDExt(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, id []byte) {
	addExt(b, oid, false, func(b *cryptobyte.Builder) {
		if oid.Equal(oidSKI) {
			b.AddASN1OctetString(id)
			return
		}
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(id) })
		})
	})
}

// addURLExts adds the CA issuers URL of the issuing CA at caURL and, with
// crl and ocsp, its CRL distribution point and OCSP URL.
func addURLExts(b *cryptobyte.Builder, caURL string, crl, ocsp bool) {
	uri := cbasn1.Tag(6).ContextSpecific()
	if crl {
		addCDP(b, caURL)
	}
	addExt(b, oidAIA, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if ocsp {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(oidOCSP)
					b.AddASN1(uri, func(b *cryptobyte.Builder) { b.AddBytes([]byte(caURL + "/ocsp")) })
				})
			}
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidCAIssuers)
				b.AddASN1(uri, func(b *cryptobyte.Builder) { b.AddBytes([]byte(caURL + ".crt")) })
			})
		})
	})
}

func addCDP(b *cryptobyte.Builder, caURL string) {
	uri := cbasn1.Tag(6).ContextSpecific()
	addExt(b, oidCDP, false, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(uri, func(b *cryptobyte.Builder) { b.AddBytes([]byte(caURL + ".crl")) })
					})
				})
			})
		})
	})
}

// certTemplate is what a certificate's TBS is built from.
type certTemplate struct {
	serial              *big.Int
	alg                 algo   // of the issuer
	issuer, subject     []byte // DER Names
	notBefore, notAfter time.Time
	spki                []byte
	ca                  bool
	ski, aki            []byte
	issuerURL           string              // issuing CA, for CDP and AIA; none for a root
	crl, ocsp           bool                // with the CRL and OCSP URLs of the issuing CA
	extra               []cryptobyte.String // extensions of the certificate template
}

func (t *certTemplate) tbs() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddASN1Int64(2) })
		b.AddASN1BigInt(t.serial)
		addAlgo(b, t.alg)
		b.AddBytes(t.issuer)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addTime(b, t.notBefore)
			addTime(b, t.notAfter)
		})
		b.AddBytes(t.subject)
		b.AddBytes(t.spki)
		b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				if t.ca {
					addExt(b, oidBasicConstr, true, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Boolean(true) })
					})
					addExt(b, oidKeyUsage, true, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddBytes(keyUsageCA) })
					})
				}
				addKeyIDExt(b, oidSKI, t.ski)
				addKeyIDExt(b, oidAKI, t.aki)
				if t.issuerURL != "" {
					addURLExts(b, t.issuerURL, t.crl, t.ocsp)
				}
				for _, e := range t.extra {
					b.AddBytes(e)
				}
			})
		})
	})
	return b.Bytes()
}

// signed wraps a TBS of a certificate or CRL with its signature by a key of a.
func signed(tbs, sig []byte, a algo) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		addAlgo(b, a)
		b.AddASN1BitString(sig)
	})
	return b.BytesOrPanic()
}

type revoked struct {
	serial *big.Int
	at     time.Time
}

func crlTBS(a algo, issuer, aki []byte, number int64, thisUpdate, nextUpdate time.Time, list []revoked) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		addAlgo(b, a)
		b.AddBytes(issuer)
		addTime(b, thisUpdate)
		addTime(b, nextUpdate)
		if len(list) > 0 {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, r := range list {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1BigInt(r.serial)
						addTime(b, r.at)
					})
				}
			})
		}
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addKeyIDExt(b, oidAKI, aki)
				addExt(b, oidCRLNumber, false, func(b *cryptobyte.Builder) { b.AddASN1Int64(number) })
			})
		})
	})
	return b.Bytes()
}

// Key usage bits (RFC 5280)
const (
	kuDigitalSignature = 1 << 0
	kuNonRepudiation   = 1 << 1
	kuKeyEncipherment  = 1 << 2
	kuDataEncipherment = 1 << 3
	kuKeyAgreement     = 1 << 4
)

var (
	oidKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidKeyEC  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// keyUsages are the key usages a leaf key of an SPKI algorithm may have:
// RSA no key agreement (RFC 4055), EC no encipherment (RFC 5480), GOST all
// CryptoPro asks for; others only signatures.
func keyUsages(spki []byte) int {
	in := cryptobyte.String(spki)
	var seq, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		return 0
	}
	sign := kuDigitalSignature | kuNonRepudiation
	switch {
	case oid.Equal(oidKeyRSA):
		return sign | kuKeyEncipherment | kuDataEncipherment
	case oid.Equal(oidKeyEC):
		return sign | kuKeyAgreement
	case oid.Equal(oidKeyGost256), oid.Equal(oidKeyGost512):
		return sign | kuKeyEncipherment | kuDataEncipherment | kuKeyAgreement
	}
	return sign
}

// leafKeyUsage is the complete key usage of the leaf template for spki.
func leafKeyUsage(spki []byte) cryptobyte.String {
	bits := keyUsages(spki)
	// a BIT STRING up to the last bit set
	n := 0
	for b := bits; b > 0; b >>= 1 {
		n++
	}
	content := []byte{byte((8 - n%8) % 8)}
	for i := 0; i < n; i += 8 {
		var octet byte
		for j := 0; j < 8 && i+j < n; j++ {
			if bits&(1<<(i+j)) != 0 {
				octet |= 0x80 >> j
			}
		}
		content = append(content, octet)
	}
	return keyUsageExt(content)
}

// requestTemplate reads TLS and DNS hints; all extensions are built by the CA.
func requestTemplate(attrs []cryptobyte.String) ([]cryptobyte.String, error) {
	var eku, san []byte
	seenRequest := false
	for _, a := range attrs {
		var oid asn1.ObjectIdentifier
		var set, exts cryptobyte.String
		if !a.ReadASN1ObjectIdentifier(&oid) || !a.ReadASN1(&set, cbasn1.SET) || !a.Empty() {
			return nil, errors.New("bad request attribute")
		}
		if !oid.Equal(oidExtensionReq) {
			continue
		}
		if seenRequest || !set.ReadASN1(&exts, cbasn1.SEQUENCE) || !set.Empty() {
			return nil, errors.New("неоднозначные расширения CSR")
		}
		seenRequest = true
		for !exts.Empty() {
			var body, value cryptobyte.String
			var eoid asn1.ObjectIdentifier
			if !exts.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&eoid) {
				return nil, errors.New("bad requested extension")
			}
			if !eoid.Equal(oidSAN) && !eoid.Equal(oidEKU) {
				continue
			}
			if len(body) > maxExtension {
				return nil, errors.New("слишком большое расширение CSR")
			}
			var critical bool
			if (body.PeekASN1Tag(cbasn1.BOOLEAN) && !body.ReadASN1Boolean(&critical)) || !body.ReadASN1(&value, cbasn1.OCTET_STRING) || !body.Empty() {
				return nil, errors.New("bad requested extension")
			}
			dst := &san
			if eoid.Equal(oidEKU) {
				dst = &eku
			}
			if *dst != nil {
				return nil, errors.New("повторное SAN или EKU в CSR")
			}
			*dst = []byte(value)
		}
	}
	tls := false
	if eku != nil {
		in := cryptobyte.String(eku)
		var seq cryptobyte.String
		if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || seq.Empty() {
			return nil, errors.New("некорректный EKU в CSR")
		}
		for !seq.Empty() {
			var oid asn1.ObjectIdentifier
			if !seq.ReadASN1ObjectIdentifier(&oid) {
				return nil, errors.New("некорректный EKU в CSR")
			}
			tls = tls || oid.Equal(oidServerAuth) || oid.Equal(oidClientAuth)
		}
	}
	var names []string
	if san != nil {
		in := cryptobyte.String(san)
		var seq cryptobyte.String
		if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
			return nil, errors.New("некорректный SAN в CSR")
		}
		seen := make(map[string]bool)
		for !seq.Empty() {
			var value cryptobyte.String
			var tag cbasn1.Tag
			if !seq.ReadAnyASN1(&value, &tag) {
				return nil, errors.New("некорректный SAN в CSR")
			}
			if tag != cbasn1.Tag(2).ContextSpecific() || !tls {
				continue
			}
			name := string(value)
			if !validDNS(name) {
				return nil, errors.New("некорректное DNS-имя в CSR")
			}
			name = strings.ToLower(name)
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
		}
	}
	if !tls {
		return nil, nil
	}
	return tlsExtensions(names)
}

var (
	oidPKIResponse = "1.3.6.1.5.5.7.12.3"
	oidStatusInfo  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 7, 1}
)

// pkiResponse is the CMC PKIResponse of an issued request, with the status
// the CryptoPro test CA reports.
func pkiResponse() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1ObjectIdentifier(oidStatusInfo)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1Int64(0) // success
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) })
						b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte("Выдан")) })
					})
				})
			})
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
	})
	return b.BytesOrPanic()
}

// nameParts splits a DER Name into its attributes, in DER order, as
// short names (or dotted OIDs) and values.
func nameParts(der []byte) [][2]string {
	short := map[string]string{}
	for k, a := range nameAttrs {
		if k != "S" {
			short[a.oid.String()] = k
		}
	}
	var parts [][2]string
	in := cryptobyte.String(der)
	var rdns cryptobyte.String
	if !in.ReadASN1(&rdns, cbasn1.SEQUENCE) {
		return nil
	}
	for !rdns.Empty() {
		var set cryptobyte.String
		if !rdns.ReadASN1(&set, cbasn1.SET) {
			return parts
		}
		for !set.Empty() {
			var atv, value cryptobyte.String
			var oid asn1.ObjectIdentifier
			var tag cbasn1.Tag
			if !set.ReadASN1(&atv, cbasn1.SEQUENCE) || !atv.ReadASN1ObjectIdentifier(&oid) || !atv.ReadAnyASN1(&value, &tag) {
				return parts
			}
			k := short[oid.String()]
			if k == "" {
				k = oid.String()
			}
			decoded, err := nameValue(tag, value)
			if err != nil {
				return parts
			}
			parts = append(parts, [2]string{k, decoded})
		}
	}
	return parts
}

// nameString writes a DER Name as "CN=Root, O=Org" in DER order.
func nameString(der []byte) string {
	var out []string
	for _, p := range nameParts(der) {
		out = append(out, p[0]+"="+p[1])
	}
	return strings.Join(out, ", ")
}

func supportedRequestKey(spki []byte) bool {
	if key, err := x509.ParsePKIXPublicKey(spki); err == nil {
		switch k := key.(type) {
		case *rsa.PublicKey:
			return k.N.BitLen() == 2048 || k.N.BitLen() == 3072 || k.N.BitLen() == 4096
		case *ecdsa.PublicKey:
			return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
		}
		return false
	}
	in := cryptobyte.String(spki)
	var seq, alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	return in.ReadASN1(&seq, cbasn1.SEQUENCE) && seq.ReadASN1(&alg, cbasn1.SEQUENCE) && alg.ReadASN1ObjectIdentifier(&oid) && (oid.Equal(oidKeyGost256) || oid.Equal(oidKeyGost512))
}

func nameValue(tag cbasn1.Tag, value []byte) (string, error) {
	bad := errors.New("некорректная строка атрибута Subject")
	if tag == cbasn1.Tag(30) || tag == cbasn1.Tag(28) {
		width := 2
		if tag == cbasn1.Tag(28) {
			width = 4
		}
		if len(value)%width != 0 {
			return "", bad
		}
		var out strings.Builder
		for len(value) > 0 {
			var r rune
			if width == 2 {
				r = rune(binary.BigEndian.Uint16(value))
			} else {
				r = rune(binary.BigEndian.Uint32(value))
			}
			if !utf8.ValidRune(r) {
				return "", bad
			}
			out.WriteRune(r)
			value = value[width:]
		}
		return out.String(), nil
	}
	switch tag {
	case cbasn1.UTF8String, cbasn1.PrintableString, cbasn1.IA5String, cbasn1.Tag(18), cbasn1.Tag(20), cbasn1.Tag(27):
	default:
		return "", bad
	}
	der, err := asn1.Marshal(asn1.RawValue{Tag: int(tag), Bytes: value})
	if err != nil {
		return "", bad
	}
	var decoded string
	if _, err = asn1.Unmarshal(der, &decoded); err != nil {
		return "", bad
	}
	return decoded, nil
}
