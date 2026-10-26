package tuc

import (
	"encoding/asn1"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidOCSPSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidOCSPNoCheck  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	keyUsageService = []byte{0x07, 0x80} // digitalSignature
)

var dnsRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

func validDNS(name string) bool {
	if len(name) > 253 || !dnsRe.MatchString(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}

// tlsExtensions builds the TLS template from validated DNS names.
func tlsExtensions(names []string) ([]cryptobyte.String, error) {
	if len(names) == 0 {
		return nil, errors.New("для TLS требуется DNS-имя в SAN")
	}
	for _, name := range names {
		if !validDNS(name) {
			return nil, errors.New("некорректное DNS-имя")
		}
	}
	return []cryptobyte.String{ekuExt(false, oidServerAuth, oidClientAuth),
		extension(oidSAN, false, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, name := range names {
					b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte(strings.ToLower(name))) })
				}
			})
		})}, nil
}

// extension is the DER of an extension of oid.
func extension(oid asn1.ObjectIdentifier, critical bool, value func(*cryptobyte.Builder)) cryptobyte.String {
	var b cryptobyte.Builder
	addExt(&b, oid, critical, value)
	return b.BytesOrPanic()
}

func keyUsageExt(bits []byte) cryptobyte.String {
	return extension(oidKeyUsage, true, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) { b.AddBytes(bits) })
	})
}

func ekuExt(critical bool, oids ...asn1.ObjectIdentifier) cryptobyte.String {
	return extension(oidEKU, critical, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, o := range oids {
				b.AddASN1ObjectIdentifier(o)
			}
		})
	})
}

// nameCN is a Name of the common name cn alone.
func nameCN(cn string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(nameAttrs["CN"].oid)
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(cn)) })
			})
		})
	})
	return b.BytesOrPanic()
}

// IssuePFX makes a key of a, by default the algorithm of n, and a leaf
// certificate of n for it named cn, with the key usages of its key and,
// for TLS, the DNS name fqdn as a server and client, and returns them
// with the chain of n in a PKCS#12 under password.
func (s *Service) IssuePFX(n *node, a algo, cn string, tls bool, fqdn, password string) ([]byte, error) {
	if a == "" {
		a = n.alg
	}
	if _, ok := algoDefs[a]; !ok {
		return nil, errors.New("неизвестный алгоритм")
	}
	if cn == "" || utf8.RuneCountInString(cn) > 64 {
		return nil, errors.New("имя — от 1 до 64 символов")
	}
	if password == "" || len(password) > 128 {
		return nil, errors.New("пароль — от 1 до 128 байт")
	}
	var extra []cryptobyte.String
	if tls {
		var err error
		extra, err = tlsExtensions([]string{fqdn})
		if err != nil {
			return nil, err
		}
	}
	subject := nameCN(cn)
	if err := checkName(subject); err != nil {
		return nil, err
	}
	key, raw, err := s.newKey(a)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	clear(raw)
	spki, err := key.SPKI()
	if err != nil {
		return nil, err
	}
	cert, err := s.issueLeaf(n, subject, spki, extra)
	if err != nil {
		return nil, err
	}
	var chain [][]byte
	for c := n; c != nil; c = c.parent {
		chain = append(chain, c.der)
	}
	return key.PKCS12(cert, chain, password)
}
