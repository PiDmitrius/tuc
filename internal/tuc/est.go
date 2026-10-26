package tuc

import (
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// certsOnly is a CMS SignedData without signers holding certs.
func certsOnly(certs [][]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSignedData)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidData) })
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					for _, c := range certs {
						b.AddBytes(c)
					}
				})
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {})
			})
		})
	})
	return b.BytesOrPanic()
}

// writeCerts answers an EST request with certs, in base64 as RFC 7030 has it.
func writeCerts(w http.ResponseWriter, certs [][]byte) {
	b64 := base64.StdEncoding.EncodeToString(certsOnly(certs))
	var out strings.Builder
	for len(b64) > 0 {
		k := min(64, len(b64))
		out.WriteString(b64[:k] + "\n")
		b64 = b64[k:]
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	w.Header().Set("Content-Transfer-Encoding", "base64")
	io.WriteString(w, out.String())
}

// estCACerts is the chain of the CA up to its root.
func (s *Service) estCACerts(w http.ResponseWriter, r *http.Request) {
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	var certs [][]byte
	for c := n; c != nil; c = c.parent {
		certs = append(certs, c.der)
	}
	writeCerts(w, certs)
}

// estEnroll issues for a PKCS#10 request in DER, PEM or base64. A CA that
// issues by link takes its issue token as the HTTP Basic password.
func (s *Service) estEnroll(w http.ResponseWriter, r *http.Request) {
	n := s.serving(w, r)
	if n == nil {
		return
	}
	defer n.Close()
	if _, pass, _ := r.BasicAuth(); (n.closed || pass != "") && !s.checkToken(n.id, "issue", pass) {
		w.Header().Set("WWW-Authenticate", `Basic realm="TUC"`)
		fail(w, http.StatusUnauthorized, errors.New("this CA issues only with its issue token as the password"))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	cert, err := s.Issue(n, string(body))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeCerts(w, [][]byte{cert})
}
