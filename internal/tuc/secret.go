package tuc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// text writes the secret in URL-safe unpadded base64.
var text = base64.RawURLEncoding

// tokenText writes tokens in lower-case unpadded base32: letters and digits
// only, so a double click selects one whole.
var tokenText = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

const tagLen = 16

// Secret is the service key: CA keys are encrypted with keys derived from it,
// and tokens are keyed from it.
type Secret struct {
	enc, mac, token []byte
	check           []byte
}

func NewSecret(raw []byte) (*Secret, error) {
	if len(raw) != 32 {
		return nil, errors.New("secret must be 32 bytes")
	}
	keys := make([]byte, 96)
	if _, err := io.ReadFull(hkdf.New(sha256.New, raw, nil, []byte("tuc")), keys); err != nil {
		return nil, err
	}
	check := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha256.New, raw, nil, []byte("tuc/unseal/v1")), check); err != nil {
		clear(keys)
		clear(check)
		return nil, err
	}
	return &Secret{enc: keys[:32], mac: keys[32:64], token: keys[64:], check: check}, nil
}

func (s *Secret) siv(plain []byte) []byte {
	m := hmac.New(sha256.New, s.mac)
	m.Write(plain)
	return m.Sum(nil)[:tagLen]
}

func (s *Secret) ctr(iv, in []byte) []byte {
	block, _ := aes.NewCipher(s.enc)
	out := make([]byte, len(in))
	cipher.NewCTR(block, iv).XORKeyStream(out, in)
	return out
}

// Encrypt is deterministic authenticated encryption: the SIV construction of
// HMAC-SHA256 and AES-256-CTR.
func (s *Secret) Encrypt(plain []byte) []byte {
	iv := s.siv(plain)
	return append(iv, s.ctr(iv, plain)...)
}

func (s *Secret) Decrypt(sealed []byte) ([]byte, error) {
	if len(sealed) < tagLen {
		return nil, errors.New("not encrypted by this service")
	}
	iv := sealed[:tagLen]
	plain := s.ctr(iv, sealed[tagLen:])
	if !hmac.Equal(s.siv(plain), iv) {
		clear(plain)
		return nil, errors.New("not encrypted by this service")
	}
	return plain, nil
}

// Token is the token of a CA for a role: "admin" or "issue".
func (s *Secret) Token(ca, role string, generation int64) string {
	m := hmac.New(sha256.New, s.token)
	m.Write([]byte(role))
	m.Write([]byte{0})
	m.Write([]byte(ca))
	if generation != 0 {
		var b [9]byte
		binary.BigEndian.PutUint64(b[1:], uint64(generation))
		m.Write(b[:])
	}
	return tokenText.EncodeToString(m.Sum(nil)[:20])
}

func EncodeSecret(k []byte) string { return text.EncodeToString(k) }

func DecodeSecret(s string) ([]byte, error) { return text.DecodeString(s) }

// Clear erases the derived keys when they are no longer in use.
func (s *Secret) Clear() {
	clear(s.enc)
	clear(s.mac)
	clear(s.token)
	clear(s.check)
}

// ReadSecret decodes one bounded base64url secret without a string copy.
func ReadSecret(r io.Reader) ([]byte, error) {
	in, err := io.ReadAll(io.LimitReader(r, 257))
	defer clear(in)
	if err != nil {
		return nil, errors.New("cannot read secret")
	}
	encoded := bytes.TrimSpace(in)
	if len(in) > 256 || len(encoded) != 43 {
		return nil, errors.New("secret must encode 32 bytes in unpadded base64url")
	}
	raw := make([]byte, 32)
	n, err := text.Strict().Decode(raw, encoded)
	if err != nil || n != 32 {
		clear(raw)
		return nil, errors.New("invalid secret encoding")
	}
	return raw, nil
}
