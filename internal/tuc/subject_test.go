package tuc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func subjectRequest(t *testing.T, tag int, value []byte) ([]byte, []byte) {
	t.Helper()
	attribute, err := asn1.Marshal(struct {
		OID   asn1.ObjectIdentifier
		Value asn1.RawValue
	}{asn1.ObjectIdentifier{2, 5, 4, 3}, asn1.RawValue{Tag: tag, Bytes: value}})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := asn1.Marshal([]asn1.RawValue{{Tag: 17, IsCompound: true, Bytes: attribute}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{RawSubject: subject}, key)
	if err != nil {
		t.Fatal(err)
	}
	return request, subject
}

func bmpName(s string) []byte {
	var value []byte
	for _, r := range utf16.Encode([]rune(s)) {
		value = binary.BigEndian.AppendUint16(value, r)
	}
	return value
}

func TestSubjectStringTypes(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, name := range []string{"Иван Тест", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno", strings.Repeat("Я", 64)} {
		request, subject := subjectRequest(t, 30, bmpName(name))
		cert, err := e.svc.Issue(n, string(request))
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		parsed, err := x509.ParseCertificate(cert)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.RawSubject, subject) || nameString(subject) != "CN="+name {
			t.Error("Subject changed or displayed incorrectly", nameString(subject))
		}
		rows, err := e.svc.st.certs(root.ID, name, 0, 100)
		if err != nil || len(rows) != 1 || rows[0].Subject != "CN="+name {
			t.Error("name search", rows, err)
		}
	}
	request, _ := subjectRequest(t, 30, bmpName(strings.Repeat("Я", 65)))
	if _, err := e.svc.Issue(n, string(request)); err == nil {
		t.Error("accepted 65 characters")
	}
	for _, tc := range []struct {
		tag   int
		value []byte
		want  string
	}{{20, []byte{0xe9}, "é"}, {12, []byte("Иван"), "Иван"}, {19, []byte("Test"), "Test"}, {22, []byte("test@example.test"), "test@example.test"}, {18, []byte("123"), "123"}, {28, []byte{0, 0, 4, 0x18}, "И"}} {
		_, subject := subjectRequest(t, tc.tag, tc.value)
		if err := checkName(subject); err != nil || nameString(subject) != "CN="+tc.want {
			t.Errorf("tag %d: %q %v", tc.tag, nameString(subject), err)
		}
	}
}

func TestSubjectControls(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, name := range []string{"evil\x1b[31m", "line\nnext", "NUL\x00", "delete\x7f", "C1\u0085"} {
		if _, err := ParseName("CN=" + name); err == nil {
			t.Errorf("CA accepted %q", name)
		}
		for _, tag := range []int{12, 30} {
			value := []byte(name)
			if tag == 30 {
				value = bmpName(name)
			}
			request, _ := subjectRequest(t, tag, value)
			if _, err := e.svc.Issue(n, string(request)); err == nil {
				t.Errorf("CSR accepted %q tag %d", name, tag)
			}
		}
	}
}

func TestEmptySubjectRequest(t *testing.T) {
	if err := checkName([]byte{0x30, 0}); err == nil {
		t.Error("empty Subject accepted")
	}
	e := newEnv(t)
	e.alg = "ecdsa256"
	e.subj = "/"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	request := csr(t, e)
	if cert, err := e.svc.Issue(n, string(request)); err == nil {
		t.Fatal("issued empty Subject", len(cert))
	}
}
