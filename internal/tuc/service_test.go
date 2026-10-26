package tuc

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"
)

func TestServiceRevocation(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, svc := range []service{serviceTSA, serviceOCSP} {
		key, old, err := e.svc.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		if code, _ := e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": certID(old)}); code != 200 {
			t.Fatal(code)
		}
		key, fresh, err := e.svc.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		if bytes.Equal(old, fresh) {
			t.Fatal("reused revoked service certificate", svc)
		}
		if at, err := e.svc.st.revokedAt(n.id, certID(fresh)); err != nil || at != nil {
			t.Fatal("replacement is revoked", err)
		}
	}
}

func TestServiceValidityWindow(t *testing.T) {
	for _, tc := range []struct {
		name       string
		from, days int
	}{{"expired", -400, 200}, {"future", 400, 200}, {"expired-short", -400, 10}, {"future-short", 400, 10}, {"current", -1, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			root := e.create("/new", map[string]any{"subject": "CN=Window", "algo": "ecdsa256", "from": tc.from, "days": tc.days})
			n, err := e.svc.open(root.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer n.Close()
			for _, svc := range []service{serviceOCSP, serviceTSA} {
				key, der, err := e.svc.service(n, svc)
				if err != nil {
					t.Fatal(svc, err)
				}
				key.Close()
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if !cert.NotAfter.After(cert.NotBefore) || cert.NotBefore.Before(n.cert.NotBefore) || cert.NotAfter.After(n.cert.NotAfter) {
					t.Errorf("%s: service %v..%v outside CA %v..%v", svc, cert.NotBefore, cert.NotAfter, n.cert.NotBefore, n.cert.NotAfter)
				}
				if tc.from > 0 && !cert.NotBefore.Equal(n.cert.NotBefore) {
					t.Error("future service must start with CA", svc)
				}
				if tc.from+tc.days < 0 && !cert.NotAfter.Equal(n.cert.NotAfter) {
					t.Error("expired service must end with CA", svc)
				}
				if svc == serviceOCSP && tc.from != -1 {
					want := 90 * 24 * time.Hour
					if tc.days < 90 {
						want = n.cert.NotAfter.Sub(n.cert.NotBefore)
					}
					if cert.NotAfter.Sub(cert.NotBefore) != want {
						t.Error("OCSP duration", cert.NotAfter.Sub(cert.NotBefore), want)
					}
				}
				key, again, err := e.svc.service(n, svc)
				if err != nil {
					t.Fatal(err)
				}
				key.Close()
				if !bytes.Equal(der, again) {
					t.Error("service regenerated", svc)
				}
			}
		})
	}
}

func TestServiceEmptyWindow(t *testing.T) {
	for _, svc := range []service{serviceOCSP, serviceTSA} {
		e := newEnv(t)
		root := e.create("/new", map[string]any{"subject": "CN=Empty", "algo": "ecdsa256"})
		n, err := e.svc.open(root.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer n.Close()
		n.cert.NotAfter = n.cert.NotBefore
		key, _, err := e.svc.service(n, svc)
		if key != nil {
			key.Close()
		}
		if err == nil {
			t.Error("empty window accepted", svc)
		}
	}
}

func TestServiceRepairsInvalidWindow(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Expired", "algo": "ecdsa256", "from": -400, "days": 10})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	for _, svc := range []service{serviceOCSP, serviceTSA} {
		key, raw, err := e.svc.newKey(n.alg)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := key.SPKI()
		key.Close()
		if err != nil {
			clear(raw)
			t.Fatal(err)
		}
		old, err := e.svc.issueCert(n, &certTemplate{subject: nameCN("Invalid service"), spki: spki, notBefore: time.Now().UTC().Truncate(time.Second), notAfter: n.cert.NotAfter})
		if err == nil {
			err = e.svc.st.setService(n.id, string(svc), old, e.svc.secret.Load().Encrypt(raw))
		}
		clear(raw)
		if err != nil {
			t.Fatal(err)
		}
		key, fresh, err := e.svc.service(n, svc)
		if err != nil {
			t.Fatal(err)
		}
		key.Close()
		cert, err := x509.ParseCertificate(fresh)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(old, fresh) || !cert.NotAfter.After(cert.NotBefore) {
			t.Error("invalid cached certificate reused", svc)
		}
	}
}
