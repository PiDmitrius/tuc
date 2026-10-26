package tuc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
)

const unsealSchema = `CREATE TABLE IF NOT EXISTS unseal (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 version INTEGER NOT NULL,
 uuid BLOB NOT NULL,
 sealed BLOB NOT NULL
)`

var (
	ErrSecret     = errors.New("wrong secret or damaged database")
	ErrInitialize = errors.New("empty database requires -initialize")
	ErrConflict   = errors.New("service is already ready with another secret")
)

// State is ready only after the secret has been verified against the database.
func (s *Service) State() string {
	if s.secret.Load() == nil {
		return "sealed"
	}
	return "ready"
}

func (s *Service) Unseal(raw []byte, initialize bool) error {
	candidate, err := NewSecret(raw)
	if err != nil {
		return err
	}
	return s.unsealSecret(candidate, initialize)
}

// unsealSecret takes ownership of candidate, including on failure.
func (s *Service) unsealSecret(candidate *Secret, initialize bool) error {
	s.unsealMu.Lock()
	defer s.unsealMu.Unlock()
	keep := false
	defer func() {
		if !keep {
			candidate.Clear()
		}
	}()
	if active := s.secret.Load(); active != nil {
		if hmac.Equal(active.check, candidate.check) {
			return nil
		}
		return ErrConflict
	}
	if err := s.checkSecret(candidate, initialize); err != nil {
		return err
	}
	s.secret.Store(candidate)
	keep = true
	log.Print("tuc state: ready")
	return nil
}

func (s *Service) checkSecret(candidate *Secret, initialize bool) error {
	tx, err := s.st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	var uuid, sealed []byte
	var exists int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'unseal'").Scan(&exists); err != nil {
		return err
	}
	err = sql.ErrNoRows
	if exists != 0 {
		err = tx.QueryRow("SELECT version, uuid, sealed FROM unseal WHERE id = 1").Scan(&version, &uuid, &sealed)
	}
	check := &Secret{enc: candidate.check[:32], mac: candidate.check[32:]}
	if err == nil {
		if version != 1 || len(uuid) != 32 {
			return ErrSecret
		}
		plain, err := check.Decrypt(sealed)
		defer clear(plain)
		if err != nil || !bytes.Equal(plain, append([]byte("tuc/unseal/v1\x00"), uuid...)) {
			return ErrSecret
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rows, err := tx.Query("SELECT cert, key FROM cas UNION ALL SELECT cert, key FROM services")
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var cert, key []byte
		if err = rows.Scan(&cert, &key); err == nil {
			err = s.checkStoredKey(candidate, cert, key)
		}
		if err != nil {
			rows.Close()
			return err
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count == 0 {
		var data int
		if err := tx.QueryRow("SELECT (SELECT count(*) FROM certs) + (SELECT count(*) FROM crls)").Scan(&data); err != nil {
			return err
		}
		if data != 0 {
			return ErrSecret
		}
		if !initialize {
			return ErrInitialize
		}
	}
	uuid = make([]byte, 32)
	if _, err := rand.Read(uuid); err != nil {
		return err
	}
	sealed = check.Encrypt(append([]byte("tuc/unseal/v1\x00"), uuid...))
	if _, err := tx.Exec(unsealSchema); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO unseal (id, version, uuid, sealed) VALUES (1, 1, ?, ?)", uuid, sealed); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) checkStoredKey(candidate *Secret, der, sealed []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ErrSecret
	}
	raw, err := candidate.Decrypt(sealed)
	if err != nil {
		return ErrSecret
	}
	defer clear(raw)
	key, err := s.importKey(algoOf(cert), raw)
	if err != nil {
		return ErrSecret
	}
	defer key.Close()
	spki, err := key.SPKI()
	if err != nil || !bytes.Equal(spki, cert.RawSubjectPublicKeyInfo) {
		return ErrSecret
	}
	return nil
}

// Close is called after HTTP and local requests have stopped.
func (s *Service) Close() error {
	if secret := s.secret.Swap(nil); secret != nil {
		secret.Clear()
	}
	return s.st.db.Close()
}

func sealedReply(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "5")
	w.Header().Set("X-TUC-State", "sealed")
	if r.Method == http.MethodGet && (r.URL.Path == "/" || (idRe.MatchString(r.PathValue("id")) && strings.Count(r.URL.Path, "/") == 1)) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := pages.ExecuteTemplate(w, "sealed", nil); err != nil {
			log.Printf("sealed page: %v", err)
		}
		return
	}
	fail(w, http.StatusServiceUnavailable, errors.New("sealed"))
}

func (s *Service) gate(ready http.Handler) http.Handler {
	sealed := http.NewServeMux()
	sealed.HandleFunc("GET /livez", s.health)
	sealed.HandleFunc("GET /readyz", s.health)
	sealed.HandleFunc("GET /{id}/ca.crt", s.caCert)
	sealed.HandleFunc("GET /{id}/crl", s.crl)
	sealed.HandleFunc("GET /{id}/cert/{cert}", s.issuedCert)
	sealed.HandleFunc("GET /.well-known/est/{id}/cacerts", s.estCACerts)
	sealed.HandleFunc("GET /{id}", func(w http.ResponseWriter, r *http.Request) {
		_, ext, _ := strings.Cut(r.PathValue("id"), ".")
		if ext == "crt" || ext == "crl" {
			s.caGet(w, r)
		} else {
			sealedReply(w, r)
		}
	})
	sealed.HandleFunc("/", sealedReply)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.secret.Load() == nil {
			sealed.ServeHTTP(w, r)
		} else {
			ready.ServeHTTP(w, r)
		}
	})
}

func (s *Service) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	state := s.State()
	if r.URL.Path == "/readyz" && state != "ready" {
		sealedReply(w, r)
		return
	}
	reply(w, map[string]string{"state": state})
}

func (s *Service) savedCRL(n *node) ([]byte, time.Time, error) {
	der, _, at, err := s.st.crl(n.id)
	if err != nil {
		return nil, time.Time{}, err
	}
	crl, err := x509.ParseRevocationList(der)
	now := time.Now()
	if err != nil || at.IsZero() || crl.ThisUpdate.After(now) || !crl.NextUpdate.After(now) {
		return nil, time.Time{}, errors.New("sealed")
	}
	if err := s.mp.VerifyCRL(der, n.der); err != nil {
		return nil, time.Time{}, errors.New("sealed")
	}
	return der, at, nil
}
