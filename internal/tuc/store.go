package tuc

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS cas (
	id      TEXT PRIMARY KEY,                               -- SHA-1 of the certificate, hex
	parent  TEXT REFERENCES cas(id) ON DELETE CASCADE,
	cert    BLOB NOT NULL,
	key     BLOB NOT NULL,                                  -- encrypted with the service secret
	closed  INTEGER NOT NULL,
	created INTEGER NOT NULL,
	-- issuance: CRL and OCSP URLs in what the CA issues, the start of a leaf
	-- in days from its issue and its days
	crl       INTEGER NOT NULL DEFAULT 0,
	ocsp      INTEGER NOT NULL DEFAULT 0,
	leaf_from INTEGER NOT NULL DEFAULT 0,
	leaf_days INTEGER NOT NULL DEFAULT 365,
	used      INTEGER NOT NULL DEFAULT 0,                   -- last use, to the hour
	admin_gen INTEGER NOT NULL DEFAULT 0,
	issue_gen INTEGER NOT NULL DEFAULT 0,
	disabled  INTEGER NOT NULL DEFAULT 0                    -- its services answer 503
);
CREATE INDEX IF NOT EXISTS cas_parent ON cas(parent);
-- Certificates a CA issued, intermediate CAs included.
CREATE TABLE IF NOT EXISTS certs (
	id        TEXT PRIMARY KEY,                             -- SHA-1, hex
	ca        TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
	serial    TEXT NOT NULL,                                -- hex
	subject   TEXT NOT NULL,
	search    TEXT NOT NULL,                                -- subject in lower case, for search
	not_after INTEGER NOT NULL,
	der       BLOB NOT NULL,
	is_ca     INTEGER NOT NULL,
	created   INTEGER NOT NULL,
	revoked   INTEGER,                                      -- revocation time
	key_hash  TEXT                                          -- SHA-256 of the SubjectPublicKeyInfo, hex
);
CREATE INDEX IF NOT EXISTS certs_ca ON certs(ca, created);
CREATE INDEX IF NOT EXISTS certs_serial ON certs(ca, serial);
-- The certificate of a CA for a service, time-stamping or OCSP, and its key,
-- encrypted with the service secret.
CREATE TABLE IF NOT EXISTS services (
	ca      TEXT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
	service TEXT NOT NULL,
	cert    BLOB NOT NULL,
	key     BLOB NOT NULL,
	PRIMARY KEY (ca, service)
);
-- The CRL a CA published last; this_update 0 when a revocation made it stale.
CREATE TABLE IF NOT EXISTS crls (
	ca          TEXT PRIMARY KEY REFERENCES cas(id) ON DELETE CASCADE,
	der         BLOB NOT NULL,
	number      INTEGER NOT NULL,
	this_update INTEGER NOT NULL
);
`

var errNotFound = errors.New("not found")

type store struct{ db *sql.DB }

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Certificates stored without the key hash get it
	if err := addKeyColumn(db); err != nil {
		db.Close()
		return nil, err
	}
	// CAs stored without the issuance columns keep the CRL and OCSP URLs
	// they issued with
	for _, c := range []string{"crl INTEGER NOT NULL DEFAULT 1", "ocsp INTEGER NOT NULL DEFAULT 1",
		"leaf_from INTEGER NOT NULL DEFAULT 0", "leaf_days INTEGER NOT NULL DEFAULT 365", "used INTEGER NOT NULL DEFAULT 0",
		"disabled INTEGER NOT NULL DEFAULT 0", "admin_gen INTEGER NOT NULL DEFAULT 0", "issue_gen INTEGER NOT NULL DEFAULT 0"} {
		var n int
		db.QueryRow(`SELECT count(*) FROM pragma_table_info('cas') WHERE name = ?`, strings.Fields(c)[0]).Scan(&n)
		if n > 0 {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE cas ADD COLUMN ` + c); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &store{db}, nil
}

func addKeyColumn(db *sql.DB) error {
	var n int
	db.QueryRow(`SELECT count(*) FROM pragma_table_info('certs') WHERE name = 'key_hash'`).Scan(&n)
	if n == 0 {
		if _, err := db.Exec(`ALTER TABLE certs ADD COLUMN key_hash TEXT`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS certs_key ON certs(ca, key_hash)`); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, der FROM certs WHERE key_hash IS NULL`)
	if err != nil {
		return err
	}
	keys := map[string]string{}
	for rows.Next() {
		var id string
		var der []byte
		if err := rows.Scan(&id, &der); err != nil {
			rows.Close()
			return err
		}
		if keys[id], err = keyHash(der); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	for id, k := range keys {
		if _, err := db.Exec(`UPDATE certs SET key_hash = ? WHERE id = ?`, k, id); err != nil {
			return err
		}
	}
	return rows.Err()
}

type caRow struct {
	id, parent string
	cert, key  []byte
	closed     bool
	disabled   bool
	issuance
}

// issuance is how a CA issues: with CRL and OCSP URLs, and leaves valid
// from From days after their issue for Days days.
type issuance struct {
	CRL  bool `json:"crl"`
	OCSP bool `json:"ocsp"`
	From int  `json:"from"`
	Days int  `json:"days"`
}

func (st *store) ca(id string) (*caRow, error) {
	r := &caRow{id: id}
	var parent sql.NullString
	err := st.db.QueryRow(`SELECT parent, cert, key, closed, disabled, crl, ocsp, leaf_from, leaf_days FROM cas WHERE id = ?`, id).
		Scan(&parent, &r.cert, &r.key, &r.closed, &r.disabled, &r.CRL, &r.OCSP, &r.From, &r.Days)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	r.parent = parent.String
	return r, err
}

type certRow struct {
	ID, Serial, Subject string
	NotBefore, NotAfter time.Time
	Created             time.Time
	Revoked             *time.Time
	CA                  bool   // a CA certificate
	Live                bool   // a CA that is not deleted
	DER                 []byte // base64 in JSON
}

// addCA stores a CA and, under its parent, its certificate.
func (st *store) addCA(r *caRow, c *certRow) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var parent any
	if r.parent != "" {
		parent = r.parent
	}
	if _, err := tx.Exec(`INSERT INTO cas (id, parent, cert, key, closed, created, crl, ocsp, leaf_from, leaf_days) VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0, 365)`,
		r.id, parent, r.cert, r.key, r.closed, time.Now().Unix()); err != nil {
		return err
	}
	if r.parent != "" {
		if err := addCert(tx, r.parent, c, r.cert); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type execer interface {
	Exec(string, ...any) (sql.Result, error)
}

// errKeyReused: a CA certifies a key once, as the CA registry of 63-FZ
// holds a key once
var errKeyReused = errors.New("ключ уже есть в сертификате этого УЦ, в том числе отозванном или истёкшем: нужен новый ключ")

// keyHash identifies the key of a certificate.
func keyHash(der []byte) (string, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:]), nil
}

// addCert stores a certificate ca issued, errKeyReused for a key it has.
func addCert(db execer, ca string, c *certRow, der []byte) error {
	key, err := keyHash(der)
	if err != nil {
		return err
	}
	res, err := db.Exec(`INSERT INTO certs (id, ca, serial, subject, search, not_after, der, is_ca, created, key_hash)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM certs WHERE ca = ? AND key_hash = ?)`,
		c.ID, ca, c.Serial, c.Subject, strings.ToLower(c.Subject), c.NotAfter.Unix(), der, c.CA, time.Now().Unix(), key, ca, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errKeyReused
	}
	return nil
}

func (st *store) addCert(ca string, c *certRow, der []byte) error { return addCert(st.db, ca, c, der) }

// service is the certificate of ca for svc and its sealed key, none if it
// has none.
func (st *store) service(ca, svc string) (cert, key []byte, err error) {
	err = st.db.QueryRow(`SELECT cert, key FROM services WHERE ca = ? AND service = ?`, ca, svc).Scan(&cert, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	return cert, key, err
}

func (st *store) setService(ca, svc string, cert, key []byte) error {
	_, err := st.db.Exec(`INSERT INTO services (ca, service, cert, key) VALUES (?, ?, ?, ?)
		ON CONFLICT (ca, service) DO UPDATE SET cert = excluded.cert, key = excluded.key`, ca, svc, cert, key)
	return err
}

// touch marks ca used at, written at most hourly.
func (st *store) touch(ca string, at time.Time) error {
	_, err := st.db.Exec(`UPDATE cas SET used = ? WHERE id = ? AND used < ?`, at.Unix(), ca, at.Add(-time.Hour).Unix())
	return err
}

// usage is a root CA with the last use of the CAs under it, its CAs and the
// certificates they issued.
type usage struct {
	id, cert      string
	used, created time.Time
	cas, certs    int
}

// usages are the roots by their last use, the least used first.
func (st *store) usages() ([]usage, error) {
	rows, err := st.db.Query(`
		WITH RECURSIVE tree(root, id) AS (
			SELECT id, id FROM cas WHERE parent IS NULL
			UNION ALL SELECT tree.root, cas.id FROM cas JOIN tree ON cas.parent = tree.id)
		SELECT r.id, r.cert, r.created, max(max(c.used, c.created)), count(*),
			(SELECT count(*) FROM certs WHERE certs.ca IN (SELECT id FROM tree t2 WHERE t2.root = r.id))
		FROM tree JOIN cas c ON c.id = tree.id JOIN cas r ON r.id = tree.root
		GROUP BY r.id ORDER BY 4`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []usage
	for rows.Next() {
		var u usage
		var cert []byte
		var created, used int64
		if err := rows.Scan(&u.id, &cert, &created, &used, &u.cas, &u.certs); err != nil {
			return nil, err
		}
		u.created, u.used = time.Unix(created, 0).UTC(), time.Unix(used, 0).UTC()
		if c, err := x509.ParseCertificate(cert); err == nil {
			u.cert = c.Subject.CommonName
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (st *store) setIssuance(ca string, i issuance) error {
	_, err := st.db.Exec(`UPDATE cas SET crl = ?, ocsp = ?, leaf_from = ?, leaf_days = ? WHERE id = ?`, i.CRL, i.OCSP, i.From, i.Days, ca)
	return err
}

func (st *store) setClosed(ca string, closed bool) error {
	_, err := st.db.Exec(`UPDATE cas SET closed = ? WHERE id = ?`, closed, ca)
	return err
}

func (st *store) setDisabled(ca string, disabled bool) error {
	_, err := st.db.Exec(`UPDATE cas SET disabled = ? WHERE id = ?`, disabled, ca)
	return err
}

// revoke marks the certificate id issued by ca revoked, once.
func (st *store) revoke(ca, id string) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE certs SET revoked = coalesce(revoked, ?) WHERE ca = ? AND id = ?`, time.Now().Unix(), ca, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	if _, err := tx.Exec(`UPDATE crls SET this_update = 0 WHERE ca = ?`, ca); err != nil {
		return err
	}
	return tx.Commit()
}

// crl is the CRL the CA ca published last, with its number and thisUpdate,
// zero for a stale one; no CRL is number 0.
func (st *store) crl(ca string) (der []byte, number int64, thisUpdate time.Time, err error) {
	var at int64
	err = st.db.QueryRow(`SELECT der, number, this_update FROM crls WHERE ca = ?`, ca).Scan(&der, &number, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, time.Time{}, nil
	}
	if at != 0 {
		thisUpdate = time.Unix(at, 0).UTC()
	}
	return der, number, thisUpdate, err
}

// setCRL publishes only while the revocation set used for signing is current.
func (st *store) setCRL(ca string, der []byte, number int64, thisUpdate time.Time, revokedCount int) (bool, error) {
	result, err := st.db.Exec(`INSERT INTO crls (ca, der, number, this_update)
        SELECT ?, ?, ?, ? WHERE (SELECT count(*) FROM certs WHERE ca = ? AND revoked IS NOT NULL) = ?
        ON CONFLICT (ca) DO UPDATE SET der = excluded.der, number = excluded.number, this_update = excluded.this_update`,
		ca, der, number, thisUpdate.Unix(), ca, revokedCount)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

// revokedAt is when ca revoked the certificate id, nil if it did not.
func (st *store) revokedAt(ca, id string) (*time.Time, error) {
	var at sql.NullInt64
	if err := st.db.QueryRow(`SELECT revoked FROM certs WHERE ca = ? AND id = ?`, ca, id).Scan(&at); err != nil || !at.Valid {
		return nil, err
	}
	t := time.Unix(at.Int64, 0).UTC()
	return &t, nil
}

// status tells whether ca issued the certificate of serial, in hex, and
// when it revoked it, nil if it did not.
func (st *store) status(ca, serial string) (issued bool, revoked *time.Time, err error) {
	var at sql.NullInt64
	err = st.db.QueryRow(`SELECT revoked FROM certs WHERE ca = ? AND serial = ?`, ca, serial).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil || !at.Valid {
		return err == nil, nil, err
	}
	t := time.Unix(at.Int64, 0).UTC()
	return true, &t, nil
}

type childRow struct {
	id      string
	cert    []byte
	revoked bool
}

// children are the CAs right under the CA id, oldest first.
func (st *store) children(id string) ([]childRow, error) {
	rows, err := st.db.Query(`SELECT c.id, c.cert, x.revoked IS NOT NULL FROM cas c
		LEFT JOIN certs x ON x.ca = c.parent AND x.id = c.id WHERE c.parent = ? ORDER BY c.created`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []childRow
	for rows.Next() {
		var r childRow
		if err := rows.Scan(&r.id, &r.cert, &r.revoked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// remove revokes the CA id under its parent and deletes it with everything
// under it.
func (st *store) remove(id, parent string) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if parent != "" {
		if _, err := tx.Exec(`UPDATE certs SET revoked = coalesce(revoked, ?) WHERE ca = ? AND id = ?`, time.Now().Unix(), parent, id); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE crls SET this_update = 0 WHERE ca = ?`, parent); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM cas WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

type revokedRow struct {
	serial string
	at     time.Time
}

func (st *store) revoked(ca string) ([]revokedRow, error) {
	rows, err := st.db.Query(`SELECT serial, revoked FROM certs WHERE ca = ? AND revoked IS NOT NULL ORDER BY revoked`, ca)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []revokedRow
	for rows.Next() {
		var r revokedRow
		var at int64
		if err := rows.Scan(&r.serial, &at); err != nil {
			return nil, err
		}
		r.at = time.Unix(at, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (st *store) certDER(ca, id string) ([]byte, error) {
	var der []byte
	err := st.db.QueryRow(`SELECT der FROM certs WHERE ca = ? AND id = ?`, ca, id).Scan(&der)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return der, err
}

// certs lists what ca issued, newest first, matching q in the subject in any
// case, or q without spaces and colons in the SHA-1 or serial.
func (st *store) certs(ca, q string, offset, limit int) ([]certRow, error) {
	like := "%" + strings.ToLower(q) + "%"
	hex := "%" + strings.NewReplacer(" ", "", ":", "").Replace(q) + "%"
	rows, err := st.db.Query(`
		SELECT c.id, c.serial, c.subject, c.not_after, c.created, c.revoked, c.is_ca,
			EXISTS (SELECT 1 FROM cas WHERE cas.id = c.id), c.der
		FROM certs c WHERE c.ca = ? AND (c.search LIKE ? OR c.id LIKE ? OR c.serial LIKE ?)
		ORDER BY c.created DESC, c.rowid DESC LIMIT ? OFFSET ?`, ca, like, hex, hex, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []certRow
	for rows.Next() {
		var r certRow
		var notAfter, created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Serial, &r.Subject, &notAfter, &created, &revoked, &r.CA, &r.Live, &r.DER); err != nil {
			return nil, err
		}
		r.NotAfter, r.Created = time.Unix(notAfter, 0).UTC(), time.Unix(created, 0).UTC()
		if c, err := x509.ParseCertificate(r.DER); err == nil {
			r.NotBefore = c.NotBefore.UTC()
		}
		if revoked.Valid {
			t := time.Unix(revoked.Int64, 0).UTC()
			r.Revoked = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Usage writes the root CAs of the database db by their last use, the least
// used first: the use of a root is the latest of the CAs under it.
// Delete deletes the CA id of the database db with everything under it and
// revokes it under its parent, for the operator to clear CAs out of use.
func Delete(db, id string) error {
	st, err := openStore(db)
	if err != nil {
		return err
	}
	defer st.db.Close()
	r, err := st.ca(strings.ToUpper(id))
	if err != nil {
		return err
	}
	return st.remove(r.id, r.parent)
}

func Usage(db string, w io.Writer) error {
	st, err := openStore(db)
	if err != nil {
		return err
	}
	defer st.db.Close()
	us, err := st.usages()
	if err != nil {
		return err
	}
	const layout = "2006.01.02 15:04:05"
	fmt.Fprintln(w, "last use (UTC)       created (UTC)        CAs certs id                                       name")
	for _, u := range us {
		fmt.Fprintf(w, "%s  %s  %3d %5d %s %s\n", u.used.Format(layout), u.created.Format(layout), u.cas, u.certs, u.id, u.cert)
	}
	return nil
}

func (st *store) tokenGeneration(id, role string, rotate bool) (int64, error) {
	column := ""
	switch role {
	case "admin":
		column = "admin_gen"
	case "issue":
		column = "issue_gen"
	default:
		return 0, errors.New("неизвестный вид ссылки")
	}
	query := "SELECT " + column + " FROM cas WHERE id = ?"
	if rotate {
		query = "UPDATE cas SET " + column + " = " + column + " + 1 WHERE id = ? RETURNING " + column
	}
	var generation int64
	err := st.db.QueryRow(query, id).Scan(&generation)
	return generation, err
}

type publicCA struct {
	ID, CN  string
	Level   int
	Alg     algo
	Created time.Time
}

func (st *store) publicCAs() ([]publicCA, error) {
	rows, err := st.db.Query(`
		WITH RECURSIVE tree(id, level) AS (
			SELECT id, 1 FROM cas WHERE parent IS NULL
			UNION ALL SELECT c.id, tree.level + 1 FROM cas c JOIN tree ON c.parent = tree.id)
		SELECT c.id, c.cert, tree.level, c.created FROM cas c JOIN tree ON tree.id = c.id
		WHERE c.closed = 0 AND c.disabled = 0
			AND NOT EXISTS (SELECT 1 FROM certs WHERE id = c.id AND revoked IS NOT NULL)
		ORDER BY c.created DESC, c.rowid DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []publicCA
	for rows.Next() {
		var c publicCA
		var der []byte
		var created int64
		if err := rows.Scan(&c.ID, &der, &c.Level, &created); err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		c.CN, c.Alg, c.Created = cert.Subject.CommonName, algoOf(cert), time.Unix(created, 0).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}
