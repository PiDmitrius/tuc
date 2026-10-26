package tuc

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestPublicCAs(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	if page := e.get(e.srv.URL + "/"); !bytes.Contains(page, []byte("Открытых УЦ пока нет")) {
		t.Fatal("no empty list message")
	}
	root := e.create("/new", map[string]any{"subject": "CN=Public"})
	closed := e.create("/new", map[string]any{"subject": "CN=Closed", "closed": true})
	child := e.create("/"+closed.ID+"/new", map[string]any{"subject": "CN=Child", "token": closed.Admin})
	revoked := e.create("/"+root.ID+"/new", map[string]any{"subject": "CN=Revoked", "token": root.Admin})
	disabled := e.create("/new", map[string]any{"subject": "CN=Disabled"})
	deep := e.create("/"+child.ID+"/new", map[string]any{"subject": "CN=Deep", "token": child.Admin, "algo": "rsa2048"})
	if code, _ := e.post("/"+root.ID+"/revoke", map[string]any{"token": root.Admin, "cert": revoked.ID}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := e.post("/"+disabled.ID+"/disabled", map[string]any{"token": disabled.Admin, "disabled": true}); code != 200 {
		t.Fatal(code)
	}
	ids := []string{root.ID, closed.ID, child.ID, revoked.ID, disabled.ID, deep.ID}
	for i, id := range ids {
		if _, err := e.svc.st.db.Exec("UPDATE cas SET created=?, used=0, key=x'00' WHERE id=?", 1700000000+i, id); err != nil {
			t.Fatal(err)
		}
	}
	cas, err := e.svc.st.publicCAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 3 {
		t.Fatal("public CA count", len(cas))
	}
	for i, want := range []struct {
		id, cn string
		level  int
		alg    algo
	}{{deep.ID, "Deep", 3, "rsa2048"}, {child.ID, "Child", 2, "ecdsa256"}, {root.ID, "Public", 1, "ecdsa256"}} {
		c := cas[i]
		if c.ID != want.id || c.CN != want.cn || c.Level != want.level || c.Alg != want.alg {
			t.Errorf("CA %d: %+v", i, c)
		}
	}
	if !cas[0].Created.Equal(time.Unix(1700000005, 0)) {
		t.Fatal("creation time", cas[0].Created)
	}
	page := e.get(e.srv.URL + "/")
	for _, cn := range []string{"Public", "Child", "Deep"} {
		if bytes.Contains(page, []byte(cn)) {
			t.Error("the index shows a name a user chose:", cn)
		}
	}
	for _, id := range []string{root.ID, child.ID, deep.ID} {
		if !bytes.Contains(page, []byte(`href="/`+id+`"`)) {
			t.Error("missing public link", id)
		}
	}
	for _, id := range []string{closed.ID, revoked.ID, disabled.ID} {
		if bytes.Contains(page, []byte(`href="/`+id+`"`)) {
			t.Error("non-public CA on index", id)
		}
	}
	if bytes.Contains(page, []byte(root.Admin)) {
		t.Error("admin token on index")
	}

	var used int
	if err := e.svc.st.db.QueryRow("SELECT sum(used) FROM cas").Scan(&used); err != nil || used != 0 {
		t.Fatal("index touched usage", used, err)
	}
}

func TestPublicCALimit(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	var ids []string
	for i := 0; i < 23; i++ {
		ca := e.create("/new", map[string]any{"subject": fmt.Sprintf("CN=Public %02d", i)})
		ids = append(ids, ca.ID)
		if _, err := e.svc.st.db.Exec("UPDATE cas SET created=? WHERE id=?", 1700000000+i/2, ca.ID); err != nil {
			t.Fatal(err)
		}
	}
	cas, err := e.svc.st.publicCAs()
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 20 {
		t.Fatal("limit", len(cas))
	}
	for i, c := range cas {
		if c.ID != ids[len(ids)-1-i] {
			t.Error("newest first, including equal timestamps", i, c.ID)
		}
	}
}
