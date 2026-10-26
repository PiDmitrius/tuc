package tuc

import (
	"strings"
	"testing"
	"time"
)

func TestCACreationDays(t *testing.T) {
	e := newEnv(t)
	e.alg = "ecdsa256"
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	for _, path := range []string{"/new", "/" + root.ID + "/new"} {
		for _, days := range []int{-1, 36501, 2932897, int(^uint(0) >> 1)} {
			if code, body := e.post(path, map[string]any{"token": root.Admin, "subject": "CN=Bounds", "days": days}); code != 400 || !strings.Contains(string(body), "36500") {
				t.Errorf("days %d: %d %s", days, code, body)
			}
		}
	}
}

func TestExpiredParentCreation(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.cert.NotAfter = time.Now().Add(-24 * time.Hour)
	if id, err := e.svc.Create(n, "ecdsa256", "CN=Child", 0, 365, false); err == nil {
		t.Fatal("created below expired parent", id)
	}
}

func TestCACreationStart(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "from": -10, "days": 5, "algo": "ecdsa256"})
	n, err := e.svc.open(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	id, err := e.svc.Create(n, "ecdsa256", "CN=Historic", -8, 10, false)
	if err != nil {
		t.Fatal(err)
	}
	child, err := e.svc.open(id)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if !child.cert.NotAfter.Equal(n.cert.NotAfter) || child.cert.NotBefore.Before(n.cert.NotBefore) {
		t.Fatal("period not clipped")
	}
	if _, err := e.svc.Create(n, "ecdsa256", "CN=Outside", 0, 10, false); err == nil {
		t.Fatal("accepted non-overlapping period")
	}
	if !child.cert.NotBefore.Before(time.Now()) {
		t.Fatal("lost start offset")
	}
}
