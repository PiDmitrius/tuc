package tuc

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestIndependentAdmin(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	child := e.create("/"+root.ID+"/new", map[string]any{"subject": "CN=Child", "token": root.Admin})
	for _, path := range []string{"admin", "closed", "issuance", "new", "revoke", "rotate", "list", "disabled"} {
		if code, _ := e.post("/"+child.ID+"/"+path, map[string]any{"token": root.Admin}); code != 403 {
			t.Errorf("ancestor access %s: %d", path, code)
		}
	}
	if code, _ := e.post("/"+child.ID+"/admin", map[string]any{"token": child.Admin}); code != 200 {
		t.Fatal(code)
	}
}

func TestRotateLinks(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root", "closed": true})
	issue := strings.TrimPrefix(e.enrollURL(root.ID, root.Admin), root.URL+"/")
	for _, role := range []string{"issue", "admin"} {
		old := root.Admin
		if role == "issue" {
			old = issue
		}
		code, body := e.post("/"+root.ID+"/rotate", map[string]any{"token": root.Admin, "role": role})
		if code != 200 {
			t.Fatal(code, string(body))
		}
		var result struct{ Token string }
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		if result.Token == old || !e.svc.checkToken(root.ID, role, result.Token) || e.svc.checkToken(root.ID, role, old) {
			t.Fatal("rotation failed", role)
		}
		if role == "issue" {
			if code, _ := e.post("/"+root.ID+"/"+old+"/pfx", map[string]any{"name": "old", "password": "test"}); code != 403 {
				t.Fatal("old issue link", code)
			}
			if code, _ := e.post("/"+root.ID+"/"+result.Token+"/pfx", map[string]any{"name": "new", "password": "test"}); code != 200 {
				t.Fatal("new issue link", code)
			}
			for _, closed := range []bool{true, false} {
				if code, _ := e.post("/"+root.ID+"/closed", map[string]any{"token": root.Admin, "closed": closed}); code != 200 {
					t.Fatal(code)
				}
				req, _ := http.NewRequest("POST", e.srv.URL+"/.well-known/est/"+root.ID+"/simpleenroll", nil)
				req.SetBasicAuth("tuc", old)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 401 {
					t.Fatal("old EST token", closed, resp.StatusCode)
				}
			}
			if !e.svc.checkToken(root.ID, "admin", root.Admin) {
				t.Fatal("issue rotation changed admin")
			}
		} else {
			if code, _ := e.post("/"+root.ID+"/admin", map[string]any{"token": old}); code != 403 {
				t.Fatal("old admin link", code)
			}
			root.Admin = result.Token
		}
	}
	st, err := openStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	gen, err := st.tokenGeneration(root.ID, "admin", false)
	if err != nil || gen != 1 {
		t.Fatal("lost generation", gen, err)
	}
}
