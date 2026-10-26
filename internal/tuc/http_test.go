package tuc

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestJSONContentType(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=Root"})
	for _, path := range []string{"/new", "/" + root.ID + "/admin", "/" + root.ID + "/pfx", "/" + root.ID + "/revoke"} {
		for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/json-invalid"} {
			resp, err := http.Post(e.srv.URL+path, ct, strings.NewReader(`{"subject":"CN=Unexpected"}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Errorf("%s %q: %d %s", path, ct, resp.StatusCode, body)
			}
		}
	}
	var count int
	if err := e.svc.st.db.QueryRow("SELECT count(*) FROM cas").Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected requests changed database", count, err)
	}
	resp, err := http.Post(e.srv.URL+"/new", "application/json; charset=utf-8", strings.NewReader(`{"subject":"CN=JSON"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}
