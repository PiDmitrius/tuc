package tuc

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCryptoProDN(t *testing.T) {
	for _, test := range []struct{ name, dn string }{
		{`Plain User`, `CN=Plain User`}, {`Probe, Person`, `CN="Probe, Person"`},
		{`a"b`, `CN="a""b"`}, {`a\b`, `CN=a\b`}, {` +;=<># `, `CN=" +;=<># "`}, {`a'b`, `CN=a'b`},
	} {
		name := test.name
		for _, script := range []string{posixVerify("/unused"), strings.ReplaceAll(posixRevoke("/unused"), markTUC, "http://tuc.test")} {
			dir := t.TempDir()
			stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGS\"\necho 'Certificate chain: Verified successfully'\n"
			for _, tool := range []string{"cryptcp", "certmgr", "curl"} {
				if err := os.WriteFile(filepath.Join(dir, tool), []byte(stub), 0700); err != nil {
					t.Fatal(err)
				}
			}
			args := filepath.Join(dir, "args")
			// curl leaves the signing command's argument capture intact.
			os.WriteFile(filepath.Join(dir, "curl"), []byte("#!/bin/sh\nexit 0\n"), 0700)
			cmd := exec.Command("sh", "-ec", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "NAME="+name, "PATH="+dir+":"+os.Getenv("PATH"), "ARGS="+args)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v %s", err, out)
			}
			argv, err := os.ReadFile(args)
			want := "-dn\n" + test.dn + "\n"
			if err != nil || !strings.Contains(string(argv), want) {
				t.Fatalf("DN for %q: %s (%v)", name, argv, err)
			}
		}
	}
	for _, script := range []string{psVerify(), psRevoke()} {
		if !strings.Contains(script, `.Replace('"', '""')`) || strings.Contains(script, `-dn "CN=$NAME"`) || !strings.Contains(script, "-dn $DN") {
			t.Fatal("PowerShell DN escaping absent")
		}
	}
}

func TestTLSCommandNameLimit(t *testing.T) {
	for _, fqdn := range []string{"example.test", strings.Repeat("a", 31) + ".example.test", strings.Repeat("a", 32) + ".example.test", strings.Repeat("a", 50) + ".example.test"} {
		server := enrollPurposes[1]
		for _, command := range []string{posixEnroll("/opt/cprocsp/bin/amd64", "rsa2048", server, true), posixEnroll("/opt/cprocsp/bin", "rsa2048", server, true), estEnroll("rsa2048", server, true)} {
			command = strings.NewReplacer(markFQDN, fqdn, markTUC, "http://example.test", markEST, "http://example.test/est").Replace(command)
			end := strings.Index(command, "cryptcp -createcert")
			if end < 0 {
				end = strings.Index(command, "openssl req")
			}
			out, err := exec.Command("sh", "-c", command[:end]+`printf '%s\n%s' "$NAME" "$FQDN"`).CombinedOutput()
			if err != nil {
				t.Fatal(err, string(out))
			}
			fields := strings.Split(string(out), "\n")
			if len(fields[0]) > 64 || fields[1] != fqdn || !strings.HasPrefix(fields[0], "TUC-") && !strings.HasPrefix(fields[0], fqdn+"-TUC-") {
				t.Errorf("TLS name: %q", out)
			}
			if len(fqdn) <= 44 && !strings.HasPrefix(fields[0], fqdn+"-TUC-") {
				t.Errorf("short DNS lost: %q", out)
			}
		}
	}
	if !strings.Contains(psEnroll("rsa2048", enrollPurposes[1], true), `if ($FQDN.Length + 1 + $NAME.Length -le 64) { $NAME = "$FQDN-$NAME" }`) {
		t.Error("PowerShell TLS CN has no length bound")
	}
}

func TestGOSTChainHint(t *testing.T) {
	e := newEnv(t)
	root := e.create("/new", map[string]any{"subject": "CN=GOST", "algo": "gost256"})
	child := e.create("/"+root.ID+"/new", map[string]any{"subject": "CN=RSA", "algo": "rsa2048", "token": root.Admin})
	if !bytes.Contains(e.get(child.URL), []byte(`"gostChain":true`)) {
		t.Fatal("RSA CA lost GOST ancestor requirement")
	}
}

func TestEnrollCommandURLs(t *testing.T) {
	for _, p := range enrollPurposes {
		for _, chain := range []bool{true, false} {
			opts := p.u.options("/")
			if !chain {
				opts += "/justcert"
			}
			for _, cmd := range []string{posixEnroll("/opt/cprocsp/bin", "rsa2048", p, chain), psEnroll("rsa2048", p, chain)} {
				if !strings.Contains(cmd, `-ca "$TUC`+opts+`"`) || strings.Contains(cmd, "-eku") || strings.Contains(cmd, "-altname") != p.dns {
					t.Errorf("%s chain=%v: %s", p.id, chain, cmd)
				}
			}
		}
		cmd := estEnroll("rsa2048", p, true)
		if !strings.Contains(cmd, `"$EST`+p.u.options("+")+`/simpleenroll"`) || strings.Contains(cmd, "extendedKeyUsage") || strings.Contains(cmd, "subjectAltName") != p.dns {
			t.Errorf("%s: %s", p.id, cmd)
		}
	}
}
