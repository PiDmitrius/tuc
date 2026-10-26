package tuc

import (
	"html/template"
	"regexp"
	"strings"
)

// Markers in commands that a page fills: the enroll URL of the CA for
// cryptcp, which may carry the issue token, the same over HTTPS for a PFX,
// the address revocation posts to, the EST URL, the DNS name of a TLS server,
// and fields of the page.
const (
	markTUC  = "\x00TUC\x00"
	markTUCS = "\x00TUCS\x00"
	markRev  = "\x00REV\x00"
	markEST  = "\x00EST\x00"
	markFQDN = "\x00FQDN\x00"
)

// field is the marker of a page field, group.name, quoted for a POSIX shell
// or PowerShell: new is the PFX to issue (name, pass, json, json64), pfx the
// one to import (name, pass, b64) and rev the one to revoke by (pass, b64).
func field(name string, ps bool) string {
	if ps {
		return "\x00F" + name + " ps\x00"
	}
	return "\x00F" + name + "\x00"
}

var fieldMark = regexp.MustCompile(`\x00F([a-z]+\.[a-z0-9]+)( ps)?\x00`)

// urls are the addresses a page starts with, before it knows the token.
type urls struct{ tuc, tucs, est string }

// script is a command as HTML: the markers become spans that the page fills.
func script(cmd string, u urls) template.HTML {
	cmd = fieldMark.ReplaceAllStringFunc(cmd, func(m string) string {
		g := fieldMark.FindStringSubmatch(m)
		ps := ""
		if g[2] != "" {
			ps = " data-ps"
		}
		return "\x01" + g[1] + ps + "\x02"
	})
	h := template.HTMLEscapeString(cmd)
	h = strings.ReplaceAll(h, "\x01", `<span data-f="`)
	h = strings.ReplaceAll(h, "\x02", `">''</span>`)
	h = strings.ReplaceAll(h, " data-ps\">", `" data-ps>`)
	for m, span := range map[string]string{markTUC: `<span data-tuc>` + u.tuc, markTUCS: `<span data-tucs>` + u.tucs,
		markRev: `<span data-rev>` + u.tuc, markEST: `<span data-est>` + u.est, markFQDN: `<span data-fqdn>&lt;FQDN&gt;`} {
		h = strings.ReplaceAll(h, template.HTMLEscapeString(m), span+`</span>`)
	}
	return template.HTML(h)
}

// chain joins shell commands into one, so that a repeat from the history
// runs all of them; psChain does so for PowerShell, which 5.1 has no && in.
func chain(cmds ...string) string { return strings.Join(cmds, " && \\\n") }

func psChain(cmds ...string) string { return strings.Join(cmds, "; `\n") }

// osCommands are the commands of a tool, "pfx", "openssl" or "cryptopro";
// those of CryptoPro differ by OS; OpenSSL and CryptoPro also issue and
// install a PFX and install one of the page.
type osCommands struct {
	ID, Title, Tool string
	Enroll          []enrollCommand
	PFX, Import     template.HTML // issue a PFX and install it, install one of the page
	Verify          template.HTML
	Revoke          template.HTML
}

type enrollCommand struct {
	Purpose  string // the id of an enrollPurpose
	Response string // "chain" or "cert"
	Script   template.HTML
}

// CryptoPro commands find a certificate by its SHA-1 thumbprint, in $SHA1:
// the enroll and PFX install commands set it.
const (
	posixSHA1 = `SHA1=$(certmgr -list -store uMy -container "\\\\.\\HDIMAGE\\$NAME" | sed -n 's/^SHA1 Thumbprint *: //p') && echo "SHA1=$SHA1"`
	psSHA1    = `$SHA1 = (certmgr -list -store uMy -container "\\.\HDIMAGE\$NAME" | Select-String 'SHA1 Thumbprint\s*:\s*(\w+)').Matches[0].Groups[1].Value; "SHA1=$SHA1"`
)

// enrollPurpose is a purpose the page offers: the TLS use and whether the
// request carries a DNS name, which a server requires and a client may have.
type enrollPurpose struct {
	id  string
	u   purpose
	dns bool
}

var enrollPurposes = []enrollPurpose{
	{"user", purpose{}, false},
	{"server", purpose{server: true}, true},
	{"client", purpose{client: true}, false},
	{"client-dns", purpose{client: true}, true},
	{"both", purpose{server: true, client: true}, true},
}

// options are the enroll path options or EST label options of u, each after sep.
func (u purpose) options(sep string) string {
	o := ""
	if u.server {
		o += sep + "tls-server"
	}
	if u.client {
		o += sep + "tls-client"
	}
	return o
}

// cryptcpCA is the -ca option: the enroll URL with the purpose and response
// options; -silent skips the root install prompt.
func cryptcpCA(u purpose, withChain bool) string {
	url := "$TUC" + u.options("/")
	if withChain {
		return ` -ca "` + url + `"`
	}
	return ` -ca "` + url + `/justcert" -silent`
}

var dnsName = []string{"NAME=TUC-$(date +%Y%m%d-%H%M%S)", `if [ $((${#FQDN} + 1 + ${#NAME})) -le 64 ]; then NAME=$FQDN-$NAME; fi`}

func posixEnroll(path string, a algo, p enrollPurpose, withChain bool) string {
	lines := []string{"export PATH=$PATH:" + path, "TUC=" + markTUC}
	opts := algoDefs[a].cryptcp
	if p.dns {
		lines = append(append(lines, "FQDN="+markFQDN), dnsName...)
		opts += ` -altname "$FQDN"`
	} else {
		lines = append(lines, "NAME=${USER:-$(id -un)}-TUC-$(date +%Y%m%d-%H%M%S)")
	}
	lines = append(lines, `cryptcp -createcert -rdn "CN=$NAME" -cont "\\\\.\\HDIMAGE\\$NAME" -du -pin ""`+opts+cryptcpCA(p.u, withChain), posixSHA1)
	return chain(lines...)
}

func posixRevoke(path string) string {
	return chain("export PATH=$PATH:"+path, "TUC="+markRev, `if [ -z "$SHA1" ]; then echo "Укажите SHA1 сертификата для отзыва"; else
  T=$(mktemp -d) && echo revoke > "$T/r.txt" &&
  cryptcp -sign -thumbprint "$SHA1" -pin "" "$T/r.txt" "$T/r.p7s" &&
  curl --data-binary @"$T/r.p7s" "$TUC/revoke"; e=$?; echo; rm -rf "$T"; [ $e = 0 ]
fi`)
}

func psEnroll(a algo, p enrollPurpose, withChain bool) string {
	date := "$(Get-Date -Format yyyyMMdd-HHmmss)"
	lines := []string{`$env:Path += ";C:\Program Files\Crypto Pro\CSP"`, `$TUC = "` + markTUC + `"`}
	opts := algoDefs[a].cryptcp
	if p.dns {
		lines = append(lines, `$FQDN = "`+markFQDN+`"`, `$NAME = "TUC-`+date+`"`, `if ($FQDN.Length + 1 + $NAME.Length -le 64) { $NAME = "$FQDN-$NAME" }`)
		opts += " -altname $FQDN"
	} else {
		lines = append(lines, `$NAME = "$env:USERNAME-TUC-`+date+`"`)
	}
	lines = append(lines, `cryptcp -createcert -rdn "CN=$NAME" -cont "\\.\HDIMAGE\$NAME" -du`+opts+cryptcpCA(p.u, withChain), psSHA1)
	return psChain(lines...)
}

func psRevoke() string {
	return psChain(`$env:Path += ";C:\Program Files\Crypto Pro\CSP"`, `$TUC = "`+markRev+`"`, `if (-not $SHA1) { "Укажите SHA1 сертификата для отзыва" } else {
  $T = Join-Path $env:TEMP ([guid]::NewGuid()); New-Item -ItemType Directory $T | Out-Null
  Set-Content -Encoding ascii "$T\r.txt" revoke
  cryptcp -sign -thumbprint $SHA1 "$T\r.txt" "$T\r.p7s"
  if ($LASTEXITCODE -eq 0) { curl.exe --data-binary "@$T\r.p7s" "$TUC/revoke" }
  Remove-Item -Recurse -Force $T
}`)
}

// estEnroll enrolls with openssl and curl over EST into $NAME.key and
// $NAME.crt, the certificate followed, with chain, by the CA chain.
func estEnroll(a algo, p enrollPurpose, withChain bool) string {
	lines := []string{"EST=" + markEST}
	ext := ""
	if p.dns {
		lines = append(append(lines, "FQDN="+markFQDN), dnsName...)
		ext = ` -addext "subjectAltName=DNS:$FQDN"`
	} else {
		lines = append(lines, "NAME=${USER:-$(id -un)}-TUC-$(date +%Y%m%d-%H%M%S)")
	}
	lines = append(lines, `openssl req -new `+algoDefs[a].openssl+` -nodes -keyout "$NAME.key" -subj "/CN=$NAME"`+ext+` -outform DER |
  base64 | curl -sSf --data-binary @- -H "Content-Type: application/pkcs10" "$EST`+p.u.options("+")+`/simpleenroll" |
  base64 -d | openssl pkcs7 -inform DER -print_certs -out "$NAME.crt"`)
	if withChain {
		lines = append(lines, `curl -sSf "$EST/cacerts" | base64 -d | openssl pkcs7 -inform DER -print_certs >> "$NAME.crt"`)
	}
	return chain(lines...)
}

func estRevoke() string {
	return chain("TUC="+markRev, `if [ -z "$NAME" ]; then echo "Укажите NAME сертификата для отзыва"; else
  echo revoke | openssl cms -sign -signer "$NAME.crt" -inkey "$NAME.key" -binary -nodetach -outform DER |
  curl -sSf --data-binary @- "$TUC/revoke"; echo
fi`)
}

// A PFX is fetched into a private temporary directory $T and installed from
// there; the directory goes whether the steps succeed or not, and the
// command keeps their status. Issued, it comes from the HTTPS address with
// the request of the page; imported, from the base64 of the page.
const cleanup = `; e=$?; rm -rf "$T"; [ $e = 0 ]`

func issuePFX(ps bool) string {
	if ps {
		return psChain("$TUC = \""+markTUCS+"\"", `[IO.File]::WriteAllBytes("$T\r.json", [Convert]::FromBase64String(`+field("new.json64", true)+`))`,
			`curl.exe -sSf -H "Content-Type: application/json" --data-binary "@$T\r.json" -o "$T\p.pfx" "$TUC/pfx"`)
	}
	return chain("TUC="+markTUCS, `curl -sSf -H "Content-Type: application/json" --data-binary `+field("new.json", false)+` -o "$T/p.pfx" "$TUC/pfx"`)
}

func decodePFX(group, decode string) string {
	return `printf %s ` + field(group+".b64", false) + ` | ` + decode + ` > "$T/p.pfx"`
}

// opensslPFX installs the PFX as the enroll with openssl does: $NAME.crt,
// the certificate followed by the CA chain, and $NAME.key without a password.
func opensslPFX(group string) string {
	get := decodePFX(group, "openssl base64 -d -A")
	if group == "new" {
		get = issuePFX(false)
	}
	return chain("NAME="+field(group+".name", false), "PASS="+field(group+".pass", false), "T=$(mktemp -d)", get,
		`openssl pkcs12 -in "$T/p.pfx" -passin pass:"$PASS" -nokeys -out "$NAME.crt"`,
		`(umask 077; openssl pkcs12 -in "$T/p.pfx" -passin pass:"$PASS" -nocerts -nodes -out "$NAME.key")`) + cleanup
}

// posixPFX installs the PFX into CryptoPro with a key without a password,
// and its root, which the PFX does not make trusted; SHA1 is the thumbprint
// of its certificate, the one with the key among those certmgr reports.
func posixPFX(path, root, group string) string {
	get := decodePFX(group, "base64 -d")
	if group == "new" {
		get = issuePFX(false)
	}
	return chain("export PATH=$PATH:"+path, "PASS="+field(group+".pass", false), "T=$(mktemp -d)", get,
		`{ certmgr -inst -pfx -file "$T/p.pfx" -pin "$PASS" -newpin "" > "$T/out" || { cat "$T/out"; false; }; }`,
		`SHA1=$(awk '/^SHA1 Thumbprint/ {s = $NF} /^PrivateKey Link *: Yes/ {print s; exit}' "$T/out")`, `echo "SHA1=$SHA1"`,
		`curl -sSf -o "$T/root.cer" "`+root+`.crt"`, `certmgr -inst -store uRoot -file "$T/root.cer"`) + cleanup
}

func psPFX(root, group string) string {
	get := `[IO.File]::WriteAllBytes("$T\p.pfx", [Convert]::FromBase64String(` + field(group+".b64", true) + `))`
	install := `$out = certmgr -inst -pfx -file "$T\p.pfx" -pin $PASS`
	if group == "new" {
		get = issuePFX(true)
		install = `if ($LASTEXITCODE -eq 0) { ` + install + ` }`
	}
	return psChain(`$env:Path += ";C:\Program Files\Crypto Pro\CSP"`, "$PASS = "+field(group+".pass", true),
		"$T = Join-Path $env:TEMP ([guid]::NewGuid())", "New-Item -ItemType Directory $T | Out-Null", get, install,
		`if ($LASTEXITCODE -eq 0) { foreach ($l in $out) { if ($l -match '^SHA1 Thumbprint\s*:\s*(\w+)') { $s = $Matches[1] } elseif ($l -match '^PrivateKey Link\s*:\s*Yes') { $SHA1 = $s; break } }; "SHA1=$SHA1" } else { $out }`,
		`if ($LASTEXITCODE -eq 0) { curl.exe -sSf -o "$T\root.cer" "`+root+`.crt" }`,
		`if ($LASTEXITCODE -eq 0) { certmgr -inst -store uRoot -file "$T\root.cer" }`,
		"Remove-Item -Recurse -Force $T")
}

// estVerify checks $NAME.crt, the certificate followed by its CA chain,
// up to the root at root: the chain, then revocation of the whole chain by
// CRL, the root's CRL given as the root itself has no CRL URL, and of the
// certificate by OCSP of the issuer at issuer.
func estVerify(root, issuer string) string {
	return `if [ -z "$NAME" ]; then echo "Укажите NAME сертификата"; else
  curl -sSf "` + root + `.crt" | openssl x509 -inform DER -out "$NAME.root.pem" &&
  curl -sSf "` + root + `.crl" | openssl crl -inform DER -out "$NAME.root.crl" &&
  curl -sSf "` + issuer + `.crt" | openssl x509 -inform DER -out "$NAME.issuer.pem" &&
  openssl x509 -in "$NAME.crt" -out "$NAME.leaf.pem" && {
  echo "Цепочка:"; openssl verify -CAfile "$NAME.root.pem" -untrusted "$NAME.crt" "$NAME.leaf.pem"
  echo "CRL цепочки:"
  if openssl x509 -in "$NAME.leaf.pem" -noout -ext crlDistributionPoints 2>/dev/null | grep -q 'URI:'; then
    openssl verify -crl_download -crl_check_all -CRLfile "$NAME.root.crl" -CAfile "$NAME.root.pem" -untrusted "$NAME.crt" "$NAME.leaf.pem"
  else echo "В сертификате нет CDP"; fi
  echo "OCSP сертификата:"
  OCSP_URL=$(openssl x509 -in "$NAME.leaf.pem" -noout -ocsp_uri)
  if [ -n "$OCSP_URL" ]; then
    openssl ocsp -issuer "$NAME.issuer.pem" -cert "$NAME.leaf.pem" -url "$OCSP_URL" \
      -CAfile "$NAME.root.pem" -verify_other "$NAME.crt"
  else echo "В сертификате нет адреса OCSP"; fi; }
fi`
}

// posixVerify checks the chain of the certificate CN=$NAME in the CryptoPro
// store, revocation included.
func posixVerify(path string) string {
	return chain("export PATH=$PATH:"+path, `if [ -z "$SHA1" ]; then echo "Укажите SHA1 сертификата"; else
  certmgr -list -store uMy -thumbprint "$SHA1" -chain | grep "Certificate chain"
fi`)
}

func psVerify() string {
	return psChain(`$env:Path += ";C:\Program Files\Crypto Pro\CSP"`, `if (-not $SHA1) { "Укажите SHA1 сертификата" } else {
  certmgr -list -store uMy -thumbprint $SHA1 -chain | Select-String "Certificate chain"
}`)
}

// pfxRevoke revokes with the key of the PFX of the page, through openssl.
func pfxRevoke() string {
	return chain("TUC="+markRev, "PASS="+field("rev.pass", false), "T=$(mktemp -d)", decodePFX("rev", "openssl base64 -d -A"),
		`(umask 077; openssl pkcs12 -in "$T/p.pfx" -passin pass:"$PASS" -nodes -out "$T/p.pem")`,
		`echo revoke | openssl cms -sign -signer "$T/p.pem" -binary -nodetach -outform DER |
  curl -sSf --data-binary @- "$TUC/revoke"`) + `; e=$?; echo; rm -rf "$T"; [ $e = 0 ]`
}

// commands are the enroll, PFX issue and import, verify and revoke commands
// of the CA at the addresses u, the root at root, with keys of a: of a PFX,
// of openssl over EST and of CryptoPro for each OS.
func commands(u urls, root string, a algo) []osCommands {
	type osDef struct {
		id, title, tool string
		enroll          func(p enrollPurpose, chain bool) string
		pfx             func(group string) string
		verify, revoke  string
	}
	posix := func(path string) func(enrollPurpose, bool) string {
		return func(p enrollPurpose, chain bool) string { return posixEnroll(path, a, p, chain) }
	}
	ps := func(p enrollPurpose, chain bool) string { return psEnroll(a, p, chain) }
	openssl := func(p enrollPurpose, chain bool) string { return estEnroll(a, p, chain) }
	posixPFXAt := func(path string) func(string) string {
		return func(group string) string { return posixPFX(path, root, group) }
	}
	defs := []osDef{
		{"pfx", "PFX", "pfx", nil, nil, "", pfxRevoke()},
		{"openssl", "OpenSSL", "openssl", openssl, opensslPFX, estVerify(root, u.tuc), estRevoke()},
		{"linux", "Linux", "cryptopro", posix("/opt/cprocsp/bin/amd64"), posixPFXAt("/opt/cprocsp/bin/amd64"), posixVerify("/opt/cprocsp/bin/amd64"), posixRevoke("/opt/cprocsp/bin/amd64")},
		{"windows", "Windows", "cryptopro", ps, func(group string) string { return psPFX(root, group) }, psVerify(), psRevoke()},
		{"macos", "macOS", "cryptopro", posix("/opt/cprocsp/bin"), posixPFXAt("/opt/cprocsp/bin"), posixVerify("/opt/cprocsp/bin"), posixRevoke("/opt/cprocsp/bin")},
	}
	var out []osCommands
	for _, d := range defs {
		c := osCommands{ID: d.id, Title: d.title, Tool: d.tool, Verify: script(d.verify, u), Revoke: script(d.revoke, u)}
		if d.pfx != nil {
			c.PFX, c.Import = script(d.pfx("new"), u), script(d.pfx("pfx"), u)
		}
		// openssl puts the chain into $NAME.crt; with CryptoPro it is a choice
		responses := []string{"chain"}
		if d.tool == "cryptopro" {
			responses = append(responses, "cert")
		}
		for _, p := range enrollPurposes {
			if d.enroll == nil {
				break
			}
			for _, response := range responses {
				c.Enroll = append(c.Enroll, enrollCommand{p.id, response, script(d.enroll(p, response == "chain"), u)})
			}
		}
		out = append(out, c)
	}
	return out
}
