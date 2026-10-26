package tuc

import (
	"html/template"
	"strings"
)

// Markers in commands that a page fills: the enroll URL of the CA and its
// EST URL, which may carry the issue token, the DNS name of a TLS server, and
// the file name, CN and password of the PFX downloaded last, quoted for a
// POSIX shell or PowerShell.
const (
	markTUC    = "\x00TUC\x00"
	markEST    = "\x00EST\x00"
	markFQDN   = "\x00FQDN\x00"
	markName   = "\x00NAME\x00"
	markPass   = "\x00PASS\x00"
	markNamePS = "\x00NAMEPS\x00"
	markCN     = "\x00CN\x00"
	markCNPS   = "\x00CNPS\x00"
	markPassPS = "\x00PASSPS\x00"
	markSetPFX = "\x00SETPFX\x00"
)

// script is a command as HTML: the markers become spans that the page fills.
func script(cmd, tuc, est string) template.HTML {
	h := template.HTMLEscapeString(cmd)
	h = strings.ReplaceAll(h, template.HTMLEscapeString(markTUC), `<span data-tuc>`+template.HTMLEscapeString(tuc)+`</span>`)
	h = strings.ReplaceAll(h, template.HTMLEscapeString(markEST), `<span data-est>`+template.HTMLEscapeString(est)+`</span>`)
	h = strings.ReplaceAll(h, template.HTMLEscapeString(markFQDN), `<span data-fqdn>&lt;FQDN&gt;</span>`)
	for m, span := range map[string]string{markName: `data-pfx="name"`, markPass: `data-pfx="pass"`,
		markNamePS: `data-pfx="name" data-ps`, markPassPS: `data-pfx="pass" data-ps`,
		markCN: `data-pfx="cn"`, markCNPS: `data-pfx="cn" data-ps`} {
		h = strings.ReplaceAll(h, template.HTMLEscapeString(m), `<span `+span+`>''</span>`)
	}
	h = strings.ReplaceAll(h, template.HTMLEscapeString(markSetPFX), `<span data-pfx-set>NAME=${NAME:-}`+"\n"+`PASS=${PASS:-}</span>`)
	return template.HTML(h)
}

// osCommands are the commands of a tool, "pfx", "openssl" or "cryptopro";
// those of CryptoPro differ by OS, a PFX is enrolled on the page and
// imported by the others.
type osCommands struct {
	ID, Title, Tool string
	Enroll          []enrollCommand
	Import, Verify  template.HTML
	Revoke          template.HTML
}

type enrollCommand struct {
	Purpose  string // "plain" or "tls"
	Response string // "chain" or "cert"
	Script   template.HTML
}

// DN values quote their separators and double embedded quotes independently of the shell.
const posixDN = `DN=$(printf '%s' "$NAME" | sed '/[,+"<>;=#]/ {s/"/""/g;s/^/"/;s/$/"/;}')
DN="CN=$DN"`
const psDN = `$DN = $NAME
if ($DN -match '[,+"<>;=#]') { $DN = '"' + $DN.Replace('"', '""') + '"' }
$DN = 'CN=' + $DN`

const ekuTLS = "-eku 1.3.6.1.5.5.7.3.1 -eku 1.3.6.1.5.5.7.3.2"

const tlsName = `NAME=TUC-$(date +%Y%m%d-%H%M%S)
if [ $((${#FQDN} + 1 + ${#NAME})) -le 64 ]; then NAME=$FQDN-$NAME; fi`

func posixEnroll(path string, a algo, tls, chain bool) string {
	lines := []string{"export PATH=$PATH:" + path, "TUC=" + markTUC}
	opts := algoDefs[a].cryptcp
	if tls {
		lines = append(lines, "FQDN="+markFQDN, tlsName)
		opts += ` -altname "$FQDN" ` + ekuTLS
	} else {
		lines = append(lines, "NAME=${USER:-$(id -un)}-TUC-$(date +%Y%m%d-%H%M%S)")
	}
	ca := ` -ca "$TUC"`
	if !chain {
		ca = ` -ca "$TUC/justcert" -silent`
	}
	lines = append(lines, `cryptcp -createcert -rdn "CN=$NAME" -cont "\\\\.\\HDIMAGE\\$NAME" -du -pin ""`+opts+ca)
	return strings.Join(lines, "\n")
}

func posixRevoke(path string) string {
	return "export PATH=$PATH:" + path + "\nTUC=" + markTUC + `
if [ -z "$NAME" ]; then echo "Укажите NAME сертификата для отзыва"; else
  ` + posixDN + `
  echo revoke > "$NAME.revoke.txt" &&
  cryptcp -sign -dn "$DN" -pin "" "$NAME.revoke.txt" "$NAME.revoke.p7s" &&
  curl --data-binary @"$NAME.revoke.p7s" "$TUC/revoke"; echo
fi`
}

func psEnroll(a algo, tls, chain bool) string {
	date := "$(Get-Date -Format yyyyMMdd-HHmmss)"
	lines := []string{`$env:Path += ";C:\Program Files\Crypto Pro\CSP"`, `$TUC = "` + markTUC + `"`}
	opts := algoDefs[a].cryptcp
	if tls {
		lines = append(lines, `$FQDN = "`+markFQDN+`"`, `$NAME = "TUC-`+date+`"`, `if ($FQDN.Length + 1 + $NAME.Length -le 64) { $NAME = "$FQDN-$NAME" }`)
		opts += " -altname $FQDN " + ekuTLS
	} else {
		lines = append(lines, `$NAME = "$env:USERNAME-TUC-`+date+`"`)
	}
	ca := " -ca $TUC"
	if !chain {
		ca = ` -ca "$TUC/justcert" -silent`
	}
	lines = append(lines, `cryptcp -createcert -rdn "CN=$NAME" -cont "\\.\HDIMAGE\$NAME" -du`+opts+ca)
	return strings.Join(lines, "\n")
}

func psRevoke() string {
	return `$env:Path += ";C:\Program Files\Crypto Pro\CSP"
$TUC = "` + markTUC + `"
if (-not $NAME) { "Укажите NAME сертификата для отзыва" } else {
  ` + psDN + `
  Set-Content -Encoding ascii "$NAME.revoke.txt" revoke
  cryptcp -sign -dn $DN "$NAME.revoke.txt" "$NAME.revoke.p7s"
  if ($LASTEXITCODE -eq 0) { curl.exe --data-binary "@$NAME.revoke.p7s" "$TUC/revoke" }
}`
}

// estEnroll enrolls with openssl and curl over EST into $NAME.key and
// $NAME.crt, the certificate followed, with chain, by the CA chain.
func estEnroll(a algo, tls, chain bool) string {
	lines := []string{"EST=" + markEST}
	ext := ""
	if tls {
		lines = append(lines, "FQDN="+markFQDN, tlsName)
		ext = ` -addext "subjectAltName=DNS:$FQDN" -addext "extendedKeyUsage=serverAuth,clientAuth"`
	} else {
		lines = append(lines, "NAME=${USER:-$(id -un)}-TUC-$(date +%Y%m%d-%H%M%S)")
	}
	lines = append(lines,
		`openssl req -new `+algoDefs[a].openssl+` -nodes -keyout "$NAME.key" -subj "/CN=$NAME"`+ext+` -outform DER |`,
		`  base64 | curl -sSf --data-binary @- -H "Content-Type: application/pkcs10" "$EST/simpleenroll" |`,
		`  base64 -d | openssl pkcs7 -inform DER -print_certs -out "$NAME.crt"`)
	if chain {
		lines[len(lines)-1] += " &&"
		lines = append(lines, `curl -sSf "$EST/cacerts" | base64 -d | openssl pkcs7 -inform DER -print_certs >> "$NAME.crt"`)
	}
	return strings.Join(lines, "\n")
}

func estRevoke() string {
	return "TUC=" + markTUC + `
if [ -z "$NAME" ]; then echo "Укажите NAME сертификата для отзыва"; else
  echo revoke | openssl cms -sign -signer "$NAME.crt" -inkey "$NAME.key" -binary -nodetach -outform DER |
  curl -sSf --data-binary @- "$TUC/revoke"; echo
fi`
}

// opensslImport splits $NAME.pfx into $NAME.crt, the certificate followed
// by the CA chain, and $NAME.key, the key without a password, as the enroll
// with openssl makes them.
func opensslImport() string {
	return "NAME=" + markName + "\nPASS=" + markPass + `
openssl pkcs12 -in "$NAME.pfx" -passin pass:"$PASS" -nokeys -out "$NAME.crt" &&
(umask 077; openssl pkcs12 -in "$NAME.pfx" -passin pass:"$PASS" -nocerts -nodes -out "$NAME.key")`
}

// posixImport installs $FILE.pfx into CryptoPro with a key without a
// password, and its root, which the PFX does not make trusted; NAME is its
// CN, as the CryptoPro revoke command finds the certificate.
func posixImport(path, root string) string {
	return "export PATH=$PATH:" + path + "\nFILE=" + markName + "\nNAME=" + markCN + "\nPASS=" + markPass + `
certmgr -inst -pfx -file "$FILE.pfx" -pin "$PASS" -newpin "" &&
curl -sSf -o "$FILE.root.cer" "` + root + `.crt" && certmgr -inst -store uRoot -file "$FILE.root.cer"`
}

func psImport(root string) string {
	return `$env:Path += ";C:\Program Files\Crypto Pro\CSP"
$FILE = ` + markNamePS + `
$NAME = ` + markCNPS + `
$PASS = ` + markPassPS + `
certmgr -inst -pfx -file "$FILE.pfx" -pin $PASS
if ($LASTEXITCODE -eq 0) { curl.exe -sSf -o "$FILE.root.cer" "` + root + `.crt" }
if ($LASTEXITCODE -eq 0) { certmgr -inst -store uRoot -file "$FILE.root.cer" }`
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
	return "export PATH=$PATH:" + path + `
if [ -z "$NAME" ]; then echo "Укажите NAME сертификата"; else
  ` + posixDN + `
  certmgr -list -store uMy -dn "$DN" -chain | grep "Certificate chain"
fi`
}

func psVerify() string {
	return `$env:Path += ";C:\Program Files\Crypto Pro\CSP"
if (-not $NAME) { "Укажите NAME сертификата" } else {
  ` + psDN + `
  certmgr -list -store uMy -dn $DN -chain | Select-String "Certificate chain"
}`
}

// pfxRevoke revokes with the key of $NAME.pfx, through openssl: of the PFX
// downloaded last on the page, or else of NAME and PASS set in the shell.
func pfxRevoke() string {
	return "TUC=" + markTUC + "\n" + markSetPFX + `
if [ -z "$NAME" ] || [ -z "$PASS" ]; then echo "Укажите NAME — имя файла PFX без .pfx — и PASS — его пароль"; else
  (umask 077; openssl pkcs12 -in "$NAME.pfx" -passin pass:"$PASS" -nodes -out "$NAME.pem") &&
  echo revoke | openssl cms -sign -signer "$NAME.pem" -binary -nodetach -outform DER |
  curl -sSf --data-binary @- "$TUC/revoke"; echo; rm -f "$NAME.pem"
fi`
}

// commands are the enroll, PFX import and revoke commands of the CA at its
// publication address url, with EST at est and the root at root, with keys
// of a: of a PFX, of openssl over EST and of CryptoPro for each OS.
func commands(url, est, root string, a algo) []osCommands {
	type osDef struct {
		id, title, tool string
		enroll          func(tls, chain bool) string
		imp, verify     string
		revoke          string
	}
	posix := func(path string) func(bool, bool) string {
		return func(tls, chain bool) string { return posixEnroll(path, a, tls, chain) }
	}
	ps := func(tls, chain bool) string { return psEnroll(a, tls, chain) }
	openssl := func(tls, chain bool) string { return estEnroll(a, tls, chain) }
	defs := []osDef{
		{"pfx", "PFX", "pfx", nil, "", "", pfxRevoke()},
		{"openssl", "OpenSSL", "openssl", openssl, opensslImport(), estVerify(root, url), estRevoke()},
		{"linux", "Linux", "cryptopro", posix("/opt/cprocsp/bin/amd64"), posixImport("/opt/cprocsp/bin/amd64", root), posixVerify("/opt/cprocsp/bin/amd64"), posixRevoke("/opt/cprocsp/bin/amd64")},
		{"windows", "Windows", "cryptopro", ps, psImport(root), psVerify(), psRevoke()},
		{"macos", "macOS", "cryptopro", posix("/opt/cprocsp/bin"), posixImport("/opt/cprocsp/bin", root), posixVerify("/opt/cprocsp/bin"), posixRevoke("/opt/cprocsp/bin")},
	}
	var out []osCommands
	for _, d := range defs {
		c := osCommands{ID: d.id, Title: d.title, Tool: d.tool, Import: script(d.imp, url, est), Verify: script(d.verify, url, est), Revoke: script(d.revoke, url, est)}
		// openssl puts the chain into $NAME.crt; with CryptoPro it is a choice
		responses := []string{"chain"}
		if d.tool == "cryptopro" {
			responses = append(responses, "cert")
		}
		for _, purpose := range []string{"plain", "tls"} {
			if d.enroll == nil {
				break
			}
			for _, response := range responses {
				c.Enroll = append(c.Enroll, enrollCommand{purpose, response,
					script(d.enroll(purpose == "tls", response == "chain"), url, est)})
			}
		}
		out = append(out, c)
	}
	return out
}
