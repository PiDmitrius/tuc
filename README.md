# TUC

A test certification authority for GOST R 34.10-2012, RSA and ECDSA
certificates with long-lived roots, subordinate CAs, HTTP CRLs and OCSP, enrolled into with
`cryptcp -createcert` of CryptoPro CSP.

Each CA has its own key algorithm, a subordinate CA by default its parent CA's: GOST R 34.10-2012 256 and
512-bit, RSA 2048, 3072 and 4096, ECDSA P-256, P-384 and P-521. What a CA signs is signed over
GOST R 34.11-2012 of its key size, SHA-256 for RSA, and SHA-256, SHA-384 or SHA-512 for ECDSA by the
curve. A hierarchy is at most 8 CAs deep. Serial numbers are random. A CA
certifies a key once: a key already certified by that CA is refused, including
when its certificate is revoked or expired. Leaf key usage follows the
algorithm-specific user or TLS template. Each CA has issuance settings for what it issues, subordinate CAs included: the CRL distribution
point and the OCSP URL, both on by default, and for leaves the start in days from the issue, which may be
negative for backdated or expired certificates, and the days, 0 and 365 by default, cut to the CA's own
validity. CMC responses omit CA certificates issued by an algorithm different
from their own; their issuer URLs remain in AIA.

CAs, the certificates they issued and revocations are stored in SQLite; CA
keys are encrypted with the service secret. A CA is addressed by the SHA-1
of its certificate: `http://tuc.example/<id>`.

CA hierarchy uses subordinate CA and parent CA; the root CA is level 1.

## Web pages

`/` creates a root CA with test data already filled in (the default name includes
its level and a timestamp marked UTC) and opens its admin
page, `/<id>#token=<admin token>`: whoever has that address administers the
CA only. Each CA has independent admin and issue tokens. The fragment after
`#` is not sent in HTTP requests;
the page submits the token when making administrative requests. The copied
management link uses that CA's own token; hierarchy navigation carries no
token. The admin page lists and searches the certificates the CA issued, revokes them,
creates subordinate CAs, makes issuance open or by link, revokes a
subordinate CA under its issuer and disables the CA: a disabled CA answers
503 to issuance, CRL, OCSP, its certificate and time-stamps, as if it were
down, until enabled again. `/<id>` shows the CA and
how to get a certificate: a PFX made by the CA, or a key of one's own with
OpenSSL or CryptoPro; how to import a PFX, check a certificate's chain and
revocation, and revoke it; `/<id>#issue=<issue token>`, the issue link, opens it
for a CA that issues by link.

The Access section can replace either link independently. Replacement increments
that role's generation in SQLite and invalidates the previous token immediately.
Save the new admin link when prompted. Replacing an issue link does not close
public issuance.
The parent CA revokes a subordinate CA's certificate from its certificate list; a subordinate CA
can revoke itself with its own admin link.

CA creation accepts `from` (days from creation, default 0, range -36500..36500)
and `days` (1..36500). The requested period is intersected with the parent CA's;
a disjoint period is refused. A negative start can create a CA under an expired
parent CA when the periods overlap. The issue row shows the configured leaf period
and gives the owner a shortcut to its settings. Public operations and CA
management are separate groups.

Names are limited to 8 attributes of up to 64 characters of their type.
PKCS#10 signatures are checked for all eight algorithms, including GOST through
MiniPKI. Invalid signatures are refused before issuance. CSR keys must be RSA
2048/3072/4096, P-256/384/521 or GOST 256/512; other keys are refused.

Leaf extensions come from the CA's user or TLS template, not from the request.
The request supplies its Subject and public key. Either serverAuth or clientAuth
in the requested EKU selects TLS; the CA adds both and rebuilds SAN from the
requested DNS names. Without either, the user template has no EKU or SAN.
Requested keyUsage, service EKUs (OCSP signing, time-stamping, anyExtendedKeyUsage),
other EKUs, non-DNS SAN entries and all other extensions are ignored, including
their requested criticality. Key usage, key identifiers, AIA and any CRL/OCSP
URLs come from the CA's template and settings.

Repeated SAN/EKU extensions or extension-request attributes, malformed SAN/EKU,
and empty EKU are refused. TLS requires at least one valid DNS name: ASCII
labels of 1–63 letters, digits or hyphens, with no leading/trailing hyphen,
up to 253 characters overall; no wildcards or trailing dot. DNS names are
lowercased and duplicates removed. Without TLS, SAN names are discarded.
These rules apply to cryptcp and both EST enrollment endpoints. PFX selects
the same templates with its `tls` and `fqdn` fields. DNS names are syntax-checked, not ownership-validated.

## Public endpoints

| Request | Does |
|---|---|
| `GET /<id>.crt`, `GET /<id>.crl` | CA certificate, CRL (published hourly and at once on a revocation, made when asked for with thisUpdate when it became due, valid for a week), as CA issuers and, when the CA issues with it, CRL distribution point of what the CA issues |
| `POST /<id>/ocsp`, `GET /<id>/ocsp/<request>` | OCSP (RFC 6960) of what the CA issued, the OCSP URL of their AIA when the CA issues with it: good, revoked or, for anything else, unknown, with CertIDs of any hash OpenSSL has, GOST R 34.11-2012 included; signed by the OCSP responder of the CA, a certificate it issues at the first request for 90 days with OCSPSigning and id-pkix-ocsp-nocheck, thisUpdate now, valid for a week, nonce repeated; a signature on the request is ignored |
| `GET /<id>/cert/<sha1>.crt` | a certificate the CA issued |
| `POST <enroll>/certfnsh.asp` | issues a leaf certificate, as `cryptcp -createcert -ca <enroll>` posts |
| `GET /.well-known/est/<id>/cacerts` | EST (RFC 7030): the CA and the CAs above it |
| `POST /.well-known/est/<id>/simpleenroll`, `/simplereenroll` | EST: issues a leaf certificate; a CA that issues by link takes its issue token as the HTTP Basic password |
| `POST <enroll>/pfx` | `{"name", "algo", "tls", "fqdn", "password"}`: a key of any algorithm, by default the CA's, generated and not retained by TUC, with a leaf certificate from the user or TLS template, in a password-protected PKCS#12 with the chain; GOST uses Kuznyechik and Streebog, other algorithms use AES-256 and SHA-256 |
| `POST /<id>/tsp` | time-stamp (RFC 3161) under the policy anyPolicy, signed by a time-stamping certificate the CA issues at the first request, of its algorithm, with its CRL and OCSP URLs |
| `POST /<id>/revoke` | revokes the certificate that signed the word `revoke` |

JSON POST requests require `Content-Type: application/json` (parameters such as `charset=utf-8` are allowed). This applies to PFX issuance and page management requests, including JSON revocation.

CRL responses use their CRL number as `ETag`; revalidate with `If-None-Match`.

The holder of a certificate revokes it by posting a signature of the word
`revoke` made with it, as `cryptcp -sign` writes it (DER, PEM or base64, with
the certificate in it):

```sh
echo revoke > revoke
DN=$(printf '%s' "$NAME" | sed '/[,+"<>;=#]/ {s/"/""/g;s/^/"/;s/$/"/;}')
DN="CN=$DN"
cryptcp -sign -dn "$DN" -pin "" revoke revoke.p7s
curl --data-binary @revoke.p7s "$TUC/revoke"
```

## Enrolling

The page of a CA shows the commands for Linux, Windows and macOS. On Linux:

```sh
export PATH=$PATH:/opt/cprocsp/bin/amd64
TUC=<enroll>
NAME=${USER:-$(id -un)}-TUC-$(date +%Y%m%d-%H%M%S)
cryptcp -createcert -rdn "CN=$NAME" -cont "\\\\.\\HDIMAGE\\$NAME" -du -pin "" -ca "$TUC"
```

At `<enroll>` TUC returns a signed CMC response containing the certificate
and CA chain, subject to the mixed-algorithm rule above. At
`<enroll>/justcert` it returns only the issued certificate; the page command
uses `-silent` and requires the root to be trusted beforehand. Confirm trust
only for the intended root. For TLS, add
`-altname <host> -eku 1.3.6.1.5.5.7.3.1 -eku 1.3.6.1.5.5.7.3.2`.

## Running

For installation, permissions and TLS, follow [Deployment and recovery](DEPLOY.md).
The example below assumes the state and socket directories have been prepared
for the service user.

The service starts **sealed** without `-secret`, and does not read stdin:

```sh
tuc serve -base http://tuc.example:8080 -listen :8080 -db /var/lib/tuc/tuc.db
```

The local socket defaults to `/run/tuc/unseal.sock` (`-unseal-socket` changes
it). Its directory must belong to the service user with mode 0700; the socket
is 0600 and checks the peer uid. Run the client as that same user. On Linux,
commands disable core files and process dump access before handling a secret;
failure to apply this protection stops the command.

Generate the 32-byte secret once with `tuc keygen` and keep it in a recoverable,
protected source outside the instance. Do not generate a new one on restart.
From another terminal, as the service user:

```sh
tuc status
tuc unseal -initialize
```

`unseal` reads the base64url secret from stdin, hiding input when it is a
terminal. `-socket` selects another socket. `-initialize` is required only for
a fresh, empty database; it never replaces an existing verifier. On each
restart, use `tuc unseal` with the same secret. Status prints `sealed` or
`ready`; a successful status command reports connectivity, not readiness.

For automatic delivery, use the same command in a supervised pipeline (Bash):

```sh
set -o pipefail
secret-provider | tuc unseal
```

`secret-provider` stands for the deployment's own command: it retrieves the
secret by the instance's identity, writes only it to stdout and exits. Keep
secret values out of arguments, environment variables, tracing and logs.
The delivery succeeds only if both commands succeed. The supervisor bounds
provider execution, retries failures and stops after success. If the source
is unavailable, TUC stays sealed; manual delivery remains available. A source
failure after unsealing does not interrupt a ready instance. A client timeout
can leave the outcome uncertain: check `tuc status` before retrying.

The database contains a versioned encrypted verifier, derived with a separate
HKDF purpose and bound to a random database identifier. A wrong secret does
not change it. A database with data but without a verifier is rejected. An empty database
requires explicit initialization. Deleting the last CA does not reset the
secret. Repeating the correct delivery is harmless; another secret gets a
conflict while the service stays ready. There is no live reseal or secret
rotation command; stopping the process removes its unlocked state.

| Endpoint while sealed | Result |
|---|---|
| `/livez` | 200, process is serving HTTP |
| `/readyz` | 503 (`sealed`); 200 after unsealing |
| Main and CA pages | 503 with an operator message, no forms or management data |
| Public CA/issued certificates and EST `cacerts` | Available without private keys or usage updates |
| CRL | Saved, correctly signed, unexpired CRL only; an invalidated, missing or damaged one gives 503 |
| OCSP, TSP, creation, issuance, PFX, revocation and administration | 503 before token checks or database changes |

Sealed refusals have `Cache-Control: no-store`, `Retry-After: 5` and
`X-TUC-State: sealed`. Existing disabled-CA restrictions still apply to public
certificates and CRLs. A saved CRL reduces restart disruption but cannot
replace unsealing indefinitely; its original expiry still applies. Do not use
readiness failure to restart an otherwise live sealed service.

See [Deployment and recovery](DEPLOY.md) for Docker/systemd, TLS, access profiles,
monitoring, lifecycle, consistent SQLite backups and clean restoration.

Systemd credentials can feed stdin as a deployment adapter, but they are
runtime files, not a guarantee of process-memory-only storage. The same applies
to ordinary Docker secrets and tmpfs: account for swap. A strict deployment
must disable swap/hibernation and memory snapshots across TUC **and the delivery
path**, prevent provider dumps and restrict process inspection. The process
protections do not defend against root or compromise of a running instance.
Input buffers and rejected derived keys are cleared; Go/cgo cannot guarantee
that every internal copy has been erased.

`-secret <file>` and `-secret -` are explicit startup modes, with the same
verification. A fresh database also needs `serve -initialize`.
Without `-secret`, the service starts sealed and does not read stdin.
File-based startup keeps the master secret on the instance's disk.

`-base` is the external address for pages and issuance. `-publish` sets the
publication address embedded in certificates (AIA, CDP and OCSP); it defaults
to `-base`. Existing certificates retain their embedded addresses. Use `tuc backup -db tuc.db <new-file>` for a
consistent SQLite snapshot (including WAL); retain the external secret separately. After restore, start
sealed and deliver the original secret; existing keys and management links
from that backup remain usable. Restoring an older backup restores its link
generations too; replace affected links before reopening access. CA keys are decrypted only to sign.

Each request to a CA marks it used, to the hour. `tuc usage -db tuc.db` lists the root CAs by the last
use of the CAs under them, the least used first, with how many CAs and certificates they hold; the
operator deletes a CA no longer used, with everything under it, by `tuc delete -db tuc.db <id>`;
a subordinate CA is revoked under its parent CA first.
The GOST engine is named by
`MINIPKI_GOST_ENGINE`.

## Building and testing

Initialize the pinned MiniPKI submodule with `git submodule update --init --recursive`
(or clone with `--recurse-submodules`). `VERSION` sets the version compiled into
`tuc version`. From the repository root:

```sh
version=v$(cat VERSION)
docker build -t "pidmitrius/tuc:$version" .
docker run --rm "pidmitrius/tuc:$version" version
docker tag "pidmitrius/tuc:$version" pidmitrius/tuc:latest
docker push "pidmitrius/tuc:$version"
docker push pidmitrius/tuc:latest
```

Images are published manually. For the first deployment from an image tag, follow
[Docker deployment](DEPLOY.md#docker), including the external network, volumes
and their permissions. The service starts sealed; initialize it as described there.

`build/Dockerfile` is also the root `Dockerfile`; it builds OpenSSL with the
GOST engine, MiniPKI and TUC. The checks use the submodule by default;
`MINIPKI` overrides its source directory.

```sh
build/test.sh
build/ui.sh
build/minipki-test.sh
```

`build/ui.sh` runs the scenarios of the pages in Chromium.

`build/minipki-test.sh` runs the MiniPKI tests against the GOST engine.

Compatibility was tested with CryptoPro CSP 5.0.
