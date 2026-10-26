# Deployment and recovery

TUC may issue certificates trusted by working systems. Fix the externally
reachable addresses **before the first issuance**: `-base` supplies page and
enrollment links; `-publish` supplies AIA, CDP and OCSP. Preserve both addresses, routing and secret on
restart, update and restore. Changing configuration does not rewrite URLs in
certificates already issued.

The examples use `-base https://tuc.example` for pages, EST, issuance and
management, and `-publish http://tuc.example` for AIA caIssuers, CDP and OCSP
addresses embedded in certificates and for the commands on the page. Without
`-publish`, they use `-base`. Plain HTTP publication lets certificate retrieval
and revocation checks run without first validating the proxy's TLS certificate;
certificates, CRLs and OCSP responses carry their own signatures. `cryptcp -ca`
validates TLS only against the CryptoPro root store, which lacks common web
roots, so its enrollment and the revocation commands use HTTP too; issue tokens
in their URLs travel unencrypted. TSP accepts requests on both addresses.
The proxy serves only certificates, CRLs, OCSP, TSP, `cryptcp` enrollment and
revocation over HTTP and redirects all other HTTP requests to HTTPS. Existing certificates retain their embedded
addresses when either setting changes. Use your permanent DNS
name and provision a valid TLS certificate independently of the TUC instance
being recovered. Distribute the TLS issuer's trust as required by your clients.
Test their AIA/CDP/OCSP access at the chosen URLs before issuing working
certificates.

## Access boundary

The [open HTTPS proxy](deploy/Caddyfile.open) forwards all TUC endpoints. Public CA
creation and open issuance are intentional; CA tokens still protect their
respective roles. In the [closed HTTPS proxy](deploy/Caddyfile.closed), only trusted
peer addresses can reach pages, creation, issuance, PFX, EST, revocation,
administration, time-stamps and health endpoints.

The closed HTTPS profile's outside allowlist is:

| Method | Path | Purpose |
|---|---|---|
| GET/HEAD | `/<id>.crt` | CA certificates and AIA chains |
| GET/HEAD | `/<id>.crl` | Revocation lists |
| POST | `/<id>/ocsp` | OCSP requests |
| GET | `/<id>/ocsp/<request>` | OCSP requests encoded in the URL |

HTTP additionally exposes `POST /<id>/tsp` to all callers in both profiles, and
`cryptcp` enrollment (`POST /<id>[/<issue>][/justcert]/certfnsh.asp`) and
revocation (`POST /<id>[/<issue>]/revoke`) to all callers in the open profile
and to trusted peers in the closed one.
All other HTTP paths redirect to HTTPS, where the selected profile applies.

Issued-certificate downloads and EST cacerts stay inside this default boundary;
add a deliberate allowlist rule if an outside consumer requires them. Network
closure and a CA's `closed` issuance setting are separate: set `closed` on each
CA that must require an issue token, including for trusted-network callers.

As the service uid, `tuc link [-socket path] <id>` replaces and prints a lost admin link through the local socket; the service must be unsealed and no secret is passed to the command.

Each CA has its own admin and issue links. A parent CA's admin link cannot manage
its subordinate CAs; save each new CA's admin link. Replace either link in Access when
needed and save the new admin link immediately. Old tokens stop working;
replacing an issue link does not restrict open issuance. Link generations are
part of the database: restoring an older backup also restores its generations
and can reactivate the links that were valid at that backup. After such a
restore, replace both links for any affected CA before reopening access.

Only the proxy publishes ports. Do not publish TUC's 8080 or its Unix socket.
Check the actual peer address reaching the proxy on your network. The sample
uses `remote_ip`, not a client-supplied forwarded header. An additional proxy or
NAT needs a separately verified source-identity policy. TUC has no load limits
in this version; connection, request-size and rate limits belong on the proxy.

## Docker

Use Docker Engine with Compose and a Linux runtime. Clone the chosen TUC tag
with its submodule (`git clone --recurse-submodules --branch <tag> <repository>`).
For an existing checkout run `git submodule update --init --recursive`.
Build and publish manually from the repository root:

```sh
version=v$(cat VERSION)
docker build -t "pidmitrius/tuc:$version" .
docker run --rm "pidmitrius/tuc:$version" version
docker tag "pidmitrius/tuc:$version" pidmitrius/tuc:latest
docker push "pidmitrius/tuc:$version"
docker push pidmitrius/tuc:latest
```

Set deployment configuration; these variables contain **no master secret**:

```sh
export COMPOSE_PROJECT_NAME=tuc
export TUC_TAG=v1.0.0 TUC_HOST=tuc.example
export TUC_BASE=https://tuc.example TUC_PUBLISH=http://tuc.example
export TUC_UID=10001 TUC_GID=10001
export TUC_TLS_DIR=/srv/tuc/tls TUC_HTTPS_BIND=0.0.0.0:443 TUC_HTTP_BIND=0.0.0.0:80
export TUC_FRONT_NETWORK=tuc-edge TUC_BACKUP_VOLUME=tuc-backups
export TUC_PROXY_CONFIG=Caddyfile.closed
export TUC_TRUSTED_CIDRS='192.0.2.0/24'
dc() { docker compose "$@"; }
```

Replace the documentation network with your actual trusted source networks.
For open access use `TUC_PROXY_CONFIG=Caddyfile.open`. Record resolved image IDs
and configuration; use immutable image references for a reproducible release.
The proxy example is tested with `caddy:2.11.4-alpine` and the
`NET_BIND_SERVICE` capability set in Compose.

Provision `fullchain.pem` and `key.pem` in `TUC_TLS_DIR`, readable by `TUC_UID`,
with a private directory and mode 0600 on the key. The mount is read-only.
Certificate renewal must update those files and recreate/reload the proxy;
verify TLS again afterwards. The example does not obtain certificates for you.

On a fresh deployment:

```sh
docker network create "$TUC_FRONT_NETWORK"
docker volume create "$TUC_BACKUP_VOLUME"
dc run --rm --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint sh maintenance \
  /tools/prepare.sh "$TUC_UID" "$TUC_GID"
dc pull tuc proxy
dc up -d tuc proxy
```

`prepare.sh` initializes empty named volumes as private directories. It refuses to
change ownership of nonempty volumes belonging to another user. TUC runs as the
configured uid with a read-only root filesystem, private runtime tmpfs, no
capabilities and no-new-privileges. Only `/var/lib/tuc` is persistent. The Unix
socket stays inside the container; clients executed there use the same uid.
The backup volume is separate and never contains the master secret.

The sample budgets TUC at 512 MiB and two CPUs (`TUC_MEMORY`, `TUC_CPUS` override
these values), with the memory-plus-swap budget equal to the memory budget. Size these budgets
for your workload. Container settings do not replace a host-wide policy for
swap, hibernation, dumps or memory snapshots throughout the secret-delivery path.

Generate the secret once and retain it in a recoverable protected source
outside the instance and its database backups. Generate it with
`docker run --rm pidmitrius/tuc:$TUC_TAG keygen` and save the output directly
to that protected source. Never generate another secret
as a restart procedure. Initialize an empty database manually:

```sh
dc exec tuc tuc unseal -initialize
dc exec -T tuc tuc status
```

The first command reads a line from the terminal with echo disabled. After
restarts, use `dc exec tuc tuc unseal` without `-initialize`.
For a supervised external provider, the same delivery channel is used:

```bash
set -o pipefail
secret-provider | dc exec -T tuc tuc unseal
```

Here `secret-provider` is your own command, authenticated to your chosen source,
writing only the secret to stdout. Supervise it with a deadline and retry delay;
stop retries after confirmation and a successful provider exit. Keep values
out of arguments, environment, files, shell tracing and logs. Without a valid
delivery TUC stays sealed; a pipeline failure or timeout can occur after
unsealing, so check status before assuming whether delivery completed. Stop the
provider supervisor when intentionally stopping TUC; arrange fresh delivery for
every subsequent start. Do not put a failing provider in a startup hook that
restarts the otherwise live HTTP service.

From a trusted monitoring source, using your normal TLS trust bundle:

```sh
curl --cacert /path/to/tls-issuer.pem -fsS "https://$TUC_HOST/livez"
curl --cacert /path/to/tls-issuer.pem -fsS "https://$TUC_HOST/readyz"
```

Liveness is 200 while HTTP works; readiness is 503 while sealed and 200 after
unsealing. Alert on prolonged sealed state; do not restart merely because it is
sealed. Saved valid CRLs can remain available then, but expire normally.

## Stop, restart, logs and update

```sh
dc logs --tail=100 tuc proxy
dc stop tuc
# Start and deliver the same secret again:
dc up -d tuc
```

The sample rotates local Docker logs (three files of 10 MiB per service).
TUC logs transitions and requests, redacting issue-token path segments. Treat
administrative/enrollment URLs as capabilities. The supplied proxy files do not
enable access logs; review error logs too before exporting them. Do not enable
request-body, authorization-header or full capability-URL logging.

Before updating, make and verify a backup and record the old image reference.
Select the tested new version in `TUC_TAG`, keeping hostname, volumes, uid and
secret, then run `dc pull tuc` and `dc up -d --no-deps --force-recreate tuc`. Unseal and verify
readiness, old administration/enrollment links, chain validation and revocation.
Update/recreate the proxy separately. `dc stop` preserves data; **do not use
`down --volumes`** on a deployment whose data must survive.

Keep the preceding binary/configuration for rollback. Do not silently restore
an older database after issuance or revocation has resumed: that would discard
those operations. Binary rollback against current data also needs schema and
cryptographic compatibility checks.

## Consistent backup and clean restore

`tuc backup -db <database> <new-file>` uses SQLite's backup API, not a copy
of a live `.db` file. It reads committed data including WAL, checks the completed
snapshot, closes it into a single database file and publishes it without
replacing an existing destination. The snapshot has mode 0600. It prints SHA-256;
the operation deadline is 300 seconds. The same command imports a completed archive into a clean instance.

```sh
SNAPSHOT=tuc-$(date -u +%Y.%m.%d-%H.%M.%S-UTC).db
dc run --rm maintenance backup -db /data/tuc.db "/backup/$SNAPSHOT"
# Export only after a successful backup; do not overwrite an existing archive:
umask 077
set -o noclobber
dc run --rm --entrypoint cat maintenance "/backup/$SNAPSHOT" > "$SNAPSHOT"
sha256sum "$SNAPSHOT"
```

Copy completed archives to your protected independent backup storage and retain
the checksum, release/configuration and permanent hostname. Keep the recoverable
master secret separately, with separately controlled access. A snapshot excludes
later issuance and revocation: agree the acceptable loss interval (RPO), backup
frequency and retention before working issuance. Test access to both;
either alone is insufficient for full recovery. Never copy just the live `.db`
while ignoring its WAL, nor include runtime socket files as persistent state.

Before restore, compare the archive SHA-256 with the independently retained
checksum and stop on a mismatch.

For recovery, stop the old provider supervisor and old TUC/proxy before handing
the public address to a replacement. Use a **new** Compose project/data volume,
the same TLS hostname/configuration and the original secret. For example:

```sh
export COMPOSE_PROJECT_NAME=tuc-restored
# Keep the other deployment variables; ARCHIVE is the completed local copy.
ARCHIVE=$(realpath "$SNAPSHOT")
dc run --rm --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint sh maintenance \
  /tools/prepare.sh "$TUC_UID" "$TUC_GID"
dc run --rm -v "$ARCHIVE:/input.db:ro" maintenance \
  backup -db /input.db /data/tuc.db
dc up -d tuc proxy
# Deliver the ORIGINAL secret, without -initialize:
secret-provider | dc exec -T tuc tuc unseal
```

The target must not contain `tuc.db`, its WAL or SHM; restore refuses an occupied
target. Do not attach a second writer to a running instance's data volume. Keep
the old data until recovery is verified. Check old CA certificate fingerprints,
chain and revoked certificates, administration/issue capabilities, new issuance
and signing by existing OCSP/TSP services. Measure time from clean-target
preparation through readiness and through these checks; the result is specific
to database size, provider availability, hardware and routing, not a universal RTO.

## systemd on a compatible Linux host

Use a host compatible with the runtime image's architecture and shared-library
ABI. The Docker qualification below verifies unit syntax, not a native systemd
boot. Validate service behavior on the actual target before working issuance.

As administrator, create a dedicated `tuc` system account. Extract
`/usr/local/bin/tuc` and `/opt/openssl` from the release image into a new directory
`/opt/tuc/releases/<release>/bin/tuc` and `.../openssl`; make them root-owned and
not writable by the service user. Point `/opt/tuc/current` at that release.
Install [deploy/tuc](deploy/tuc) as `/usr/local/bin/tuc` (0755) and the two
[unit files](deploy/systemd) in `/etc/systemd/system`. Record an existing release
link before replacing it; do not overwrite unrelated paths.

Create `/etc/tuc/tuc.env` containing `TUC_BASE=https://tuc.example`
and `TUC_PUBLISH=http://tuc.example` on separate lines.
The unit binds the backend to `127.0.0.1:8080`; run the HTTP/HTTPS proxy with the same
provided Caddyfile, `TUC_HOST` and `TUC_UPSTREAM=127.0.0.1:8080`. Configure its
certificate permissions and service lifecycle separately. Restrict other local
accounts and do not expose backend port 8080 through a firewall or port forward.

```sh
systemd-analyze verify /etc/systemd/system/tuc.service /etc/systemd/system/tuc-unseal.service
systemctl daemon-reload
systemctl enable --now tuc.service
# In a terminal, using an authorized switch to the service account:
runuser -u tuc -- /usr/local/bin/tuc unseal -initialize
```

`StateDirectory` and `RuntimeDirectory` establish private persistent/runtime
paths; no secret is put into an EnvironmentFile. For automatic delivery install
`/usr/local/libexec/tuc-deliver` as a root-owned executable, using this pattern:

```bash
#!/bin/bash
set -euo pipefail
/usr/local/libexec/secret-provider | /usr/local/bin/tuc unseal
```

Give that provider the instance's approved source identity. Enable
`tuc-unseal.service` only for automatic mode; its install dependency belongs to
`tuc.service`, and its retry deadline/delay are separate from HTTP. Use
`systemctl enable --now tuc-unseal.service` after initial bootstrap.
For manual mode leave it disabled; switching back uses
`systemctl disable --now tuc-unseal.service`. Check units and logs on the target.

Use `systemctl stop/restart tuc.service` and `journalctl -u tuc.service -u
tuc-unseal.service`; apply journal retention/access policy and the same secret
logging exclusions as Docker. Update the release link only after recording it,
backing up, stopping delivery/TUC, and verifying the new runtime. Restart and
unseal, retaining the same base and secret.

Run `tuc backup -db /var/lib/tuc/tuc.db <new-backup>` as `tuc`; restore with
`tuc backup -db <archive> /var/lib/tuc/tuc.db` to an empty service-owned state
location while the service is stopped. The snapshot/secret separation and
post-restore checks are the same as Docker. Core-dump protection inside TUC
cannot protect an arbitrary provider or a compromised host; configure dump,
swap, hibernation and snapshot policy for the whole delivery path.

## Reproduce the Docker qualification

The host requires Docker Compose, Bash, `openssl` and `jq`.

```sh
mkdir /path/to/new-empty-results
DEPLOY_LOG_DIR=/path/to/new-empty-results build/deploy.sh
```

The check uses isolated names, unprivileged service users, a private backend,
a fixture TLS issuer with certificate verification enabled, and a memory-only
external provider. It exercises both access profiles, manual/operator delivery,
provider failure and later automatic delivery, concurrent issuance during live
backup, archive export, restart/recreation, clean restore and old capabilities,
CA/service keys, mixed ECDSA/GOST chains and revocation. It checks unit syntax
inside the tool container. It saves logs/checksums/recovery timings and removes
its containers, networks, volumes and temporary TLS keys. No public DNS, deployed
instance or native host service is changed.
