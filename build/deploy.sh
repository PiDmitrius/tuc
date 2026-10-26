#!/bin/bash
# Run the shipped deployment and restore procedure on isolated Docker resources.
set -euo pipefail
umask 077
: "${DEPLOY_LOG_DIR:?set an empty result directory}"
here=$(cd "$(dirname "$0")/.." && pwd)
: "${MINIPKI:=$here/minipki}"
out=$(realpath "$DEPLOY_LOG_DIR")
[ -d "$out" ] && [ -z "$(ls -A "$out")" ] || { echo "result directory must be empty" >&2; exit 2; }
run=tuc-deploy-$(openssl rand -hex 6)
work=$(mktemp -d)
export TUC_IMAGE=$run TUC_HOST=ca.example.test TUC_UID=$(id -u) TUC_GID=$(id -g)
export TUC_BASE=https://$TUC_HOST TUC_PUBLISH=http://$TUC_HOST
export TUC_HTTP_BIND=127.0.0.1:0 TUC_HTTPS_BIND=127.0.0.1:0 TUC_TLS_DIR=$work/tls
export TUC_BACKUP_VOLUME=$run-backups TUC_FRONT_NETWORK=$run-front
export TUC_PROXY_CONFIG=Caddyfile.open
old=$run-source new=$run-restored
project=$old
compose() { docker compose -p "$project" -f "$here/docker-compose.yml" "$@"; }
cleanup() {
    status=$?
    trap - EXIT
    set +e
    for p in "$old" "$new"; do
        project=$p
        compose logs --no-color > "$out/$p.log" 2>&1
        compose down --volumes --timeout 10 >/dev/null 2>&1
    done
    if [ -n "${writer:-}" ]; then kill "$writer" 2>/dev/null; wait "$writer" 2>/dev/null; fi
    docker rm -f "$run-client" "$run-outsider" "$run-provider" >/dev/null 2>&1
    docker volume rm "$TUC_BACKUP_VOLUME" >/dev/null 2>&1
    docker network rm "$TUC_FRONT_NETWORK" >/dev/null 2>&1
    docker image rm "$run-tools" "$run-go" "$run" >/dev/null 2>&1
    rm -r "$work"
    exit "$status"
}
trap cleanup EXIT

docker build -q -f "$here/build/Dockerfile" --build-context minipki="$MINIPKI" --target tuc -t "$run" "$here" > "$out/build.log" 2>&1
docker build -q -f "$here/build/Dockerfile" --build-context minipki="$MINIPKI" --target go -t "$run-go" "$here" >> "$out/build.log" 2>&1
docker build -q -f "$here/build/deploy.Dockerfile" --build-arg TOOL_BASE="$run-go" --build-arg TUC_IMAGE="$run" -t "$run-tools" "$here" >> "$out/build.log" 2>&1
docker run --rm -v "$here/deploy:/docs:ro" "$run-tools" systemd-analyze verify /docs/systemd/tuc.service /docs/systemd/tuc-unseal.service > "$out/systemd-verify.log" 2>&1
printf 'systemd unit syntax: ok\n'
mkdir "$work/tls"
docker run --rm --user "$TUC_UID:$TUC_GID" -v "$work/tls:/tls" "$run-tools" sh -ec '
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /tls/transport-ca.key -out /tls/transport-ca.pem -subj /CN=DeploymentTransport -days 2 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /tls/key.pem -out /tls/request.pem -subj /CN=ca.example.test
printf "subjectAltName=DNS:ca.example.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" > /tls/ext
openssl x509 -req -in /tls/request.pem -CA /tls/transport-ca.pem -CAkey /tls/transport-ca.key -CAcreateserial -out /tls/fullchain.pem -days 2 -extfile /tls/ext
rm /tls/transport-ca.key /tls/request.pem /tls/ext /tls/transport-ca.srl' > "$out/tls-generation.log" 2>&1

docker network create "$TUC_FRONT_NETWORK" >/dev/null
docker volume create "$TUC_BACKUP_VOLUME" >/dev/null
for role in client outsider; do
    docker run -d --name "$run-$role" --network "$TUC_FRONT_NETWORK" --user "$TUC_UID:$TUC_GID" --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 --tmpfs "/state:uid=$TUC_UID,gid=$TUC_GID,mode=0700" -v "$work/tls/transport-ca.pem:/trust.pem:ro" -v "$here/build:/tests:ro" "$run-tools" sleep infinity >/dev/null
done
trusted=$(docker inspect "$run-client" | jq -r '.[0].NetworkSettings.Networks[] .IPAddress')
export TUC_TRUSTED_CIDRS=$trusted/32
client() { docker exec "$run-client" python3 /tests/deploy_test.py "$@"; }
prepare() { compose run --rm --user 0 --cap-add CHOWN --cap-add FOWNER --entrypoint sh maintenance /tools/prepare.sh "$TUC_UID" "$TUC_GID"; }
prepare
compose up -d tuc proxy
client wait 503
backend=$(docker inspect "$(compose ps -q tuc)" | jq -r '.[0].NetworkSettings.Networks | to_entries[] | select(.key | endswith("_backend")) | .value.IPAddress')
docker exec "$run-outsider" python3 /tests/deploy_test.py backend-denied "$backend"
# The same secret stays only in the separate provider process across restores.
docker run -d --name "$run-provider" --network none --user "$TUC_UID:$TUC_GID" --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit core=0 --memory 128m --memory-swap 128m --tmpfs "/run:uid=$TUC_UID,gid=$TUC_GID,mode=0700" -v "$here/build/deploy-provider.py:/provider.py:ro" "$run-tools" python3 /provider.py hold >/dev/null
docker run --rm --entrypoint tuc "$run" keygen | docker exec -i "$run-provider" python3 /provider.py put >/dev/null
provider() { docker exec "$run-provider" python3 /provider.py fetch; }
provider | compose exec -T tuc tuc unseal -initialize
client wait 200
client pre
client publication
docker exec "$run-outsider" python3 /tests/deploy_test.py outside-open
client writer > "$out/writer.log" 2>&1 &
writer=$!
client writer-wait
compose run --rm maintenance backup -db /data/tuc.db /backup/snapshot.db | tee "$out/backup.log"
kill -0 "$writer"
docker exec "$run-client" touch /state/writer.stop
wait "$writer"
writer=
compose run --rm --entrypoint cat maintenance /backup/snapshot.db > "$work/export.db"
sha256sum "$work/export.db" > "$out/export.sha256"
# Never overwrite an existing snapshot.
if compose run --rm maintenance backup -db /data/tuc.db /backup/snapshot.db > "$out/refuse-overwrite.log" 2>&1; then echo "backup overwrote a destination" >&2; exit 1; fi
compose restart tuc
client wait 503
if docker exec "$run-tools-missing-provider" true 2>/dev/null | compose exec -T tuc tuc unseal >/dev/null 2>&1; then echo "missing provider accepted" >&2; exit 1; fi
client wait 503
provider | compose exec -T tuc tuc unseal
client wait 200
# Exercise the closed profile from a different real peer address.
export TUC_PROXY_CONFIG=Caddyfile.closed
compose up -d --force-recreate proxy
client wait 200
client publication
ident=$(client public-id)
docker exec "$run-client" cat /state/ocsp.req | docker exec -i "$run-outsider" python3 /tests/deploy_test.py outside-closed "$ident" "$trusted"
compose stop tuc
compose up -d --no-deps --force-recreate tuc
client wait 503
provider | compose exec -T tuc tuc unseal
client wait 200
compose stop tuc proxy

started=$(date +%s%N)
project=$new
prepare
compose run --rm -v "$work/export.db:/input.db:ro" maintenance backup -db /input.db /data/tuc.db | tee "$out/restore.log"
compose up -d tuc proxy
client wait 503
provider | compose exec -T tuc tuc unseal
client wait 200
ready=$(date +%s%N)
client post
finished=$(date +%s%N)
printf '{"snapshot_bytes":%s,"ready_seconds":%.3f,"verified_seconds":%.3f}\n' "$(stat -c %s "$work/export.db")" "$(awk -v a="$started" -v b="$ready" 'BEGIN{print (b-a)/1e9}')" "$(awk -v a="$started" -v b="$finished" 'BEGIN{print (b-a)/1e9}')" > "$out/recovery.json"
if compose run --rm maintenance backup -db /backup/snapshot.db /data/tuc.db > "$out/refuse-restore.log" 2>&1; then echo "restore overwrote a database" >&2; exit 1; fi
compose exec -T tuc tuc status
printf 'deployment and clean restore: ok\n'
