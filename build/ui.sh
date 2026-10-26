#!/bin/bash
# ui.sh: the browser scenarios of the pages (build/ui_test.py) against a
# fresh service, in Chromium of the Playwright image.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${MINIPKI:=$here/../minipki}"
net=tuc-ui-$$
cleanup() { docker rm -f "$net-tuc" >/dev/null 2>&1; docker network rm "$net" >/dev/null 2>&1; }
trap cleanup EXIT
docker build -q -f "$here/Dockerfile" --build-context minipki="$MINIPKI" --target tuc -t tuc "$here/.." >/dev/null
docker build -q -f "$here/Dockerfile" --build-context minipki="$MINIPKI" --target ui -t tuc-ui "$here/.." >/dev/null
docker network create "$net" >/dev/null
docker run -d --name "$net-tuc" --network "$net" tuc \
    serve -base "http://$net-tuc:8080" -db /tmp/tuc.db >/dev/null
sleep 1
docker run --rm --init --network "$net" -v "$here/ui_test.py:/ui_test.py:ro" tuc-ui \
    python3 /ui_test.py "http://$net-tuc:8080" sealed
docker exec "$net-tuc" tuc keygen | docker exec -i "$net-tuc" tuc unseal -initialize
docker exec "$net-tuc" tuc status | grep -qx ready
docker run --rm --init --network "$net" -v "$here/ui_test.py:/ui_test.py:ro" tuc-ui \
    xvfb-run -a python3 /ui_test.py "http://$net-tuc:8080"
