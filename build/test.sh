#!/bin/sh
# test.sh: go vet and go test of TUC with the pinned MiniPKI source
set -eu
here=$(cd "$(dirname "$0")" && pwd)
: "${MINIPKI:=$here/../minipki}"
docker build -q -f "$here/Dockerfile" --build-context minipki="$MINIPKI" --target go -t tuc-go "$here/.." >/dev/null
docker run --rm -v "$here/..:/src:ro" -v tuc-gomod:/go/pkg/mod -e GOFLAGS=-mod=mod -e GOCACHE=/tmp/gocache tuc-go \
    sh -c 'cp -r /src /tmp/w && cd /tmp/w && go vet ./... && go test -count=1 ./...'
