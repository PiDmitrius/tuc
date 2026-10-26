# OpenSSL with the GOST engine (target gost-openssl) and its C toolchain (target dev)
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make perl curl ca-certificates git cmake libc6-dev && \
    rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=3.5.9
ARG GOST_ENGINE_REF=af2b7e69e855572202420ffc36bae06ccd70796b

RUN curl -fSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    | tar -xz -C /tmp && \
    cd /tmp/openssl-${OPENSSL_VERSION} && \
    ./config --prefix=/opt/openssl --libdir=lib shared no-tests no-docs && \
    make -j$(nproc) && \
    make install_sw install_ssldirs && \
    rm -rf /tmp/openssl-${OPENSSL_VERSION}

RUN git clone https://github.com/gost-engine/engine.git /tmp/gost-engine && \
    cd /tmp/gost-engine && git checkout -q ${GOST_ENGINE_REF} && git submodule update --init && \
    mkdir build && cd build && \
    cmake -DOPENSSL_ROOT_DIR=/opt/openssl -DOPENSSL_ENGINES_DIR=/opt/openssl/lib/engines-3 .. && \
    make -j$(nproc) && \
    cp bin/gost.so /opt/openssl/lib/engines-3/ && \
    rm -rf /tmp/gost-engine

# The engine only: the GOST provider cannot verify X.509 signatures, and
# loaded together with the engine it breaks GOST signing in the CLI.
RUN printf 'openssl_conf = openssl_init\n\n[openssl_init]\nengines = engine_sect\n\n[engine_sect]\ngost = gost_sect\n\n[gost_sect]\nengine_id = gost\ndynamic_path = /opt/openssl/lib/engines-3/gost.so\ndefault_algorithms = ALL\n' \
    > /opt/openssl/ssl/openssl.cnf

FROM debian:trixie-slim AS gost-openssl
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/openssl /opt/openssl
ENV PATH="/opt/openssl/bin:$PATH" \
    LD_LIBRARY_PATH="/opt/openssl/lib" \
    OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf" \
    MINIPKI_GOST_ENGINE="/opt/openssl/lib/engines-3/gost.so"

FROM gost-openssl AS dev
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# MiniPKI defaults to the checked-out submodule; a named context overrides it.
FROM scratch AS minipki
COPY minipki/include /include
COPY minipki/src /src

FROM builder AS minipki-lib
COPY --from=minipki include /opt/minipki/include
COPY --from=minipki src /tmp/minipki
RUN mkdir -p /opt/minipki/lib /tmp/o && cd /tmp/o && \
    for f in /tmp/minipki/*.c; do \
        gcc -Wall -O2 -fPIC -std=c11 -I/opt/minipki/include -I/opt/openssl/include -c "$f"; \
    done && \
    ar rcs /opt/minipki/lib/libminipki.a /tmp/o/*.o

FROM golang:1.27-trixie AS go
COPY --from=builder /opt/openssl /opt/openssl
COPY --from=minipki-lib /opt/minipki /opt/minipki
ENV PATH="/opt/openssl/bin:$PATH" \
    LD_LIBRARY_PATH="/opt/openssl/lib" \
    OPENSSL_CONF="/opt/openssl/ssl/openssl.cnf" \
    MINIPKI_GOST_ENGINE="/opt/openssl/lib/engines-3/gost.so" \
    CGO_CFLAGS="-I/opt/minipki/include -I/opt/openssl/include" \
    CGO_LDFLAGS="-L/opt/minipki/lib -L/opt/openssl/lib"
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY VERSION ./
COPY cmd cmd
COPY internal internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go build -ldflags "-X main.version=$(cat VERSION)" -o /out/tuc ./cmd/tuc

FROM gost-openssl AS tuc
COPY --from=go /out/tuc /usr/local/bin/tuc
ENTRYPOINT ["tuc"]

# Browser scenarios of the pages (build/ui.sh)
FROM mcr.microsoft.com/playwright/python:v1.64.1-resolute AS ui
RUN pip install --no-cache-dir --break-system-packages playwright==1.64.1

FROM tuc AS release
