#!/bin/sh
# minipki-test.sh: builds MiniPKI against OpenSSL with the GOST engine and runs its tests
set -e
here=$(cd "$(dirname "$0")" && pwd)
: "${MINIPKI:=$here/../minipki}"
[ -d "$MINIPKI/src" ] || { echo "initialize the minipki submodule or set MINIPKI" >&2; exit 2; }
docker build -q --target dev -t tuc-dev "$(dirname "$0")" >/dev/null
docker run --rm -v "$(cd "$MINIPKI" && pwd):/src:ro" tuc-dev sh -ec '
mkdir /tmp/o && cd /tmp/o
for f in /src/src/*.c; do gcc -Wall -O2 -fPIC -Werror -std=c11 -I/src/include -I/opt/openssl/include -c $f; done
gcc -Wall -std=c11 -I/src/include -I/opt/openssl/include -c /src/test/test_minipki.c
gcc -o test_minipki *.o -L/opt/openssl/lib -lcrypto
cd /src/build && /tmp/o/test_minipki'
