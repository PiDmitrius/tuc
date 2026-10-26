#!/bin/sh
set -eu
uid=$1 gid=$2
for path in /data /backup; do
    if [ "$(stat -c %u:%g "$path")" != "$uid:$gid" ]; then
        entries=$(ls -A "$path")
        [ -z "$entries" ] || { echo "refusing to change ownership of nonempty $path" >&2; exit 1; }
        chown "$uid:$gid" "$path"
    fi
    chmod 0700 "$path"
done
