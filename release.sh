#!/bin/sh

set -eux

curdir="$(readlink -f "$0")"
curdir="$(dirname "$curdir")"
cd "$curdir"
pkg="$(omake -s echo-pkg)"
mtmpf="$(mktemp -d)"
trap "rm -rf \"${mtmpf}\"" EXIT

if which gtar >/dev/null 2>&1 ; then
    tar=gtar
else
    tar=tar
fi

stash="$(git stash create)"
git archive --format=tar ${stash:-HEAD} | ( cd "$mtmpf" ; tar -xf- )

if which gfind >/dev/null 2>&1 ; then
    find=gfind
else
    find=find
fi

cd "$mtmpf"
rm -f .git*
$find . -type f ! -executable ! -perm 644 -exec chmod 644 {} \+
$find . -type f -executable ! -perm 755 -exec chmod 755 {} \+
$find . -type d ! -perm 755 -exec chmod 755 {} \+

$tar --transform "s|^.|${pkg}|" --format=ustar --numeric-owner -cf- . | \
    gzip -9 > "${curdir}/${pkg}.tar.gz"
