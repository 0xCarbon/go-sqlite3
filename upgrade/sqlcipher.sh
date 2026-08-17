#!/bin/sh

# Regenerate the bundled SQLCipher amalgamation (sqlite3-binding.c/h) for the
# 0xCarbon fork.
#
# Upstream mattn/go-sqlite3 bundles the plain SQLite amalgamation via
# upgrade/upgrade.sh; this fork bundles SQLCipher instead, so the amalgamation
# must be built from a SQLCipher release tag and then wrapped with the same
# USE_LIBSQLITE3 guard that upgrade/upgrade.go injects upstream. Never hand-edit
# sqlite3-binding.c or sqlite3-binding.h; always regenerate through this script.
#
# Usage: upgrade/sqlcipher.sh [version]    (default: latest v4.* tag)
#
# Requires: git, C compiler, tclsh, OpenSSL headers and libcrypto.
# Tip: run it inside a container when the host lacks the build deps:
#   docker run --rm -v "$PWD:/repo" -w /repo \
#     golang:1.26 bash -c 'apt-get update -qq && \
#       apt-get install -y -qq git build-essential tcl libssl-dev && \
#       upgrade/sqlcipher.sh'

set -e

cd "$(dirname "$0")/.."

if [ -n "$1" ]; then
  # Accept both 4.17.0 and v4.17.0.
  VERSION="v${1#v}"
else
  # --refs: without it the peeled annotated-tag refs (refs/tags/vX.Y.Z^{})
  # match the glob and version-sort above the plain tags.
  VERSION=$(git ls-remote --tags --refs --sort=-v:refname \
    https://github.com/sqlcipher/sqlcipher 'v4.*' |
    head -n 1 | sed 's|.*refs/tags/||')
fi

if [ -z "$VERSION" ]; then
  echo "Error: Could not determine latest SQLCipher version"
  exit 1
fi

CURRENT=$(grep -m1 '#define CIPHER_VERSION_NUMBER' sqlite3-binding.c | \
  grep -o '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*')

if [ "$CURRENT" = "${VERSION#v}" ]; then
  echo "Already up to date: SQLCipher $VERSION"
  exit 0
fi

echo "Bundling SQLCipher $VERSION (currently ${CURRENT:-none})"

# Pinned commits per release tag (the commit the annotated tag points at).
# A tag is a mutable ref: the clone is verified to land exactly on the
# pinned commit, so a retagged release cannot serve different source. When
# bundling a new version, add its pin here first (after cloning the tag,
# git -C <dir> rev-parse HEAD).
#
# Deliberately an explicit case table, not an indirect variable lookup:
# the version string arrives from git ls-remote auto-discovery or argv,
# git permits \$(), and eval-based lookup would execute it.
PIN=""
case "${VERSION#v}" in
4.17.0) PIN=810db22f575ee7cf94ea96a3e91622b5fcece3dc ;;
esac
if [ -z "$PIN" ]; then
  echo "Error: no pinned commit for SQLCipher $VERSION." >&2
  echo "Add a case entry for ${VERSION#v} to upgrade/sqlcipher.sh first" \
    "(clone the tag, then git -C <dir> rev-parse HEAD)." >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

git clone --quiet --branch "$VERSION" --depth 1 \
  https://github.com/sqlcipher/sqlcipher "$WORK/sqlcipher"

CLONED=$(git -C "$WORK/sqlcipher" rev-parse HEAD)
if [ "$CLONED" != "$PIN" ]; then
  echo "Error: cloned $CLONED, expected pinned $PIN" >&2
  exit 1
fi

cd "$WORK/sqlcipher"
./configure --with-tempstore=yes \
  CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown" \
  LDFLAGS="-lcrypto"
make sqlite3.c
cd - >/dev/null

# Wrap the amalgamation the same way upgrade/upgrade.go does upstream: guard
# the whole file behind USE_LIBSQLITE3 so a -tags libsqlite3 build can link
# against the system library, and retarget the amalgamation's self-include.
wrap() {
  {
    printf '#ifndef USE_LIBSQLITE3\n'
    awk '{
      if ($0 == "#include \"sqlite3.h\"") {
        print "#include \"sqlite3-binding.h\""
        print "#ifdef __clang__"
        print "#define assert(condition) ((void)0)"
        print "#endif"
      } else {
        print
      }
    }' "$1"
    printf '#else // USE_LIBSQLITE3\n // If users really want to link against the system sqlite3 we\n// need to make this file a noop.\n #endif'
  } > "$2"
}

wrap "$WORK/sqlcipher/sqlite3.c" sqlite3-binding.c
wrap "$WORK/sqlcipher/sqlite3.h" sqlite3-binding.h

echo "Bundled SQLCipher $VERSION" \
  "($(grep -m1 '#define SQLITE_VERSION ' sqlite3-binding.c))"
sha256sum sqlite3-binding.c sqlite3-binding.h
