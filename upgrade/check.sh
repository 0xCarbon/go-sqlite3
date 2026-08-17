#!/bin/sh

# 0xCarbon fork: this repo bundles the SQLCipher amalgamation (see
# upgrade/sqlcipher.sh), so the upgrade check compares against SQLCipher
# releases, not plain SQLite from sqlite.org.

set -e

cd "$(dirname "$0")/.."

CURRENT_VERSION=$(grep '#define CIPHER_VERSION_NUMBER' sqlite3-binding.c | grep -o '[0-9]*\.[0-9]*\.[0-9]*')

if [ -z "$CURRENT_VERSION" ]; then
  echo "Error: Could not extract current SQLCipher version from sqlite3-binding.c"
  exit 1
fi

LATEST_VERSION=$(git ls-remote --tags --sort=-v:refname \
  https://github.com/sqlcipher/sqlcipher 'v4.*' \
  | head -n 1 \
  | sed 's|.*refs/tags/||;s|^v||')

if [ -z "$LATEST_VERSION" ]; then
  echo "Error: Could not extract latest SQLCipher version from github.com/sqlcipher/sqlcipher"
  exit 1
fi

echo "Current SQLCipher version: $CURRENT_VERSION (SQLite $(grep -m1 '#define SQLITE_VERSION ' sqlite3-binding.c | grep -o '[0-9]*\.[0-9]*\.[0-9]*'))"
echo "Latest SQLCipher version:  $LATEST_VERSION"

if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
  echo "Already up to date."
  exit 0
fi

echo "Upgrade available: $CURRENT_VERSION -> $LATEST_VERSION"
echo "Run upgrade/sqlcipher.sh to upgrade."
exit 1
