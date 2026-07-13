#!/bin/sh
set -eu

version=1.13.14
sha256=f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697
archive_name="sing-box-${version}-linux-amd64.tar.gz"
release_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/${archive_name}"
destination=${1:?"destination path is required"}
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
archive_path="$temporary_directory/$archive_name"

curl --fail --location --silent --show-error "$release_url" --output "$archive_path"
actual_sha256=$(sha256sum "$archive_path")
actual_sha256=${actual_sha256%% *}
if [ "$actual_sha256" != "$sha256" ]; then
  echo "sing-box archive checksum verification failed" >&2
  exit 1
fi
tar --extract --gzip --file "$archive_path" --directory "$temporary_directory"
install -m 0755 "$temporary_directory/sing-box-${version}-linux-amd64/sing-box" "$destination"
