#!/bin/sh
# Collect the licence and notice files of every third-party Go module linked
# into phantomfleet (for linux, darwin and windows), plus the Go toolchain's
# own licence, into one directory that ships with binaries and images.
#
#   scripts/third-party-licenses.sh [OUT_DIR]   (default: THIRD_PARTY_LICENSES)
#
# For each module it copies every LICENSE*, LICENCE*, COPYING*, NOTICE*,
# AUTHORS* and PATENTS* file at the module root (modernc.org/libc and
# modernc.org/sqlite carry LICENSE-3RD-PARTY.md files for the musl, Go and
# SQLite code they include). It fails if a module has no licence file.
set -eu

out="${1:-THIRD_PARTY_LICENSES}"
main="$(go list -m)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for os in linux darwin windows; do
	GOOS="$os" CGO_ENABLED=0 go list -deps \
		-f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' . >>"$tmp/modules"
done

rm -rf "$out"
mkdir -p "$out"
sort -u "$tmp/modules" | while read -r modver dir; do
	mod="${modver%@*}"
	[ "$mod" = "$main" ] && continue
	dest="$out/$mod"
	mkdir -p "$dest"
	found=0
	for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/AUTHORS* "$dir"/PATENTS*; do
		[ -f "$f" ] || continue
		cp "$f" "$dest/"
		case "$(basename "$f")" in LICENSE* | LICENCE* | COPYING*) found=1 ;; esac
	done
	if [ "$found" -eq 0 ]; then
		echo "error: no licence file for $modver in $dir" >&2
		exit 1
	fi
	echo "$modver" >>"$out/MODULES.txt"
done

mkdir -p "$out/go"
cp "$(go env GOROOT)/LICENSE" "$out/go/LICENSE"
echo "go $(go env GOVERSION)" >>"$out/MODULES.txt"

cat >"$out/README.md" <<'TXT'
# Third-party licences

phantomfleet binaries and container images include the Go modules listed in
MODULES.txt and the Go standard library. Each directory holds the licence and
notice files of one of them, copied unchanged from its source.
TXT
echo "wrote $(wc -l <"$out/MODULES.txt" | tr -d ' ') licence sets to $out"
