#!/usr/bin/env bash
# Diagnostic provenance only; never substitutes for existing SHA/guest gates.
set -euo pipefail
binary=$1
out=$2
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sha256sum "$binary" > "$out/binary.sha256"
readelf -W -n "$binary" > "$out/elf-notes.txt"
for section in text rodata; do
    objcopy -O binary --only-section=".$section" "$binary" "$tmp/$section"
    test -s "$tmp/$section"
done
(cd "$tmp" && sha256sum text rodata) > "$out/sections.sha256"
ldd "$binary" > "$out/linked-libraries.txt"
awk '$2 == "=>" && $3 ~ /^\// {print $3} $1 ~ /^\// {print $1}' "$out/linked-libraries.txt" \
    | sort -u | xargs -r sha256sum > "$out/linked-libraries.sha256"
{
    uname -srmo
    printf 'available_cpus='; nproc
    printf 'workspace_fs='; stat -f -c '%T' .
    for pressure in cpu io; do
        printf '\n/proc/pressure/%s\n' "$pressure"
        if test -r "/proc/pressure/$pressure"; then
            cat "/proc/pressure/$pressure"
        else
            printf 'unavailable\n'
        fi
    done
} > "$out/host.txt"
