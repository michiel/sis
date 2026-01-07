#!/usr/bin/env bash
set -euo pipefail

OUT="out"
MANIFEST="${OUT}/dataset.jsonl"
mkdir -p "${OUT}"
rm -f "${MANIFEST}"

emit() {
  local label="$1"
  local name="$2"
  printf '{"label":"%s","ir":"%s","org":"%s"}\n' \
    "$label" "${OUT}/ir/${label}/${name}.json" "${OUT}/org/${label}/${name}.json" >> "${MANIFEST}"
}

for label in benign malicious; do
  for ir in "${OUT}/ir/${label}"/*.json; do
    [ -e "$ir" ] || continue
    name="$(basename "$ir" .json)"
    emit "$label" "$name"
  done
done
