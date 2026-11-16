#!/usr/bin/env bash

set -u
OUT="${1:-test/results/sbom}"
rm -rf "$OUT" && mkdir -p "$OUT/work"
W="$(cd "$OUT/work" && pwd)"
IMG=kelompok17:sbom-test

docker build -q -t "$IMG" . > /dev/null || exit 1
K() { docker run --rm --network none --user "$(id -u):$(id -g)" -v "$W:/work" "$IMG" "$@"; echo "exit=$?"; }
flip() { python3 -c "import sys;p,i=sys.argv[1],int(sys.argv[2]);b=bytearray(open(p,'rb').read());b[i]^=int(sys.argv[3]);open(p,'wb').write(bytes(b))" "$@"; }


cid=$(docker create "$IMG") && docker cp "$cid:/kelompok17" "$W/kelompok17" > /dev/null && docker rm "$cid" > /dev/null
docker run --rm --user "$(id -u):$(id -g)" -v "$W:/w" anchore/syft:v1.18.1 scan file:/w/kelompok17 -o cyclonedx-json@1.5=/w/sbom.json -q

V="--release kelompok17 --bundle sbom.bundle.json --trust-store trust.json --package demo --json"
{
  echo "# image: $(docker image inspect -f '{{.Id}}' "$IMG"), commit: $(git rev-parse --short HEAD)"
  K keygen --algorithm ed25519 --out publisher
  K trust add --key publisher.pub.pem --package demo --store trust.json
  echo "## S01 normal"
  K sbom-sign --sbom sbom.json --release kelompok17 --package demo --version 1.0.0 --key publisher.key.pem --out sbom.bundle.json
  K sbom-verify --sbom sbom.json $V --version 1.0.0
  echo "## S02 satu bit sbom.json dibalik (JSON tetap valid)"
  cp "$W/sbom.json" "$W/sbom.bak"
  flip "$W/sbom.json" "$(grep -bo '"bomFormat"' "$W/sbom.json" | head -1 | cut -d: -f1 | awk '{print $1+2}')" 32
  K sbom-verify --sbom sbom.json $V --version 1.0.0
  mv "$W/sbom.bak" "$W/sbom.json"
  echo "## S03 satu bit artefak release dibalik"
  cp "$W/kelompok17" "$W/release.bak"
  flip "$W/kelompok17" 100 1
  K sbom-verify --sbom sbom.json $V --version 1.0.0
  mv "$W/release.bak" "$W/kelompok17"
  echo "## S04 versi yang diharapkan berbeda"
  K sbom-verify --sbom sbom.json $V --version 2.0.0
  echo "## S05 bundle SBOM dipakai di verify biasa"
  K verify --file kelompok17 --bundle sbom.bundle.json --trust-store trust.json --package demo --version 1.0.0 --json
} > "$OUT/log.txt" 2>&1
rm -f "$W/publisher.key.pem" "$W/kelompok17"
cat "$OUT/log.txt"
