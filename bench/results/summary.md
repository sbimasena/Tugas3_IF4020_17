# Benchmark summary

Warm-up 5, measured runs 30 (keygen: 1 warm-up, 5 runs). Percentile: nearest-rank, value at position ceil(p*n).

| metric | algorithm | size | n | median (ms) | P95 (ms) |
|---|---|---|---|---|---|
| hash | - | 1KiB | 30 | 0.031 | 0.042 |
| hash | - | 1MiB | 30 | 1.423 | 2.078 |
| hash | - | 100MiB | 30 | 138.437 | 144.908 |
| keygen | rsa-pss-sha256 | - | 5 | 352.637 | 883.842 |
| sign-manifest | rsa-pss-sha256 | - | 30 | 4.700 | 5.975 |
| verify-manifest | rsa-pss-sha256 | - | 30 | 0.263 | 0.521 |
| e2e-sign | rsa-pss-sha256 | 1KiB | 30 | 42.828 | 56.346 |
| e2e-verify | rsa-pss-sha256 | 1KiB | 30 | 16.999 | 18.643 |
| e2e-sign | rsa-pss-sha256 | 1MiB | 30 | 43.797 | 61.262 |
| e2e-verify | rsa-pss-sha256 | 1MiB | 30 | 18.556 | 21.140 |
| e2e-sign | rsa-pss-sha256 | 100MiB | 30 | 181.345 | 191.597 |
| e2e-verify | rsa-pss-sha256 | 100MiB | 30 | 156.308 | 162.301 |
| keygen | ecdsa-p256-sha256 | - | 5 | 0.044 | 0.055 |
| sign-manifest | ecdsa-p256-sha256 | - | 30 | 0.062 | 0.098 |
| verify-manifest | ecdsa-p256-sha256 | - | 30 | 0.133 | 0.254 |
| e2e-sign | ecdsa-p256-sha256 | 1KiB | 30 | 37.285 | 38.869 |
| e2e-verify | ecdsa-p256-sha256 | 1KiB | 30 | 17.111 | 19.478 |
| e2e-sign | ecdsa-p256-sha256 | 1MiB | 30 | 38.780 | 39.909 |
| e2e-verify | ecdsa-p256-sha256 | 1MiB | 30 | 18.417 | 21.155 |
| e2e-sign | ecdsa-p256-sha256 | 100MiB | 30 | 176.121 | 184.778 |
| e2e-verify | ecdsa-p256-sha256 | 100MiB | 30 | 156.456 | 164.690 |
| keygen | ed25519 | - | 5 | 0.038 | 0.065 |
| sign-manifest | ed25519 | - | 30 | 0.038 | 0.075 |
| verify-manifest | ed25519 | - | 30 | 0.085 | 0.094 |
| e2e-sign | ed25519 | 1KiB | 30 | 38.980 | 43.112 |
| e2e-verify | ed25519 | 1KiB | 30 | 17.264 | 19.356 |
| e2e-sign | ed25519 | 1MiB | 30 | 41.713 | 47.603 |
| e2e-verify | ed25519 | 1MiB | 30 | 20.688 | 27.230 |
| e2e-sign | ed25519 | 100MiB | 30 | 180.306 | 199.465 |
| e2e-verify | ed25519 | 100MiB | 30 | 162.264 | 189.978 |

## Sizes (bytes)

| algorithm | public key DER (SPKI) | private key DER (PKCS#8) | signature | bundle (1KiB artifact) |
|---|---|---|---|---|
| rsa-pss-sha256 | 422 | 1793 | 384 | 997 |
| ecdsa-p256-sha256 | 91 | 138 | 64 | 577 |
| ed25519 | 44 | 48 | 64 | 565 |
