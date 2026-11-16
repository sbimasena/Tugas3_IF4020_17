# kelompok17

CLI untuk menandatangani dan memverifikasi software release (Tugas 3 IF4020 Kriptografi). Program menghitung SHA-256 artefak, menandatangani manifest canonical yang berisi paket, versi, algoritma, keyid, dan digest artefak, lalu menyimpannya sebagai bundle JSON. Saat verifikasi, kunci publik hanya diterima jika terdaftar di trust store dan diizinkan untuk paket tersebut. Algoritma yang didukung adalah `rsa-pss-sha256`, `ecdsa-p256-sha256`, dan `ed25519`.

Dokumentasi API: (https://sbimasena.github.io/Tugas3_IF4020_17/)

## Tech stack dan dependensi

| Komponen | Versi | Kegunaan |
|---|---|---|
| Go | 1.23 (sesuai `go.mod`) | bahasa dan seluruh operasi kriptografi (standard library) |
| Cobra https://github.com/spf13/cobra | v1.10.1 | parsing command CLI |
| `golang:1.23` | image build | tahap build di Dockerfile |
| `gcr.io/distroless/static-debian12` | base image | image akhir |
| GitHub Actions dan GHCR | | CI/CD dan registry image |
| [gomarkdoc](https://github.com/princjef/gomarkdoc) v1.1.0 dan GitHub Pages (Jekyll, tema Cayman) | | dokumentasi API |
| OpenSSL | 3.0.17 | hanya untuk tes interoperabilitas |
| Python | 3.11.2 | skenario test |



## Versi, tag, dan image

| Versi program (`--version`) | Tag repo | Image | Isi |
|---|---|---|---|
| `0.1.0` | belum ada tag, dibangun lewat `workflow_dispatch` dari commit `551f3f2` (11 November 2026) | `ghcr.io/sbimasena/kelompok17@sha256:082ea0321c599b22b3a9fa739b349528397ece0fcd03be36781e878982eff59a` | keygen, sign, verify, trust. Dipakai `pipeline.yml` dan `scenarios.yml` |
| [isi versi berikutnya] | [isi tag] | [isi digest] | ditambah sbom-sign dan sbom-verify |


## Run

### Dari image GHCR

Program dijalankan sebagai container di runner Linux amd64.

```sh
docker pull ghcr.io/sbimasena/kelompok17@sha256:082ea0321c599b22b3a9fa739b349528397ece0fcd03be36781e878982eff59a
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/sbimasena/kelompok17@sha256:082ea0321c599b22b3a9fa739b349528397ece0fcd03be36781e878982eff59a --help
```

### Di CI

`pipeline.yml` menjalankan image di atas dengan langkah berikut:

1. Kunci privat diambil dari GitHub Secrets dan ditulis ke `$RUNNER_TEMP` dengan `umask 077`. Berkasnya dihapus dengan `trap` saat langkah selesai.
2. `sign` dijalankan di container dengan `--network none` dan `--user` sesuai uid runner dan kunci dipasang read-only.
3. `verify --json` dijalankan dengan trust store di `ci/trust.json`
4. Langkah deploy simulasi hanya jalan jika verify berhasil

`scenarios.yml` menjalankan skenario gagal C02 sampai C04 lalu memeriksa status, exit code, dan tidak adanya penanda deploy.

### Build image sendiri

```sh
docker build -t kelompok17:local --build-arg VERSION=dev .
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" kelompok17:local --help
```

### Di luar CI dengan go build

```sh
go build -o kelompok17 ./cmd/kelompok17      # Windows: -o kelompok17.exe
./kelompok17 --help
```


## Contoh semua subcommand

```sh
kelompok17 keygen --algorithm ed25519 --out publisher             # publisher.key.pem (0600) dan publisher.pub.pem
kelompok17 trust add --key publisher.pub.pem --package demo --store trust.json
kelompok17 trust list --store trust.json
kelompok17 sign --file artifact.bin --package demo --version 1.0.0 --key publisher.key.pem --out bundle.json
kelompok17 verify --file artifact.bin --bundle bundle.json --trust-store trust.json --package demo --version 1.0.0 --json
kelompok17 sbom-sign --sbom sbom.json --release artifact.bin --package demo --version 1.0.0 --key publisher.key.pem --out sbom.bundle.json
kelompok17 sbom-verify --sbom sbom.json --release artifact.bin --bundle sbom.bundle.json --trust-store trust.json --package demo --version 1.0.0 --json
kelompok17 trust remove --keyid <keyid> --store trust.json
```



| Status verify | Exit | Kondisi |
|---|---|---|
| `OK` | 0 | semua pemeriksaan lolos |
| `INPUT_ERROR` | 2 | opsi kosong atau tidak valid, berkas tidak dapat dibaca |
| `FORMAT_ERROR` | 1 | bundle, manifest, atau trust store tidak valid atau tidak canonical |
| `UNSUPPORTED_ALGORITHM` | 1 | algoritma di manifest tidak didukung |
| `KEY_NOT_TRUSTED` | 1 | keyid tidak ada di trust store atau tidak diizinkan untuk paket dan algoritma |
| `INVALID_SIGNATURE` | 1 | panjang signature salah atau signature tidak cocok |
| `METADATA_MISMATCH` | 1 | paket, versi, atau nama berkas berbeda |
| `ARTIFACT_MISMATCH` | 1 | ukuran atau SHA-256 artefak berbeda |




## Format

**Manifest** (data yang ditandatangani) selalu canonical, yaitu JSON satu baris tanpa spasi dengan urutan field tetap, maksimal 16 KiB.

```json
{"schema":"minisign-manifest/v1","package":"demo","version":"1","algorithm":"ed25519","keyid":"<64 hex>","artifact":{"name":"text.txt","size":19,"sha256":"<64 hex>"}}
```

| Field | Aturan |
|---|---|
| `package` | `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `version` | `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` |
| `artifact.name` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| `keyid`, `artifact.sha256` | `^[0-9a-f]{64}$` |
| `artifact.size` | 0 sampai 9007199254740991 |

**Bundle** berisi tiga field, maksimal 64 KiB. Urutan field dan whitespace bebas.

```json
{"schema":"minisign-bundle/v1","manifest_b64":"<Base64 manifest>","signature_b64":"<Base64 signature>"}
```

**Trust store** berisi daftar kunci dan paket yang boleh ditandatangani kunci tersebut.

```json
{"schema":"minisign-trust/v1","keys":[{"keyid":"<64 hex>","algorithm":"ed25519","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...","packages":["demo"]}]}
```

Semua JSON di-parse secara strict: duplicate key, field tambahan atau hilang, null, dan tipe yang salah ditolak. Base64 harus canonical.

## Pemetaan library

Semua profil memakai Go standard library (Go 1.23).

| Profil | Kunci | Signature | API Go |
|---|---|---|---|
| `rsa-pss-sha256` | RSA 3072 bit, e = 65537 | 384 byte | [`rsa.GenerateKey`](https://pkg.go.dev/crypto/rsa#GenerateKey), [`rsa.SignPSS`](https://pkg.go.dev/crypto/rsa#SignPSS), [`rsa.VerifyPSS`](https://pkg.go.dev/crypto/rsa#VerifyPSS) dengan SHA-256, MGF1 SHA-256, salt 32 byte |
| `ecdsa-p256-sha256` | P-256 | 64 byte (r‖s) | [`ecdsa.GenerateKey`](https://pkg.go.dev/crypto/ecdsa#GenerateKey), [`ecdsa.SignASN1`](https://pkg.go.dev/crypto/ecdsa#SignASN1), [`ecdsa.Verify`](https://pkg.go.dev/crypto/ecdsa#Verify), DER diubah ke r‖s |
| `ed25519` | Ed25519 | 64 byte | [`ed25519.GenerateKey`](https://pkg.go.dev/crypto/ed25519#GenerateKey), [`ed25519.Sign`](https://pkg.go.dev/crypto/ed25519#Sign), [`ed25519.Verify`](https://pkg.go.dev/crypto/ed25519#Verify) (PureEdDSA) |
| Kunci | PKCS#8 dan SPKI PEM | | [`crypto/x509`](https://pkg.go.dev/crypto/x509), [`encoding/pem`](https://pkg.go.dev/encoding/pem) |
| Base64 | | | [`base64.StdEncoding`](https://pkg.go.dev/encoding/base64) dengan cek encode ulang |
| JSON | | | [`json.Decoder.Token`](https://pkg.go.dev/encoding/json#Decoder.Token) untuk parser strict |



## SBOM (bonus)

`sbom-sign` menandatangani SBOM berformat JSON dan mengikatnya ke artefak release lewat SHA-256. `sbom-verify` memeriksa keduanya.

| Opsi | Dipakai oleh | Keterangan |
|---|---|---|
| `--sbom` | sbom-sign, sbom-verify | path SBOM JSON |
| `--release` | sbom-sign, sbom-verify | path artefak release yang diikat |
| `--package` | sbom-sign, sbom-verify | nama paket (sign) atau paket yang diharapkan (verify) |
| `--version` | sbom-sign, sbom-verify | versi release (sign) atau versi yang diharapkan (verify) |
| `--key` | sbom-sign | kunci privat PKCS#8 PEM |
| `--out` | sbom-sign | path bundle SBOM, tidak boleh sudah ada |
| `--bundle` | sbom-verify | path bundle SBOM |
| `--trust-store` | sbom-verify | path trust store |
| `--json` | sbom-verify | cetak hasil sebagai JSON ke stdout |

Manifest SBOM (schema `minisign-sbom-manifest/v1`) dikemas di bundle biasa (`minisign-bundle/v1`). Urutan field tetap dan tanpa spasi.

| Field | Tipe | Aturan |
|---|---|---|
| `schema` | string | `minisign-sbom-manifest/v1` |
| `package` | string | `^[a-z0-9][a-z0-9._-]{0,63}$` |
| `version` | string | `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` |
| `algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, atau `ed25519` |
| `keyid` | string | 64 hex huruf kecil |
| `sbom_name` | string | nama berkas SBOM, harus sama saat verify |
| `sbom_size` | integer | ukuran SBOM dalam byte |
| `sbom_sha256` | string | SHA-256 SBOM, 64 hex huruf kecil |
| `release_sha256` | string | SHA-256 artefak release, 64 hex huruf kecil |

| Status sbom-verify | Exit | Kondisi |
|---|---|---|
| `OK` | 0 | signature valid, SBOM dan release cocok |
| `INPUT_ERROR` | 2 | opsi kosong atau tidak valid, berkas tidak dapat dibaca |
| `FORMAT_ERROR` | 1 | SBOM bukan JSON valid, bundle atau manifest SBOM tidak valid atau tidak canonical, nama SBOM berbeda, trust store tidak valid |
| `KEY_NOT_TRUSTED` | 1 | keyid tidak ada di trust store atau tidak diizinkan untuk paket dan algoritma |
| `INVALID_SIGNATURE` | 1 | signature tidak cocok |
| `SBOM_MISMATCH` | 1 | ukuran atau SHA-256 SBOM berbeda |
| `METADATA_MISMATCH` | 1 | paket atau versi berbeda |
| `RELEASE_MISMATCH` | 1 | SHA-256 artefak release berbeda |

## Testing

| Test | Command | Output |
|---|---|---|
| Tes unit, Example, U14, interop OpenSSL | `go test -count=1 -v ./...` | `test/results/go-test-v.txt` |
| Skenario U01 sampai U14, CLI, trust store | `python test/scenarios/run_app.py` | `test/results/app-<waktu>/` |
| SBOM S01 sampai S05 (butuh Docker dan Python 3) | `bash test/scenarios/run_sbom.sh` | `test/results/sbom/log.txt` |
| Benchmark | `go build -o bench/k17 ./cmd/kelompok17` lalu `go run ./bench` | `bench/results/` |


## Dokumentasi API

Dokumentasi modul `internal/` dibuat dari komentar godoc dengan gomarkdoc v1.1.0, lalu di-hosting di GitHub Pages dari folder `docs/` (Jekyll, tema Cayman). Contoh penggunaan di dokumentasi berasal dari fungsi `Example` di `example_test.go` dan ikut dijalankan oleh `go test`.

Link: https://sbimasena.github.io/Tugas3_IF4020_17/

Membuat ulang setelah kode atau komentar berubah:

```sh
go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0
gomarkdoc --output "docs/api/{{.Dir}}.md" ./internal/app ./internal/trust ./internal/contract ./internal/core ./internal/profile ./internal/keys ./internal/manifest ./internal/strictjson ./internal/b64
```

Tambahkan `--check` untuk memastikan dokumentasi masih sesuai dengan kode