CLI pakai Cobra

## Yang udah
- CLI: `keygen`, `sign`, `verify`, dan `trust add/list/remove`.
- Alur sign dan verify, output JSON, exit code.
- Manage trust store dan overwrite kunci lewat `--force`.
- Kontrak fungsi untuk integrasi dengan core (by toto ya nanti).

## CLI

minimal Go 1.23, do this first: *tidy kalo perlu
```sh
go mod tidy 
go install ./cmd/kelompok17
```

make sure folder bin Go (biasanya `%USERPROFILE%\go\bin` di Windows) masuk PATH

```sh
kelompok17 --help
kelompok17 --version
kelompok17 keygen --help
kelompok17 sign --help
kelompok17 verify --help
kelompok17 trust add --help
kelompok17 trust list --help
kelompok17 trust remove --help
```

Baru bisa help dan version, yg lain harus connect ke toto

## Misal udah integrate, coba ini

Buat `artifact.bin` sebagai berkas yang ingin ditandatangani, contoh buat sbom bisa buat exe ini biar lebih ril wkwk
```
winget install Anchore.Syft
go build -o artifact.exe ./cmd/kelompok17
syft .\artifact.exe -o cyclonedx-json@1.5=sbom.json
```


baru bisa jalanin

```sh
kelompok17 keygen --algorithm ed25519 --out publisher
kelompok17 trust add --key publisher.pub.pem --package demo --store trust.json
kelompok17 trust list --store trust.json
kelompok17 sign --file artifact.bin --package demo --version 1 --key publisher.key.pem --out bundle.json
kelompok17 verify --file artifact.bin --bundle bundle.json --trust-store trust.json --package demo --version 1 --json
kelompok17 sbom-sign --sbom sbom.json --release artifact.bin --package demo --version 1 --key publisher.key.pem --out sbom.bundle.json
kelompok17 sbom-verify --sbom sbom.json --release artifact.bin --bundle sbom.bundle.json --trust-store trust.json --package demo --version 1 --json
kelompok17 trust remove --keyid <keyid> --store trust.json
```

Ganti `<keyid>` sama fingerprint yang didapet pas keygen atau trust add. pilihannya kaya `rsa-pss-sha256`, `ecdsa-p256-sha256`, dan `ed25519`. Pakai `--force` kalau mau timpa key yang udah ada.

notes: sambungin implementasi `contract.Core` ke field `Core` pada `app.Service` di `cmd/kelompok17/main.go`.

alternatif tanpa install (tetap memakai Cobra):
 `go build -o kelompok17.exe ./cmd/kelompok17`terus `.\kelompok17.exe --help` 

atau run langsung dari source:
`go run ./cmd/kelompok17 --help`

`go run ./cmd/kelompok17 sign --help`

## Contoh penggunaan setelah core tersambung

siapin `artifact.bin`, run:

```sh
kelompok17 keygen --algorithm ed25519 --out publisher
kelompok17 trust add --key publisher.pub.pem --package demo --store trust.json
kelompok17 sign --file artifact.bin --package demo --version 1 --key publisher.key.pem --out bundle.json
kelompok17 verify --file artifact.bin --bundle bundle.json --trust-store trust.json --package demo --version 1 --json
```

bisa pake `--algorithm`: `rsa-pss-sha256`, `ecdsa-p256-sha256`, atau `ed25519`. 