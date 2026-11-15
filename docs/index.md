# kelompok17 API

Library internal Go yang dipakai CLI `kelompok17` untuk membuat kunci, menandatangani, memverifikasi, membaca kunci PEM, dan mengolah format data (manifest, bundle, trust store)

## Alur modul

```
CLI (cmd/kelompok17)
  -> app.Service, app.Verify, trust
    -> contract.Core (interface)
      -> core.Core
        -> profile, keys, manifest, strictjson, b64
```

## Paket

| Paket | Isi |
|---|---|
| [app](api/internal/app.md) | Logika perintah CLI keygen, sign, verify, trust, sbom-sign, sbom-verify |
| [trust](api/internal/trust.md) | Parse, validasi, simpan trust store |
| [contract](api/internal/contract.md) | Konstanta schema dan batas ukuran, tipe JSON, interface `Core` |
| [core](api/internal/core.md) | Implementasi `contract.Core` |
| [profile](api/internal/profile.md) | Profil tanda tangan RSA-PSS, ECDSA, Ed25519 |
| [keys](api/internal/keys.md) | Baca/tulis kunci PEM dan keyid |
| [manifest](api/internal/manifest.md) | Validasi, bentuk canonical, parse manifest |
| [strictjson](api/internal/strictjson.md) | Parser JSON ketat |
| [b64](api/internal/b64.md) | Base64 standar canonical |

## Profil

| Profil | Kunci | Panjang signature | API Go |
|---|---|---|---|
| `rsa-pss-sha256` | RSA 3072 bit, e = 65537 | 384 byte | `rsa.SignPSS` / `rsa.VerifyPSS`, salt 32 byte |
| `ecdsa-p256-sha256` | P-256 | 64 byte (r‖s) | `ecdsa.SignASN1` / `ecdsa.Verify` |
| `ed25519` | Ed25519 | 64 byte | `ed25519.Sign` / `ed25519.Verify` |

## Catatan

- Message tidak di-hash dua kali, RSA-PSS dan ECDSA meng-hash message dengan SHA-256 sekali lalu menandatangani hasilnya, sedangkan Ed25519 langsung menerima message
- Signature ECDSA disimpan dalam format r‖s (r dan s masing-masing 32 byte), bukan DER, konversinya pakai `profile.DERToRaw` dan `profile.RawToDER`
- Manifest harus canonical (JSON satu baris tanpa spasi, urutan field tetap) dan `manifest.Parse` menolak manifest yang tidak sama persis dengan hasil `manifest.Canonical`
- Base64 juga harus canonical
- `Verify` tidak pernah mengembalikan error, kunci beda profil, panjang signature salah, atau signature tidak valid hasilnya `false`
- `Sign` mengembalikan `profile.ErrKey` kalau kuncinya tidak cocok
- Ukuran manifest maksimal 16 KiB (`contract.MaxManifest`) dan bundle maksimal 64 KiB (`contract.MaxBundle`)
- keyid adalah SHA-256 dari DER SPKI kunci publik, ditulis dalam 64 karakter hex huruf kecil

## Cara update dokumentasi

Halaman di folder `api/` dibuat otomatis dari komentar di kode Go memakai [gomarkdoc](https://github.com/princjef/gomarkdoc) v1.1.0. Kalau komentar atau kode berubah, jalankan perintah ini dari root repo:

{% raw %}
```sh
go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0
gomarkdoc --output "docs/api/{{.Dir}}.md" ./internal/app ./internal/trust ./internal/contract ./internal/core ./internal/profile ./internal/keys ./internal/manifest ./internal/strictjson ./internal/b64
```
{% endraw %}

Untuk mengecek apakah dokumentasi masih sesuai dengan kode, tambahkan `--check` pada perintah kedua. Contoh kode di dokumentasi juga ikut dites lewat `go test ./internal/... -run Example -v`.
