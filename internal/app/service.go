// Package app berisi logika perintah CLI keygen, sign, verify, dan trust
package app

import (
	"errors"
	"regexp"

	"kelompok17/internal/contract"
)

// ErrCoreUnavailable muncul kalau Service.Core belum diisi
var ErrCoreUnavailable = errors.New("core backend has not been connected")
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$`)
var artifactPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Service dipakai CLI untuk menjalankan perintah. Isi Core dengan core.Core{}.
type Service struct{ Core contract.Core }

// KeyInfo berisi keyid dan algoritma kunci hasil Keygen
type KeyInfo struct{ KeyID, Algorithm string }

// KeygenOptions berisi opsi untuk Keygen
//
//   - Algorithm: nama profil, lihat contract.Supported
//   - Out: prefix nama file, hasilnya <Out>.key.pem dan <Out>.pub.pem
//   - Force: timpa file yang sudah ada
type KeygenOptions struct {
	Algorithm, Out string
	Force          bool
}

// SignOptions berisi opsi untuk Sign
//
//   - File: file artifact, nama file-nya dipakai sebagai artifact.name
//   - Package, Version: aturannya sama dengan contract.Manifest
//   - Key: kunci privat PEM
//   - Out: file bundle, tidak boleh sudah ada atau sama dengan file input
type SignOptions struct{ File, Package, Version, Key, Out string }

// TrustAddOptions berisi opsi untuk TrustAdd
//
//   - Key: kunci publik PEM
//   - Package: paket yang boleh ditandatangani kunci ini
//   - Store: file trust store, dibuat kalau belum ada
type TrustAddOptions struct{ Key, Package, Store string }
