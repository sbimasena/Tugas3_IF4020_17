package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"kelompok17/internal/contract"
	"kelompok17/internal/trust"
)

// VerifyOptions berisi opsi untuk Verify
//
//   - File: file artifact
//   - Bundle: file bundle dari Sign
//   - TrustStore: file trust store
//   - Package, Version: harus sama dengan isi manifest
type VerifyOptions struct {
	File, Bundle, TrustStore, Package, Version string
}

// Result adalah hasil Verify. Dengan verify --json, struct ini dicetak sebagai JSON.
// Algorithm, KeyID, Package, dan Version masih nil kalau manifest gagal di-parse.
type Result struct {
	Valid     bool    `json:"valid"`
	Status    string  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`
}

func readLimited(file *os.File, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func hashArtifact(file *os.File) (int64, string, error) {
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	return size, hex.EncodeToString(hash.Sum(nil)), err
}

// Verify mengecek artifact dengan bundle dan trust store. Hasilnya berupa Result dan
// exit code: 0 untuk OK, 2 untuk INPUT_ERROR, dan 1 untuk FORMAT_ERROR,
// UNSUPPORTED_ALGORITHM, KEY_NOT_TRUSTED, INVALID_SIGNATURE, METADATA_MISMATCH,
// atau ARTIFACT_MISMATCH. Signature dicek dulu sebelum metadata dan isi artifact.
func Verify(core contract.Core, options VerifyOptions) (Result, int) {
	result := Result{}
	fail := func(status string, err any) (Result, int) {
		result.Status, result.Message = status, fmt.Sprint(err)
		if status == "INPUT_ERROR" {
			return result, 2
		}
		return result, 1
	}
	if options.File == "" || options.Bundle == "" || options.TrustStore == "" || options.Package == "" || options.Version == "" {
		return fail("INPUT_ERROR", "missing required option")
	}
	if !trust.PackagePattern.MatchString(options.Package) || !versionPattern.MatchString(options.Version) {
		return fail("INPUT_ERROR", "invalid expected package or version")
	}
	if core == nil {
		return fail("INPUT_ERROR", ErrCoreUnavailable)
	}
	artifact, err := os.Open(options.File)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	defer artifact.Close()
	// input dibaca sblm validasi format biar handle error i/o
	size, digest, err := hashArtifact(artifact)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	bundleFile, err := os.Open(options.Bundle)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	defer bundleFile.Close()
	bundleData, err := readLimited(bundleFile, contract.MaxBundle)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	trustData, err := os.ReadFile(options.TrustStore)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	if len(bundleData) > contract.MaxBundle {
		return fail("FORMAT_ERROR", "bundle exceeds 64 KiB")
	}
	var bundle contract.Bundle
	if err = core.StrictJSON(bundleData, &bundle); err != nil {
		return fail("FORMAT_ERROR", err)
	}
	if bundle.Schema != contract.BundleSchema {
		return fail("FORMAT_ERROR", "invalid bundle schema")
	}
	manifestBytes, err := core.DecodeBase64(bundle.ManifestB64)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	signature, err := core.DecodeBase64(bundle.SignatureB64)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	if len(manifestBytes) > contract.MaxManifest {
		return fail("FORMAT_ERROR", "manifest exceeds 16 KiB")
	}
	manifest, err := core.ParseManifest(manifestBytes)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	result.Algorithm, result.KeyID, result.Package, result.Version = &manifest.Algorithm, &manifest.KeyID, &manifest.Package, &manifest.Version
	store, err := trust.Parse(trustData, core)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	if !contract.Supported(manifest.Algorithm) {
		return fail("UNSUPPORTED_ALGORITHM", "unsupported algorithm")
	}
	for _, entry := range store.Keys {
		if entry.KeyID != manifest.KeyID {
			continue
		}
		allowed := false
		for _, name := range entry.Packages {
			if name == options.Package {
				allowed = true
			}
		}
		if entry.Algorithm != manifest.Algorithm || !allowed {
			return fail("KEY_NOT_TRUSTED", "key is not authorized for expected package and algorithm")
		}
		key, _, _, err := core.LoadPublic([]byte(entry.PublicKeyPEM))
		if err != nil {
			return fail("FORMAT_ERROR", "invalid trusted key")
		}
		length := 64
		if manifest.Algorithm == "rsa-pss-sha256" {
			length = 384
		}
		if len(signature) != length || !core.Verify(manifest.Algorithm, key, manifestBytes, signature) {
			return fail("INVALID_SIGNATURE", "invalid signature")
		}
		if manifest.Package != options.Package || manifest.Version != options.Version || manifest.Artifact.Name != filepath.Base(options.File) {
			return fail("METADATA_MISMATCH", "package, version, or artifact name differs")
		}
		if manifest.Artifact.Size != size || manifest.Artifact.SHA256 != digest {
			return fail("ARTIFACT_MISMATCH", "artifact size or digest differs")
		}
		result.Valid, result.Status, result.Message = true, "OK", "release verified"
		return result, 0
	}
	return fail("KEY_NOT_TRUSTED", "keyid not present in trust store")
}
