package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kelompok17/internal/contract"
	"kelompok17/internal/trust"
)

// Sign menghitung SHA-256 artifact, membuat manifest canonical, menandatanganinya,
// lalu menulis bundle JSON ke Out. Gagal kalau opsi atau kunci tidak valid, Out sudah
// ada, atau ukurannya lewat batas (manifest 16 KiB, bundle 64 KiB).
func (service Service) Sign(options SignOptions) error {
	if options.File == "" || options.Key == "" || options.Out == "" {
		return fmt.Errorf("missing artifact, key, or output path")
	}
	if !trust.PackagePattern.MatchString(options.Package) || !versionPattern.MatchString(options.Version) || !artifactPattern.MatchString(filepath.Base(options.File)) {
		return fmt.Errorf("invalid package, version, or artifact basename")
	}
	if service.Core == nil {
		return ErrCoreUnavailable
	}
	if samePath(options.File, options.Out) || samePath(options.Key, options.Out) {
		return fmt.Errorf("output overlaps an input")
	}
	keyBytes, err := os.ReadFile(options.Key)
	if err != nil {
		return err
	}
	key, algorithm, keyid, err := service.Core.LoadPrivate(keyBytes)
	if err != nil {
		return fmt.Errorf("invalid private key")
	}
	if !contract.Supported(algorithm) || !trust.KeyIDPattern.MatchString(keyid) {
		return fmt.Errorf("invalid private key profile or fingerprint")
	}
	artifact, err := os.Open(options.File)
	if err != nil {
		return err
	}
	defer artifact.Close()
	size, digest, err := hashArtifact(artifact)
	if err != nil {
		return err
	}
	if size > contract.MaxArtifactSize {
		return fmt.Errorf("artifact exceeds maximum size")
	}
	manifest := contract.Manifest{Schema: contract.ManifestSchema, Package: options.Package, Version: options.Version, Algorithm: algorithm, KeyID: keyid, Artifact: contract.Artifact{Name: filepath.Base(options.File), Size: size, SHA256: digest}}
	message, err := service.Core.CanonicalManifest(manifest)
	if err != nil {
		return err
	}
	if len(message) > contract.MaxManifest {
		return fmt.Errorf("manifest exceeds 16 KiB")
	}
	signature, err := service.Core.Sign(algorithm, key, message)
	if err != nil {
		return fmt.Errorf("signing failed")
	}
	bundle, err := json.Marshal(contract.Bundle{Schema: contract.BundleSchema, ManifestB64: base64.StdEncoding.EncodeToString(message), SignatureB64: base64.StdEncoding.EncodeToString(signature)})
	if err != nil {
		return err
	}
	if len(bundle)+1 > contract.MaxBundle {
		return fmt.Errorf("bundle exceeds 64 KiB")
	}
	return writeNew(options.Out, append(bundle, '\n'), 0644)
}
