package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kelompok17/internal/contract"
	"kelompok17/internal/trust"
)

const sbomManifestSchema = "minisign-sbom-manifest/v1"

type SBOMManifest struct {
	Schema        string `json:"schema"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyid"`
	SBOMName      string `json:"sbom_name"`
	SBOMSize      int64  `json:"sbom_size"`
	SBOMSHA256    string `json:"sbom_sha256"`
	ReleaseSHA256 string `json:"release_sha256"`
}

type SBOMSignOptions struct{ SBOM, Release, Package, Version, Key, Out string }
type SBOMVerifyOptions struct{ SBOM, Release, Bundle, TrustStore, Package, Version string }

func (service Service) SignSBOM(o SBOMSignOptions) error {
	if o.SBOM == "" || o.Release == "" || o.Key == "" || o.Out == "" || o.Package == "" || o.Version == "" {
		return fmt.Errorf("missing required option")
	}
	if !trust.PackagePattern.MatchString(o.Package) || !versionPattern.MatchString(o.Version) {
		return fmt.Errorf("invalid package or version")
	}
	if service.Core == nil {
		return ErrCoreUnavailable
	}
	if samePath(o.SBOM, o.Out) || samePath(o.Release, o.Out) || samePath(o.Key, o.Out) {
		return fmt.Errorf("output overlaps an input")
	}
	sbom, err := os.ReadFile(o.SBOM)
	if err != nil {
		return err
	}
	if len(sbom) == 0 || int64(len(sbom)) > contract.MaxArtifactSize || !json.Valid(sbom) {
		return fmt.Errorf("SBOM must be valid JSON within artifact size limit")
	}
	release, err := os.Open(o.Release)
	if err != nil {
		return err
	}
	defer release.Close()
	_, releaseHash, err := hashArtifact(release)
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(o.Key)
	if err != nil {
		return err
	}
	key, alg, keyid, err := service.Core.LoadPrivate(keyBytes)
	if err != nil || !contract.Supported(alg) || !trust.KeyIDPattern.MatchString(keyid) {
		return fmt.Errorf("invalid private key profile or fingerprint")
	}
	sum := sha256.Sum256(sbom)
	m := SBOMManifest{sbomManifestSchema, o.Package, o.Version, alg, keyid, filepath.Base(o.SBOM), int64(len(sbom)), hex.EncodeToString(sum[:]), releaseHash}
	message, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(message) > contract.MaxManifest {
		return fmt.Errorf("manifest exceeds 16 KiB")
	}
	sig, err := service.Core.Sign(alg, key, message)
	if err != nil {
		return fmt.Errorf("signing failed")
	}
	bundle, err := json.Marshal(contract.Bundle{Schema: contract.BundleSchema, ManifestB64: base64.StdEncoding.EncodeToString(message), SignatureB64: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return err
	}
	if len(bundle)+1 > contract.MaxBundle {
		return fmt.Errorf("bundle exceeds 64 KiB")
	}
	return writeNew(o.Out, append(bundle, '\n'), 0644)
}

func VerifySBOM(core contract.Core, o SBOMVerifyOptions) (Result, int) {
	r := Result{}
	fail := func(status string, e any) (Result, int) {
		r.Status, r.Message = status, fmt.Sprint(e)
		if status == "INPUT_ERROR" {
			return r, 2
		}
		return r, 1
	}
	if o.SBOM == "" || o.Release == "" || o.Bundle == "" || o.TrustStore == "" || o.Package == "" || o.Version == "" {
		return fail("INPUT_ERROR", "missing required option")
	}
	if !trust.PackagePattern.MatchString(o.Package) || !versionPattern.MatchString(o.Version) {
		return fail("INPUT_ERROR", "invalid expected package or version")
	}
	if core == nil {
		return fail("INPUT_ERROR", ErrCoreUnavailable)
	}
	sbom, err := os.ReadFile(o.SBOM)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	if len(sbom) == 0 || int64(len(sbom)) > contract.MaxArtifactSize || !json.Valid(sbom) {
		return fail("FORMAT_ERROR", "SBOM must be valid JSON within artifact size limit")
	}
	release, err := os.Open(o.Release)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	defer release.Close()
	_, releaseHash, err := hashArtifact(release)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	b, err := os.ReadFile(o.Bundle)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	trustData, err := os.ReadFile(o.TrustStore)
	if err != nil {
		return fail("INPUT_ERROR", err)
	}
	if len(b) > contract.MaxBundle {
		return fail("FORMAT_ERROR", "bundle exceeds 64 KiB")
	}
	var bundle contract.Bundle
	if err = core.StrictJSON(b, &bundle); err != nil {
		return fail("FORMAT_ERROR", err)
	}
	if bundle.Schema != contract.BundleSchema {
		return fail("FORMAT_ERROR", "invalid bundle schema")
	}
	msg, err := core.DecodeBase64(bundle.ManifestB64)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	sig, err := core.DecodeBase64(bundle.SignatureB64)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	if len(msg) > contract.MaxManifest {
		return fail("FORMAT_ERROR", "manifest exceeds 16 KiB")
	}
	var m SBOMManifest
	if err = core.StrictJSON(msg, &m); err != nil {
		return fail("FORMAT_ERROR", err)
	}
	canonical, _ := json.Marshal(m)
	if string(canonical) != string(msg) || m.Schema != sbomManifestSchema || !trust.PackagePattern.MatchString(m.Package) || !versionPattern.MatchString(m.Version) || !contract.Supported(m.Algorithm) || !trust.KeyIDPattern.MatchString(m.KeyID) || m.SBOMName != filepath.Base(o.SBOM) || m.SBOMSize < 0 {
		return fail("FORMAT_ERROR", "invalid or non-canonical SBOM manifest")
	}
	r.Algorithm, r.KeyID, r.Package, r.Version = &m.Algorithm, &m.KeyID, &m.Package, &m.Version
	store, err := trust.Parse(trustData, core)
	if err != nil {
		return fail("FORMAT_ERROR", err)
	}
	for _, entry := range store.Keys {
		if entry.KeyID != m.KeyID {
			continue
		}
		allowed := false
		for _, p := range entry.Packages {
			if p == o.Package {
				allowed = true
			}
		}
		if entry.Algorithm != m.Algorithm || !allowed {
			return fail("KEY_NOT_TRUSTED", "key is not authorized for expected package and algorithm")
		}
		key, _, _, e := core.LoadPublic([]byte(entry.PublicKeyPEM))
		if e != nil {
			return fail("FORMAT_ERROR", "invalid trusted key")
		}
		want := 64
		if m.Algorithm == "rsa-pss-sha256" {
			want = 384
		}
		if len(sig) != want || !core.Verify(m.Algorithm, key, msg, sig) {
			return fail("INVALID_SIGNATURE", "invalid signature")
		}
		sum := sha256.Sum256(sbom)
		if m.SBOMSize != int64(len(sbom)) || m.SBOMSHA256 != hex.EncodeToString(sum[:]) {
			return fail("SBOM_MISMATCH", "SBOM content digest differs")
		}
		if m.Package != o.Package || m.Version != o.Version {
			return fail("METADATA_MISMATCH", "package or version differs")
		}
		if m.ReleaseSHA256 != releaseHash {
			return fail("RELEASE_MISMATCH", "release artifact digest differs")
		}
		r.Valid, r.Status, r.Message = true, "OK", "SBOM signature and release binding verified"
		return r, 0
	}
	return fail("KEY_NOT_TRUSTED", "keyid not present in trust store")
}
