// Package manifest berisi validasi, pembuatan, dan parsing manifest canonical
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"kelompok17/internal/contract"
	"kelompok17/internal/strictjson"
)

var (
	packageRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	nameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hex64RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\b", `\b`, "\f", `\f`, "\n", `\n`, "\r", `\r`, "\t", `\t`)

// Validate mengecek semua field m sesuai aturan di contract.Manifest.
// Nilai Algorithm tidak dicek, hanya dipastikan bisa di-escape.
func Validate(m contract.Manifest) error {
	if m.Schema != contract.ManifestSchema || !packageRE.MatchString(m.Package) ||
		!versionRE.MatchString(m.Version) || !hex64RE.MatchString(m.KeyID) ||
		!nameRE.MatchString(m.Artifact.Name) || !hex64RE.MatchString(m.Artifact.SHA256) ||
		m.Artifact.Size < 0 || m.Artifact.Size > contract.MaxArtifactSize {
		return errors.New("manifest: invalid field value")
	}
	if strings.ContainsFunc(m.Algorithm, func(r rune) bool { return r < 0x20 && !strings.ContainsRune("\b\f\n\r\t", r) }) {
		return errors.New("manifest: algorithm cannot be canonicalized")
	}
	return nil
}

// Canonical mengubah m ke JSON satu baris tanpa spasi dengan urutan field
// schema, package, version, algorithm, keyid, artifact (name, size, sha256).
// Gagal kalau m tidak valid atau hasilnya lebih dari 16 KiB.
func Canonical(m contract.Manifest) ([]byte, error) {
	if err := Validate(m); err != nil {
		return nil, err
	}
	out := fmt.Appendf(nil, `{"schema":"%s","package":"%s","version":"%s","algorithm":"%s","keyid":"%s","artifact":{"name":"%s","size":%d,"sha256":"%s"}}`,
		m.Schema, m.Package, m.Version, escaper.Replace(m.Algorithm), m.KeyID, m.Artifact.Name, m.Artifact.Size, m.Artifact.SHA256)
	if len(out) > contract.MaxManifest {
		return nil, errors.New("manifest: exceeds 16 KiB")
	}
	return out, nil
}

// Parse mem-parse data lalu membandingkannya byte per byte dengan hasil Canonical.
// Gagal kalau data lebih dari 16 KiB, JSON-nya ditolak strictjson, ada field
// yang tidak valid, atau data tidak canonical.
func Parse(data []byte) (contract.Manifest, error) {
	var m contract.Manifest
	if len(data) > contract.MaxManifest {
		return m, errors.New("manifest: exceeds 16 KiB")
	}
	if err := strictjson.Unmarshal(data, &m); err != nil {
		return m, err
	}
	canonical, err := Canonical(m)
	if err == nil && !bytes.Equal(canonical, data) {
		err = errors.New("manifest: not in canonical form")
	}
	return m, err
}
