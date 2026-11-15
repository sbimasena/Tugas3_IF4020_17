// Package trust berisi fungsi untuk membaca, mengecek, dan menyimpan trust store
package trust

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"kelompok17/internal/contract"
)

// PackagePattern adalah regex untuk nama paket
var PackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// KeyIDPattern adalah regex untuk keyid (64 karakter hex huruf kecil)
var KeyIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Parse mem-parse trust store dengan core.StrictJSON lalu mengecek setiap entry:
// keyid tidak dobel, algorithm didukung, PEM cocok dengan algorithm dan keyid,
// dan daftar paket tidak kosong serta tidak dobel
func Parse(data []byte, core contract.Core) (contract.Store, error) {
	var store contract.Store
	if err := core.StrictJSON(data, &store); err != nil {
		return store, err
	}
	if store.Schema != contract.TrustSchema || store.Keys == nil {
		return store, fmt.Errorf("invalid trust store schema or keys")
	}
	seen := make(map[string]bool)
	for _, entry := range store.Keys {
		if !KeyIDPattern.MatchString(entry.KeyID) || seen[entry.KeyID] || !contract.Supported(entry.Algorithm) {
			return store, fmt.Errorf("invalid or duplicate trust key")
		}
		seen[entry.KeyID] = true
		_, algorithm, keyid, err := core.LoadPublic([]byte(entry.PublicKeyPEM))
		if err != nil || algorithm != entry.Algorithm || keyid != entry.KeyID {
			return store, fmt.Errorf("invalid public key or fingerprint")
		}
		if len(entry.Packages) == 0 {
			return store, fmt.Errorf("empty package permissions")
		}
		packages := make(map[string]bool)
		for _, name := range entry.Packages {
			if !PackagePattern.MatchString(name) || packages[name] {
				return store, fmt.Errorf("invalid or duplicate package permission")
			}
			packages[name] = true
		}
	}
	return store, nil
}

// Load membaca file di path lalu memanggil Parse. Kalau create true dan file
// belum ada, Load mengembalikan store kosong.
func Load(path string, core contract.Core, create bool) (contract.Store, error) {
	data, err := os.ReadFile(path)
	if create && os.IsNotExist(err) {
		return contract.Store{Schema: contract.TrustSchema, Keys: []contract.Entry{}}, nil
	}
	if err != nil {
		return contract.Store{}, err
	}
	return Parse(data, core)
}

// Save menyimpan store ke path sebagai JSON dengan mode 0600. File ditulis ke
// file sementara dulu lalu di-rename.
func Save(path string, store contract.Store) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Add memberi kunci izin untuk paket name. Kalau keyid sudah ada di store,
// name ditambahkan ke Packages entry tersebut.
func Add(store *contract.Store, entry contract.Entry, name string) {
	for i := range store.Keys {
		if store.Keys[i].KeyID == entry.KeyID {
			if !slices.Contains(store.Keys[i].Packages, name) {
				store.Keys[i].Packages = append(store.Keys[i].Packages, name)
			}
			return
		}
	}
	entry.Packages = []string{name}
	store.Keys = append(store.Keys, entry)
}

// Remove menghapus kunci dengan keyid dari store. Gagal kalau keyid tidak ada.
func Remove(store *contract.Store, keyid string) error {
	for i, entry := range store.Keys {
		if entry.KeyID == keyid {
			store.Keys = append(store.Keys[:i], store.Keys[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("keyid not found")
}
