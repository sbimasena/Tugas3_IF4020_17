// Package strictjson berisi parser JSON yang lebih ketat dari encoding/json
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Unmarshal mengisi target (pointer ke struct) dari data. Gagal kalau ada BOM,
// UTF-8 tidak valid, key dobel, field tidak dikenal atau kurang, null, tipe tidak
// cocok, angka pecahan atau eksponen, atau ada data lain setelah objek.
func Unmarshal(data []byte, target any) error {
	if bytes.HasPrefix(data, []byte("\xEF\xBB\xBF")) || !utf8.Valid(data) {
		return fmt.Errorf("json: BOM or invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := check(dec, reflect.TypeOf(target).Elem(), "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("json: trailing data")
	}
	return json.Unmarshal(data, target)
}

func check(dec *json.Decoder, t reflect.Type, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("json: %s: %w", path, err)
	}
	kind, ok := t.Kind(), false
	switch v := tok.(type) {
	case nil:
		return fmt.Errorf("json: %s: null is not allowed", path)
	case string:
		ok = kind == reflect.String
	case bool:
		ok = kind == reflect.Bool
	case json.Number:
		ok = kind == reflect.Int64 && !strings.ContainsAny(string(v), ".eE")
	case json.Delim:
		if v == '[' && kind == reflect.Slice {
			for i := 0; dec.More(); i++ {
				if err := check(dec, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		if v == '{' && kind == reflect.Struct {
			return checkObject(dec, t, path)
		}
	}
	if !ok {
		return fmt.Errorf("json: %s: unexpected %v", path, tok)
	}
	return nil
}

func checkObject(dec *json.Decoder, t reflect.Type, path string) error {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		fields[name] = t.Field(i).Type
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key := tok.(string)
		if seen[key] {
			return fmt.Errorf("json: %s: duplicate key %q", path, key)
		}
		seen[key] = true
		ft, ok := fields[key]
		if !ok {
			return fmt.Errorf("json: %s: unknown field %q", path, key)
		}
		if err := check(dec, ft, path+"."+key); err != nil {
			return err
		}
	}
	if len(seen) != len(fields) {
		return fmt.Errorf("json: %s: missing field", path)
	}
	_, err := dec.Token()
	return err
}
