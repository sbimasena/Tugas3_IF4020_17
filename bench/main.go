package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"kelompok17/internal/contract"
	"kelompok17/internal/core"
)

const (
	pkg     = "kelompok17-bench"
	version = "1.0.0"
	warmup  = 5
	runs    = 30
)

var algorithms = []string{"rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"}

var sizes = []struct {
	name  string
	bytes int64
}{{"1KiB", 1 << 10}, {"1MiB", 1 << 20}, {"100MiB", 100 << 20}}

type series struct {
	metric, algorithm, size string
	samples                 []time.Duration
}

type keySizes struct {
	algorithm                          string
	publicDER, privateDER, sig, bundle int
}

var c core.Core

func main() {
	cli := flag.String("cli", "bench/k17", "CLI binary used for end-to-end runs")
	work := flag.String("work", "bench/artifacts", "scratch dir for artifacts, keys and bundles (gitignored)")
	out := flag.String("out", "bench/results", "output dir for raw.csv, summary.md, env.txt")
	flag.Parse()
	log.SetFlags(0)

	cliPath, err := filepath.Abs(*cli)
	check(err)
	workDir, err := filepath.Abs(*work)
	check(err)
	check(os.MkdirAll(workDir, 0o755))
	check(os.MkdirAll(*out, 0o755))

	var all []series
	add := func(s series) {
		all = append(all, s)
		sorted := sortedCopy(s.samples)
		log.Printf("%-14s %-18s %-7s median=%s p95=%s", s.metric, s.algorithm, s.size,
			percentile(sorted, 0.5), percentile(sorted, 0.95))
	}

	artifacts := map[string]string{}
	for _, s := range sizes {
		path := filepath.Join(workDir, "artifact-"+s.name+".bin")
		check(ensureRandomFile(path, s.bytes))
		artifacts[s.name] = path
		add(series{"hash", "-", s.name, measure(warmup, runs, func() { _, _, _ = hashFile(path) })})
	}

	trustPath := filepath.Join(workDir, "trust.json")
	_ = os.Remove(trustPath)
	var keyTable []keySizes

	for _, algo := range algorithms {
		add(series{"keygen", algo, "-", measure(1, 5, func() {
			_, _, err := c.Generate(algo)
			check(err)
		})})

		privPEM, pubPEM, err := c.Generate(algo)
		check(err)
		priv, _, _, err := c.LoadPrivate(privPEM)
		check(err)
		pub, _, keyid, err := c.LoadPublic(pubPEM)
		check(err)
		keyPath := filepath.Join(workDir, algo+".key.pem")
		pubPath := filepath.Join(workDir, algo+".pub.pem")
		check(os.WriteFile(keyPath, privPEM, 0o600))
		check(os.WriteFile(pubPath, pubPEM, 0o644))
		runCLI(cliPath, "trust", "add", "--key", pubPath, "--package", pkg, "--store", trustPath)

		size, digest, err := hashFile(artifacts["1KiB"])
		check(err)
		message, err := c.CanonicalManifest(contract.Manifest{
			Schema: contract.ManifestSchema, Package: pkg, Version: version, Algorithm: algo, KeyID: keyid,
			Artifact: contract.Artifact{Name: filepath.Base(artifacts["1KiB"]), Size: size, SHA256: digest},
		})
		check(err)
		var sig []byte
		add(series{"sign-manifest", algo, "-", measure(warmup, runs, func() {
			sig, err = c.Sign(algo, priv, message)
			check(err)
		})})
		add(series{"verify-manifest", algo, "-", measure(warmup, runs, func() {
			if !c.Verify(algo, pub, message, sig) {
				log.Fatalf("%s: signature did not verify", algo)
			}
		})})

		signDir, err := os.MkdirTemp(workDir, "sign-")
		check(err)
		bundleSize := 0
		for _, s := range sizes {
			file := artifacts[s.name]
			n := 0
			add(series{"e2e-sign", algo, s.name, measure(warmup, runs, func() {
				n++ 
				runCLI(cliPath, "sign", "--file", file, "--package", pkg, "--version", version,
					"--key", keyPath, "--out", filepath.Join(signDir, fmt.Sprintf("%s-%d.json", s.name, n)))
			})})

			bundle := filepath.Join(signDir, s.name+".bundle.json")
			runCLI(cliPath, "sign", "--file", file, "--package", pkg, "--version", version, "--key", keyPath, "--out", bundle)
			if s.name == "1KiB" {
				info, err := os.Stat(bundle)
				check(err)
				bundleSize = int(info.Size())
			}
			add(series{"e2e-verify", algo, s.name, measure(warmup, runs, func() {
				runCLI(cliPath, "verify", "--file", file, "--bundle", bundle, "--trust-store", trustPath,
					"--package", pkg, "--version", version, "--json")
			})})
		}
		check(os.RemoveAll(signDir))

		keyTable = append(keyTable, keySizes{algo, derLen(pubPEM), derLen(privPEM), len(sig), bundleSize})
	}

	check(writeRaw(filepath.Join(*out, "raw.csv"), all))
	check(writeSummary(filepath.Join(*out, "summary.md"), all, keyTable))
	check(os.WriteFile(filepath.Join(*out, "env.txt"), []byte(environment(cliPath)), 0o644))
	log.Printf("results written to %s", *out)
}

func measure(warm, n int, f func()) []time.Duration {
	for range warm {
		f()
	}
	samples := make([]time.Duration, n)
	for i := range samples {
		start := time.Now()
		f()
		samples[i] = time.Since(start)
	}
	return samples
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(i, 0)]
}

func sortedCopy(d []time.Duration) []time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

func ensureRandomFile(path string, size int64) error {
	if info, err := os.Stat(path); err == nil && info.Size() == size {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, rand.Reader, size); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func runCLI(cli string, args ...string) {
	if out, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
		log.Fatalf("%s %s: %v\n%s", filepath.Base(cli), strings.Join(args[:2], " "), err, out)
	}
}

func derLen(pemBytes []byte) int {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatal("invalid PEM from Generate")
	}
	return len(block.Bytes)
}

func writeRaw(path string, all []series) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"metric", "algorithm", "size", "run", "ns"})
	for _, s := range all {
		for i, d := range s.samples {
			_ = w.Write([]string{s.metric, s.algorithm, s.size, strconv.Itoa(i + 1), strconv.FormatInt(d.Nanoseconds(), 10)})
		}
	}
	w.Flush()
	return errors.Join(w.Error(), f.Close())
}

func writeSummary(path string, all []series, keys []keySizes) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Benchmark summary\n\nWarm-up %d, measured runs %d (keygen: 1 warm-up, 5 runs). Percentile: nearest-rank, value at position ceil(p*n).\n\n", warmup, runs)
	b.WriteString("| metric | algorithm | size | n | median (ms) | P95 (ms) |\n|---|---|---|---|---|---|\n")
	for _, s := range all {
		sorted := sortedCopy(s.samples)
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %.3f | %.3f |\n", s.metric, s.algorithm, s.size, len(sorted),
			ms(percentile(sorted, 0.5)), ms(percentile(sorted, 0.95)))
	}
	b.WriteString("\n## Sizes (bytes)\n\n| algorithm | public key DER (SPKI) | private key DER (PKCS#8) | signature | bundle (1KiB artifact) |\n|---|---|---|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", k.algorithm, k.publicDER, k.privateDER, k.sig, k.bundle)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func environment(cli string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "date: %s\ngo runtime: %s\nos/arch: %s/%s\nlogical CPUs: %d\n",
		time.Now().Format(time.RFC3339), runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	for _, cmd := range [][]string{
		{"sysctl", "-n", "machdep.cpu.brand_string"},
		{"sysctl", "-n", "hw.memsize"},
		{"sw_vers"},
		{"uname", "-a"},
		{"go", "version", "-m", cli},
	} {
		if out, err := exec.Command(cmd[0], cmd[1:]...).Output(); err == nil {
			fmt.Fprintf(&b, "\n$ %s\n%s", strings.Join(cmd, " "), out)
		}
	}
	return b.String()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
