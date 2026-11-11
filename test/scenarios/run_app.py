import argparse
import base64
import copy
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


PROFILES = ["rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"]
FIELDS = {"valid", "status", "message", "algorithm", "keyid", "package", "version"}


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def encode(data):
    return base64.b64encode(data).decode("ascii")


class Runner:
    def __init__(self, repo, output, executable):
        self.repo, self.output, self.executable = repo, output, executable
        self.results = []

    def run(self, name, command, code=0, status=None, check=None):
        arguments = [os.path.relpath(arg, self.repo) if isinstance(arg, Path) else str(arg) for arg in command]
        result = subprocess.run([str(self.executable), *arguments], cwd=self.repo,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
        logs = self.output / "logs"
        logs.mkdir(exist_ok=True)
        (logs / f"{name}.stdout.txt").write_text(result.stdout, encoding="utf-8")
        (logs / f"{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")
        passed = result.returncode == code
        actual = None
        if status is not None:
            try:
                actual = json.loads(result.stdout)
                passed = (passed and set(actual) == FIELDS and actual["status"] == status
                          and actual["valid"] is (status == "OK")
                          and isinstance(actual["message"], str)
                          and all(actual[key] is None or isinstance(actual[key], str)
                                  for key in ["algorithm", "keyid", "package", "version"])
                          and result.stdout.endswith("\n") and not result.stdout.endswith("\n\n")
                          and bool(result.stderr))
            except (ValueError, TypeError, KeyError):
                passed = False
        if check is not None:
            passed = passed and check(result)
        passed = passed and "PRIVATE KEY" not in result.stdout + result.stderr
        self.results.append({"id": name, "command": ["kelompok17", *arguments],
                             "expected_exit": code, "expected_status": status,
                             "actual_exit": result.returncode, "actual": actual, "passed": bool(passed)})
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)
        return result

    def verify(self, name, artifact, bundle, store, status="OK", package="demo", version="1"):
        code = 0 if status == "OK" else 2 if status == "INPUT_ERROR" else 1
        return self.run(name, ["verify", "--file", artifact, "--bundle", bundle, "--trust-store", store,
                               "--package", package, "--version", version, "--json"], code, status)

    def observe(self, name, passed, details):
        self.results.append({"id": name, "expected_exit": None, "expected_status": None,
                             "actual_exit": None, "actual": details, "passed": bool(passed)})
        print(f"{'PASS' if passed else 'FAIL'} {name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="U01-U14 and member B CLI/trust checks")
    parser.add_argument("--cli", help="existing executable; otherwise build from this repository")
    parser.add_argument("--out", default="test/results/app-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--revision", default="not recorded")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = (repo / args.out).resolve()
    output.mkdir(parents=True, exist_ok=False)
    executable = Path(args.cli).resolve() if args.cli else repo / "dist" / ("kelompok17.exe" if os.name == "nt" else "kelompok17")
    if not args.cli:
        executable.parent.mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-o", str(executable), "./cmd/kelompok17"], cwd=repo, check=True)
    runner = Runner(repo, output, executable)
    baselines = {}
    fixtures = {"text.txt": b"release kelompok17\n", "binary.bin": bytes(range(256)), "empty.bin": b""}
    for algorithm in PROFILES:
        directory = output / "inputs" / algorithm
        directory.mkdir(parents=True)
        prefix = repo / "test" / "keys" / ("app-" + algorithm)
        private, public = Path(str(prefix) + ".key.pem"), Path(str(prefix) + ".pub.pem")
        store = directory / "trust.json"
        runner.run("setup-key-" + algorithm, ["keygen", "--algorithm", algorithm, "--out", prefix, "--force"])
        runner.run("setup-trust-" + algorithm, ["trust", "add", "--key", public, "--package", "demo", "--store", store])
        for filename, contents in fixtures.items():
            artifact, bundle = directory / filename, directory / (filename + ".json")
            artifact.write_bytes(contents)
            runner.run("setup-sign-" + algorithm + "-" + filename,
                       ["sign", "--file", artifact, "--package", "demo", "--version", "1", "--key", private, "--out", bundle])
            runner.verify("U01-" + algorithm + "-" + filename, artifact, bundle, store)
        baselines[algorithm] = {"artifact": directory / "binary.bin", "bundle": directory / "binary.bin.json",
                                "store": store, "private": private, "public": public, "prefix": prefix}
        second = directory / "second.json"
        runner.run("setup-U14-" + algorithm, ["sign", "--file", directory / "binary.bin", "--package", "demo",
                                               "--version", "1", "--key", private, "--out", second])
        runner.verify("U14-" + algorithm + "-first", directory / "binary.bin", directory / "binary.bin.json", store)
        runner.verify("U14-" + algorithm + "-second", directory / "binary.bin", second, store)
        first_bundle = json.loads((directory / "binary.bin.json").read_text())
        second_bundle = json.loads(second.read_text())
        identical = first_bundle["signature_b64"] == second_bundle["signature_b64"]
        runner.observe("U14-" + algorithm + "-comparison",
                       first_bundle["manifest_b64"] == second_bundle["manifest_b64"] and identical == (algorithm == "ed25519"),
                       {"same_manifest": first_bundle["manifest_b64"] == second_bundle["manifest_b64"], "identical_signature": identical})

    base = baselines["ed25519"]
    good_bundle = json.loads(base["bundle"].read_text())
    good_store = json.loads(base["store"].read_text())
    manifest_bytes = base64.b64decode(good_bundle["manifest_b64"])

    def case(name, status, artifact_data=None, manifest_change=None, bundle_change=None, store_change=None,
             filename="binary.bin", package="demo", version="1", raw_bundle=None, raw_manifest=None, raw_store=None):
        directory = output / "inputs" / name
        directory.mkdir()
        artifact, bundle, store = directory / filename, directory / "bundle.json", directory / "trust.json"
        artifact.write_bytes(base["artifact"].read_bytes() if artifact_data is None else artifact_data)
        b, s = copy.deepcopy(good_bundle), copy.deepcopy(good_store)
        if manifest_change:
            m = json.loads(manifest_bytes)
            manifest_change(m)
            b["manifest_b64"] = encode(json.dumps(m, separators=(",", ":"), ensure_ascii=False).encode())
        if raw_manifest is not None:
            b["manifest_b64"] = encode(raw_manifest)
        if bundle_change:
            bundle_change(b)
        if store_change:
            store_change(s)
        save(bundle, b)
        save(store, s)
        if raw_bundle is not None:
            bundle.write_bytes(raw_bundle)
        if raw_store is not None:
            store.write_bytes(raw_store)
        runner.verify(name, artifact, bundle, store, status, package, version)
        return artifact, bundle, store

    altered = bytearray(base["artifact"].read_bytes())
    altered[10] ^= 1
    case("U02", "ARTIFACT_MISMATCH", artifact_data=altered)
    case("U03-add", "ARTIFACT_MISMATCH", artifact_data=base["artifact"].read_bytes() + b"x")
    case("U03-remove", "ARTIFACT_MISMATCH", artifact_data=base["artifact"].read_bytes()[:-1])
    case("U04", "INVALID_SIGNATURE", manifest_change=lambda m: m.update(version="2"))
    signature = bytearray(base64.b64decode(good_bundle["signature_b64"]))
    signature[0] ^= 1
    case("U05", "INVALID_SIGNATURE", bundle_change=lambda b: b.update(signature_b64=encode(signature)))
    case("U06-empty", "KEY_NOT_TRUSTED", store_change=lambda s: s.update(keys=[]))
    case("U07", "KEY_NOT_TRUSTED", store_change=lambda s: s["keys"][0].update(packages=["other"]))
    case("U08", "METADATA_MISMATCH", version="2")
    case("U09", "METADATA_MISMATCH", filename="renamed.bin")
    case("U10-duplicate-bundle", "FORMAT_ERROR", raw_bundle=b'{"schema":"minisign-bundle/v1",' + json.dumps(good_bundle).encode()[1:])
    case("U10-duplicate-manifest", "FORMAT_ERROR", raw_manifest=manifest_bytes.replace(b'"version":"1"', b'"version":"1","version":"1"'))
    case("U10-duplicate-nested", "FORMAT_ERROR", raw_manifest=manifest_bytes.replace(b'"size":256', b'"size":256,"size":256'))
    case("U10-type", "FORMAT_ERROR", manifest_change=lambda m: m["artifact"].update(size="256"))
    case("U10-boolean", "FORMAT_ERROR", manifest_change=lambda m: m["artifact"].update(size=True))
    case("U10-null", "FORMAT_ERROR", manifest_change=lambda m: m.update(version=None))
    case("U10-extra-field", "FORMAT_ERROR", bundle_change=lambda b: b.update(extra="x"))
    case("U10-missing-field", "FORMAT_ERROR", bundle_change=lambda b: b.pop("schema"))
    case("U10-base64-character", "FORMAT_ERROR", bundle_change=lambda b: b.update(signature_b64="%%%"))
    case("U10-base64-padding", "FORMAT_ERROR", bundle_change=lambda b: b.update(signature_b64=b["signature_b64"].rstrip("=")))
    case("U10-base64-space", "FORMAT_ERROR", bundle_change=lambda b: b.update(signature_b64=b["signature_b64"] + "\n"))
    case("U10-base64-pad-bits", "FORMAT_ERROR", bundle_change=lambda b: b.update(signature_b64="/x=="))
    case("U10-manifest-size", "FORMAT_ERROR", raw_manifest=b" " * 16385)
    case("U10-bundle-size", "FORMAT_ERROR", raw_bundle=b" " * 65537)
    case("U10-canonical-space", "FORMAT_ERROR", raw_manifest=b" " + manifest_bytes)
    case("U10-canonical-order", "FORMAT_ERROR", raw_manifest=json.dumps(dict(reversed(list(json.loads(manifest_bytes).items()))), separators=(",", ":")).encode())
    case("U10-canonical-newline", "FORMAT_ERROR", raw_manifest=manifest_bytes + b"\n")
    case("U10-canonical-exponent", "FORMAT_ERROR", raw_manifest=manifest_bytes.replace(b'"size":256', b'"size":2.56e2'))
    case("U10-bom", "FORMAT_ERROR", raw_bundle=b"\xef\xbb\xbf" + json.dumps(good_bundle).encode())
    case("U10-trailing-json", "FORMAT_ERROR", raw_bundle=json.dumps(good_bundle).encode() + b"{}")
    case("U11", "UNSUPPORTED_ALGORITHM", manifest_change=lambda m: m.update(algorithm="unknown"))
    other_prefix = repo / "test" / "keys" / "app-untrusted"
    runner.run("setup-untrusted", ["keygen", "--algorithm", "ed25519", "--out", other_prefix, "--force"])
    other_bundle = output / "inputs" / "untrusted.json"
    runner.run("setup-U12", ["sign", "--file", base["artifact"], "--package", "demo", "--version", "1",
                              "--key", Path(str(other_prefix) + ".key.pem"), "--out", other_bundle])
    runner.verify("U12", base["artifact"], other_bundle, base["store"], "KEY_NOT_TRUSTED")
    case("U13", "OK", raw_bundle=json.dumps(dict(reversed(list(good_bundle.items()))), indent=4).encode())

    trust_checks = {
        "duplicate-keyid": lambda s: s["keys"].append(copy.deepcopy(s["keys"][0])),
        "duplicate-package": lambda s: s["keys"][0].update(packages=["demo", "demo"]),
        "empty-package": lambda s: s["keys"][0].update(packages=[]),
        "wildcard": lambda s: s["keys"][0].update(packages=["*"]),
        "fingerprint": lambda s: s["keys"][0].update(keyid="0" * 64),
        "key-encoding": lambda s: s["keys"][0].update(public_key_pem="invalid"),
        "key-profile": lambda s: s["keys"][0].update(algorithm="rsa-pss-sha256"),
        "keys-null": lambda s: s.update(keys=None),
        "extra-field": lambda s: s.update(extra="x"),
        "missing-field": lambda s: s["keys"][0].pop("algorithm"),
    }
    for name, change in trust_checks.items():
        case("TRUST-format-" + name, "FORMAT_ERROR", store_change=change)
    case("TRUST-format-duplicate-field", "FORMAT_ERROR", raw_store=b'{"schema":"minisign-trust/v1",' + json.dumps(good_store).encode()[1:])
    wrong_profile = copy.deepcopy(good_store)
    wrong_profile["keys"][0] = json.loads(baselines["rsa-pss-sha256"]["store"].read_text())["keys"][0]
    case("TRUST-valid-different-profile", "KEY_NOT_TRUSTED",
         manifest_change=lambda m: m.update(keyid=wrong_profile["keys"][0]["keyid"]), store_change=lambda s: s.update(wrong_profile))
    case("SIGNATURE-length", "INVALID_SIGNATURE", bundle_change=lambda b: b.update(signature_b64=encode(b"x" * 63)))
    case("ORDER-trust-before-algorithm", "FORMAT_ERROR", manifest_change=lambda m: m.update(algorithm="unknown"), raw_store=b"{}")
    case("ORDER-algorithm-before-trust", "UNSUPPORTED_ALGORITHM", manifest_change=lambda m: m.update(algorithm="unknown"), store_change=lambda s: s.update(keys=[]))
    case("ORDER-trust-before-signature", "KEY_NOT_TRUSTED", store_change=lambda s: s.update(keys=[]), bundle_change=lambda b: b.update(signature_b64=encode(b"x")))
    case("ORDER-signature-before-metadata", "INVALID_SIGNATURE", version="2", bundle_change=lambda b: b.update(signature_b64=encode(signature)))
    case("ORDER-metadata-before-artifact", "METADATA_MISMATCH", version="2", artifact_data=altered)
    missing = output / "inputs" / "missing.bin"
    runner.verify("IO-missing-artifact", missing, base["bundle"], base["store"], "INPUT_ERROR")
    runner.verify("IO-missing-bundle", base["artifact"], missing, base["store"], "INPUT_ERROR")
    runner.verify("IO-missing-trust", base["artifact"], base["bundle"], missing, "INPUT_ERROR")
    malformed = output / "inputs" / "malformed.json"
    malformed.write_text("{}")
    runner.verify("ORDER-io-before-format", base["artifact"], malformed, missing, "INPUT_ERROR")

    for command in [[], ["keygen"], ["sign"], ["verify"], ["trust"], ["trust", "add"], ["trust", "list"], ["trust", "remove"]]:
        runner.run("CLI-help-" + ("-".join(command) or "root"), [*command, "--help"], check=lambda r: "Usage:" in r.stdout)
    runner.run("CLI-version", ["--version"], check=lambda r: bool(r.stdout.strip()))
    for name, command in {
        "missing": ["verify", "--json"],
        "unknown": ["verify", "--unknown", "--json"],
        "positional": ["verify", "extra", "--json"],
    }.items():
        runner.run("CLI-" + name, command, 2, "INPUT_ERROR")
    runner.run("CLI-json-used-as-value", ["verify", "--file", "--json", "--unknown"], 2, check=lambda r: not r.stdout)
    runner.run("CLI-json-disabled", ["verify", "--unknown", "--json=false"], 2, check=lambda r: not r.stdout)
    runner.run("CLI-unknown-command", ["unknown"], 2)
    runner.run("CLI-trust-no-command", ["trust"], 2)
    runner.run("CLI-verify-text", ["verify", "--file", base["artifact"], "--bundle", base["bundle"], "--trust-store", base["store"],
                                    "--package", "demo", "--version", "1"], check=lambda r: not r.stdout and "OK" in r.stderr)
    for name, value in [("package", "bad package"), ("version", "bad version")]:
        runner.verify("INPUT-invalid-" + name, base["artifact"], base["bundle"], base["store"], "INPUT_ERROR",
                      package=value if name == "package" else "demo", version=value if name == "version" else "1")

    managed = output / "inputs" / "managed-trust.json"
    add = ["trust", "add", "--key", base["public"], "--package", "demo", "--store", managed]
    runner.run("TRUST-add", add, check=lambda r: all(word in r.stdout for word in [good_store["keys"][0]["keyid"], "ed25519", "demo"]))
    runner.run("TRUST-idempotent", add)
    state = json.loads(managed.read_text())
    runner.observe("TRUST-idempotent-state", len(state["keys"]) == 1 and state["keys"][0]["packages"] == ["demo"], state)
    runner.run("TRUST-update", ["trust", "add", "--key", base["public"], "--package", "other", "--store", managed])
    state = json.loads(managed.read_text())
    runner.observe("TRUST-update-state", len(state["keys"]) == 1 and state["keys"][0]["packages"] == ["demo", "other"], state)
    runner.run("TRUST-list", ["trust", "list", "--store", managed], check=lambda r: "demo" in r.stdout and "other" in r.stdout)
    remove = ["trust", "remove", "--keyid", good_store["keys"][0]["keyid"], "--store", managed]
    runner.run("TRUST-remove", remove)
    runner.verify("U06-removed", base["artifact"], base["bundle"], managed, "KEY_NOT_TRUSTED")
    runner.run("TRUST-remove-missing", remove, 2)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        locked_store = output / "inputs" / "locked-trust.json"
        save(locked_store, good_store)
        old_store = locked_store.read_bytes()
        handle = kernel.CreateFileW(str(locked_store), 0x80000000, 3, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            runner.run("TRUST-atomic-rename-failure", ["trust", "add", "--key", base["public"], "--package", "other", "--store", locked_store], 2)
            runner.observe("TRUST-atomic-original-preserved", locked_store.read_bytes() == old_store, "previous store unchanged after rename failure")
        finally:
            kernel.CloseHandle(handle)
    invalid_store = output / "inputs" / "invalid-store.json"
    invalid_store.write_bytes(b"invalid")
    runner.run("TRUST-preserve-invalid", ["trust", "add", "--key", base["public"], "--package", "demo", "--store", invalid_store], 2)
    runner.observe("TRUST-preserve-invalid-state", invalid_store.read_bytes() == b"invalid", "store unchanged")
    conflict = output / "inputs" / "store-directory"
    conflict.mkdir()
    runner.run("TRUST-write-failure", ["trust", "add", "--key", base["public"], "--package", "demo", "--store", conflict], 2)
    before = hashlib.sha256(base["private"].read_bytes()).hexdigest()
    runner.run("KEYGEN-no-overwrite", ["keygen", "--algorithm", "ed25519", "--out", base["prefix"]], 2)
    runner.observe("KEYGEN-preserved", hashlib.sha256(base["private"].read_bytes()).hexdigest() == before, "private key unchanged")
    force_prefix = output / "inputs" / "force-key"
    runner.run("KEYGEN-force-first", ["keygen", "--algorithm", "ed25519", "--out", force_prefix])
    first_key = Path(str(force_prefix) + ".key.pem").read_bytes()
    runner.run("KEYGEN-force-replace", ["keygen", "--algorithm", "ed25519", "--out", force_prefix, "--force"])
    runner.observe("KEYGEN-force-changed", first_key != Path(str(force_prefix) + ".key.pem").read_bytes(), "new key pair")
    original = base["artifact"].read_bytes()
    runner.run("SIGN-no-overwrite", ["sign", "--file", base["artifact"], "--package", "demo", "--version", "1", "--key", base["private"], "--out", base["bundle"]], 2)
    runner.run("SIGN-input-overlap", ["sign", "--file", base["artifact"], "--package", "demo", "--version", "1", "--key", base["private"], "--out", base["artifact"]], 2)
    runner.observe("SIGN-artifact-preserved", base["artifact"].read_bytes() == original, "artifact unchanged")
    no_temps = not list(output.rglob(".trust-*")) and not list(output.rglob(".key-*"))
    runner.observe("IO-temporary-cleanup", no_temps, "no leftover temporary files")

    save(output / "results.json", runner.results)
    with (output / "results.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["id", "expected_status", "expected_exit", "actual_status", "actual_exit", "passed"])
        for result in runner.results:
            actual = result["actual"]
            writer.writerow([result["id"], result["expected_status"], result["expected_exit"],
                             actual.get("status", "") if isinstance(actual, dict) else "", result["actual_exit"], result["passed"]])
    failed = [result["id"] for result in runner.results if not result["passed"]]
    summary = {"utc": datetime.now(timezone.utc).isoformat(), "revision": args.revision,
               "platform": platform.platform(), "python": platform.python_version(),
               "go": subprocess.check_output(["go", "version"], text=True).strip(),
               "total": len(runner.results), "passed": len(runner.results) - len(failed), "failed": failed,
               "u14": [result for result in runner.results if result["id"].endswith("-comparison")]}
    save(output / "summary.json", summary)
    print(f"{summary['passed']}/{summary['total']} passed; {output}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
