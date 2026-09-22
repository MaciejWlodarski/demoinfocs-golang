#!/usr/bin/env python3
"""Build a temporary consumer copy against this fork and compare its JSON output.

No application/dependency files in the real consumer are changed. No baseline
update mode: reviewed snapshots must be recorded separately before code changes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_files(consumer):
    names = subprocess.check_output(
        ["git", "-C", str(consumer), "ls-files", "--cached", "--others", "--exclude-standard"], text=True
    ).splitlines()
    return sorted({name for name in names if name.endswith(".go") or name in ("go.mod", "go.sum")})


def source_digest(consumer, names):
    checksum = hashlib.sha256()
    for name in names:
        checksum.update(name.encode() + b"\0")
        checksum.update((consumer / name).read_bytes())
        checksum.update(b"\0")
    return checksum.hexdigest()


def normalize(value):
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        result = {key: normalize(item) for key, item in value.items()}
        if isinstance(result.get("inventory"), list):
            result["inventory"].sort()
        if isinstance(result.get("seen_events"), list):
            # Independent visibility updates can arrive in a different order.
            # Retain every payload/tick, sorting only ties after the tick.
            result["seen_events"].sort(key=lambda item: (item["tick"], json.dumps(item, sort_keys=True)))
        return result
    return value


def output_digest(path):
    normalized = normalize(json.loads(path.read_text()))
    return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--consumer", required=True, type=Path)
    cli.add_argument("--demos", required=True, type=Path, help="directory containing demo1.dem and demo2.dem")
    cli.add_argument("--maps", required=True, type=Path)
    cli.add_argument("--output", required=True, type=Path, help="new directory for logs and actual JSON files")
    args = cli.parse_args()
    root = Path(__file__).resolve().parents[1]
    baseline = json.loads((root / "pkg/demoinfocs/testdata/gotv/consumer.json").read_text())
    consumer = args.consumer.resolve()
    names = source_files(consumer)
    if source_digest(consumer, names) != baseline["consumer_source_sha256"]:
        raise SystemExit("Consumer sources differ from the recorded baseline; review/re-record it first.")
    maps = args.maps.resolve()
    # Presence as well as contents matter: enabling another map changes vision output.
    map_files = sorted(path.name for path in maps.glob("*.kdtree"))
    if map_files != sorted(baseline["maps"]):
        raise SystemExit("Map set differs from the recorded baseline.")
    for name, expected in baseline["maps"].items():
        if digest_file(maps / name) != expected:
            raise SystemExit(f"Map checksum differs: {name}")
    for name, expected in baseline["demos"].items():
        if digest_file(args.demos / (name + ".dem")) != expected["demo_sha256"]:
            raise SystemExit(f"Demo checksum differs: {name}")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="demoinfocs-consumer-") as temporary:
        work = Path(temporary)
        for name in names:
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(consumer / name, target)
        # Replace only the active directive, preserving the rest of the manifest.
        manifest = work / "go.mod"
        content, count = re.subn(
            r"^replace github\.com/markus-wa/demoinfocs-golang/v4 => .*$",
            lambda _: 'replace github.com/markus-wa/demoinfocs-golang/v4 => ' + json.dumps(str(root)),
            manifest.read_text(), flags=re.MULTILINE,
        )
        if count != 1:
            raise SystemExit("Expected exactly one active demoinfocs replace directive.")
        manifest.write_text(content)
        binary = work / "consumer"
        with (args.output / "build.log").open("w") as log:
            subprocess.run(["go", "build", "-mod=mod", "-o", str(binary), "./cmd/parser-cs2"], cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True)
        failed = False
        for name, expected in baseline["demos"].items():
            actual = args.output.resolve() / (name + ".json")
            with (args.output / (name + ".log")).open("w") as log:
                subprocess.run([str(binary), "-input", str((args.demos / (name + ".dem")).resolve()), "-maps", str(maps), "-output", str(actual)], cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
            actual_digest = output_digest(actual)
            passed = actual_digest == expected["current_output_sha256"]
            print(f"{name}: {'PASS' if passed else 'FAIL'} {actual_digest}", flush=True)
            failed |= not passed
        if failed:
            raise SystemExit("Consumer output changed; inspect saved JSON/logs. Baseline was not updated.")


if __name__ == "__main__":
    main()
