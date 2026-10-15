"""Build and package real release binaries, with SHA-256 and ELF debug checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile


def run(*args):
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    if not os.environ.get("CARGO_TARGET_DIR"):
        parser.error("CARGO_TARGET_DIR must point outside the source repository")
    target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
    if target.is_relative_to(root):
        parser.error("build artifacts must stay outside the source repository")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        text=True,
    ))
    workspace = set(metadata["workspace_members"])
    names = sorted({
        t["name"] for p in metadata["packages"] if p["id"] in workspace
        for t in p["targets"] if "bin" in t["kind"]
    })
    if not names:
        parser.error("no executable targets; protocol libraries alone are not a release package")
    run(sys.executable, "scripts/verify_build_profiles.py")
    run("cargo", "build", "--workspace", "--release", "--locked")
    suffix = ".exe" if os.name == "nt" else ""
    binaries = [target / "release" / (name + suffix) for name in names]
    if os.name != "nt":
        run(sys.executable, "scripts/verify_build_profiles.py", *map(str, binaries))
    else:
        parser.error("Windows artifact symbol verification must be provided before packaging")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
    if dirty:
        parser.error("release requires a clean checkout")
    output = args.output.resolve()
    if output.is_relative_to(root):
        parser.error("release packages must stay outside the source repository")
    staging = output / ("lengsuo-" + revision[:12])
    staging.mkdir(parents=True, exist_ok=False)
    manifest = {"revision": revision, "debug_info": False, "binaries": []}
    for binary in binaries:
        dest = staging / binary.name
        shutil.copy2(binary, dest)
        manifest["binaries"].append({
            "name": dest.name, "bytes": dest.stat().st_size,
            "sha256": hashlib.sha256(dest.read_bytes()).hexdigest(),
        })
    (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    archive = output / (staging.name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(staging, arcname=staging.name)
    print(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
