"""Verify lean profiles and optionally inspect ELF artifacts without modifying them."""
import argparse
from pathlib import Path
import subprocess
import sys
import tomllib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "Cargo.toml").read_text())
    failures = []
    for name in ("dev", "release", "test"):
        profile = config["profile"][name]
        if profile.get("debug") != 0 or profile.get("strip") != "debuginfo":
            failures.append(f"{name}: debug=0 and strip=debuginfo required")
        if profile.get("build-override", {}).get("debug") != 0:
            failures.append(f"{name}: build dependency debug=0 required")
    for artifact in args.artifacts:
        result = subprocess.run(
            ["readelf", "--sections", "--wide", str(artifact)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            failures.append(f"{artifact}: readelf failed ({result.returncode})")
        elif ".debug_" in result.stdout or ".zdebug_" in result.stdout:
            failures.append(f"{artifact}: debug sections present")
        else:
            print(f"PASS no debug sections: {artifact}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if not failures:
        print("PASS dev/release/test build profiles")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
