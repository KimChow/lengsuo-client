"""Check tracked and non-ignored source files; 400 soft / 700 hard.

The 400-line soft target does NOT fail this gate, but its full list is always
printed and can be captured as a structured receipt with ``--json``. Acceptance
runs must record that summary instead of dropping the warnings, so "over 400"
is visible at review time without blocking an otherwise-green baseline.
"""
from pathlib import Path
import argparse
import json
import subprocess
import sys

EXTENSIONS = {".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".sh", ".toml", ".sql", ".md", ".yml", ".yaml", ".json"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path,
                        help="also write a structured receipt to this path")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, check=True, capture_output=True,
    )
    failed = []
    soft = []
    checked = 0
    for name in sorted(set(result.stdout.decode("utf-8").split("\0")) - {""}):
        path = root / name
        if not path.is_file() or path.suffix not in EXTENSIONS:
            continue
        if "fixtures" in path.relative_to(root).parts or path.name.endswith(".lock"):
            continue
        count = len(path.read_text(encoding="utf-8").splitlines())
        checked += 1
        if count > 700:
            failed.append({"path": name, "lines": count})
            print(f"FAIL {name}: {count} > 700")
        elif count > 400:
            soft.append({"path": name, "lines": count})
            print(f"WARN {name}: {count} > 400; explain or split")
    soft.sort(key=lambda item: -item["lines"])
    print(f"Checked {checked} files; hard-limit failures: {len(failed)}; "
          f"soft-target warnings: {len(soft)}")
    if args.json:
        args.json.write_text(json.dumps({
            "checked": checked,
            "hard_limit": 700,
            "soft_target": 400,
            "hard_failures": failed,
            "soft_target_over": soft,
        }, indent=2))
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main())
