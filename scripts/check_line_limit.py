"""Check tracked and non-ignored source files; 400 soft / 700 hard."""
from pathlib import Path
import subprocess
import sys

EXTENSIONS = {".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".sh", ".toml", ".sql", ".md", ".yml", ".yaml", ".json"}


def main():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, check=True, capture_output=True,
    )
    failed = []
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
            failed.append(name)
            print(f"FAIL {name}: {count} > 700")
        elif count > 400:
            print(f"WARN {name}: {count} > 400; explain or split")
    print(f"Checked {checked} files; hard-limit failures: {len(failed)}")
    return int(bool(failed))


if __name__ == "__main__":
    sys.exit(main())
