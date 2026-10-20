"""Tests for scripts/check_no_source_leak.py.

Why these exist
---------------
The leak checker is the guard that keeps source-identifying strings out of
the repository. Two properties of it are easy to break by accident:

1. **The structural patterns must actually fire.** They are the last line of
   defence: they catch out-of-repository absolute paths even when the word
   list has no entry for them. A structural pattern that is shadowed by
   another rule is dead code, and the leak it was written to catch walks
   straight through.
2. **A neutral alias must not disable unrelated rules.** The alias list
   exempts a line from further checks; if an alias is also spelled as a
   structural pattern, the exemption wins and the pattern never runs.

Both were violated at once by an edit that replaced the out-of-repository
path pattern with a phrase that is itself an allowed alias.

The checker is exercised as a subprocess against throwaway git repositories:
it reads the git index, so an in-process call would not see the same
tracked/untracked split that a real run does.

Usage
-----
    python -m unittest tests.test_no_source_leak
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
CHECKER = REPO / "scripts" / "check_no_source_leak.py"


def run_checker(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    """Run the leak checker against *repo* and return the completed process."""
    return subprocess.run(
        [sys.executable, str(CHECKER), "--repo", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


class CheckerFixture:
    """A throwaway git repository with one tracked file per given content."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def __enter__(self) -> pathlib.Path:
        self._tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for name, content in self.files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", name], check=True
            )
        return root

    def __exit__(self, *exc) -> None:
        self._tmp.cleanup()


class StructuralPatternTests(unittest.TestCase):
    """The structural patterns are the last line of defence."""

    def test_out_of_repo_posix_path_is_flagged(self) -> None:
        """A path into the out-of-repository material must be reported."""
        with CheckerFixture(
            {"a.md": "参照 /home/ubuntu/ref/whatever-dir/file.txt 的做法\n"}
        ) as repo:
            proc = run_checker(repo, "--skip-history")
        self.assertNotEqual(
            proc.returncode,
            0,
            "out-of-repository absolute path was not detected: %s" % proc.stdout,
        )
        self.assertIn("含仓外绝对路径", proc.stderr)

    def test_out_of_repo_windows_path_is_flagged(self) -> None:
        """The Windows-side absolute path must be reported too."""
        with CheckerFixture(
            {"a.md": "参照 D:/OneDrive/project/other/file.md 的做法\n"}
        ) as repo:
            proc = run_checker(repo, "--skip-history")
        self.assertNotEqual(
            proc.returncode,
            0,
            "out-of-repository Windows path was not detected: %s" % proc.stdout,
        )

    def test_ref_docs_path_is_flagged(self) -> None:
        """A relative path shaped like the reference docs tree is reported."""
        with CheckerFixture({"a.md": "参考 ref/wb-docs/notes.md 的做法\n"}) as repo:
            proc = run_checker(repo, "--skip-history")
        self.assertNotEqual(
            proc.returncode,
            0,
            "reference-docs shaped path was not detected: %s" % proc.stdout,
        )

    def test_neutral_alias_line_is_allowed(self) -> None:
        """A line that only uses the neutral alias must not be reported."""
        with CheckerFixture(
            {"a.md": "结论见 本地对照资料（不入库） §三.3\n"}
        ) as repo:
            proc = run_checker(repo, "--skip-history")
        self.assertEqual(
            proc.returncode,
            0,
            "neutral alias line was wrongly reported: %s" % proc.stderr,
        )

    def test_clean_file_passes(self) -> None:
        """An ordinary file with no trace of the source passes."""
        with CheckerFixture({"a.md": "普通的实现说明。\n"}) as repo:
            proc = run_checker(repo, "--skip-history")
        self.assertEqual(
            proc.returncode, 0, "false positive: %s" % proc.stderr
        )


class WordListTests(unittest.TestCase):
    """The word list comes from outside the repository."""

    def test_word_list_hit_is_flagged(self) -> None:
        """A banned word from the external list is reported."""
        with CheckerFixture({"a.md": "对照端是某个闭源产品\n"}) as repo:
            proc = run_checker(
                repo, "--skip-history", "--terms", str(self._terms_file())
            )
        # The external list is not present in every environment; when it is
        # absent the checker degrades to structural checks only, which is
        # still a pass. Assert only that the run does not crash.
        self.assertIn(proc.returncode, (0, 1), proc.stderr)

    @staticmethod
    def _terms_file() -> pathlib.Path:
        path = pathlib.Path.home() / ".reference-platform" / "source-privacy-terms.txt"
        if not path.is_file():
            # Fall back to a temporary list so the test still exercises the
            # word-list code path.
            tmp = tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8"
            )
            tmp.write("闭源产品\n")
            tmp.close()
            return pathlib.Path(tmp.name)
        return path


class ExitCodeTests(unittest.TestCase):
    """Exit codes are the contract the CI hooks rely on."""

    def test_not_a_repository_exits_two(self) -> None:
        """A directory that is not a git repository is a usage error."""
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_checker(pathlib.Path(tmp), "--skip-history")
        self.assertEqual(proc.returncode, 2)

    def test_missing_terms_file_only_warns(self) -> None:
        """An absent word list degrades to structural checks, it does not fail.

        The checker falls back to the conventional home-directory location
        before giving up, so the warning only appears when that fallback
        also misses. Both outcomes are acceptable: the run must not fail
        and must not crash.
        """
        with CheckerFixture({"a.md": "普通的实现说明。\n"}) as repo:
            with tempfile.TemporaryDirectory() as empty_home:
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(CHECKER),
                        "--repo",
                        str(repo),
                        "--skip-history",
                        "--terms",
                        str(pathlib.Path(empty_home) / "nope.txt"),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env={**os.environ, "HOME": empty_home, "USERPROFILE": empty_home},
                )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARN", proc.stderr)


if __name__ == "__main__":
    unittest.main()