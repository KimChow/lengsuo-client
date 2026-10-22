#!/usr/bin/env python3
"""`check_gate_coverage.py` 的单元测试（纯 unittest）。

    python3 scripts/test_gate_coverage.py -v

覆盖的失败模式（每条都对应一个真实漏网）：
1. 当前工作树无「用参考却未登记」的 target（守卫必须绿）
2. 用了参考环境变量却没登记的 target ⇒ 报违规
3. 同一 target 进豁免清单 ⇒ 不再报违规
4. `tests/<t>/mod.rs` 归 `<t>`（子目录口径）；`// #[ignore]` 注释行不算
   ignored 测试，注释里提到环境变量也不算「用了参考」
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_gate_coverage as guard  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_tree(root: Path, manifest_tests=None, extra_tests=None, crate="lengsuo-fake") -> None:
    """最小可判定树：登记清单 + run_reference_tests 源码 + crates/。"""
    write(root, "scripts/reference_manifest.json",
          json.dumps({"tests": manifest_tests or []}))
    write(root, "scripts/run_reference_tests.py",
          "EXTRA_TESTS = {}\n".format(extra_tests or []))
    (root / "crates" / crate / "tests").mkdir(parents=True, exist_ok=True)


def violations(root: Path, exempt=guard.EXEMPT):
    return guard.find_violations(root, exempt=exempt)[2]


class GateCoverageTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="gate-cov-test-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_01_current_tree_is_clean(self):
        """当前工作树：无违规，命令行 exit 0。"""
        self.assertEqual(violations(REPO), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = guard.main(["--root", str(REPO)])
        self.assertEqual(code, 0)
        self.assertTrue(out.getvalue().startswith("登记 "), out.getvalue())
        self.assertIn("OK：无「用参考却未登记」的 target", out.getvalue())

    def test_02_unregistered_reference_target_is_reported(self):
        """假树：用了 LENGSUO_XRAY 却不在登记集 ⇒ 函数返回该违规。"""
        make_tree(self.root)
        write(self.root, "crates/lengsuo-fake/tests/bogus.rs",
              'fn main() { let _ = std::env::var("LENGSUO_XRAY"); }\n')
        result = violations(self.root)
        self.assertEqual(
            [(v["crate"], v["target"]) for v in result],
            [("lengsuo-fake", "bogus")])
        self.assertTrue(result[0]["evidence"].endswith("tests/bogus.rs:1"),
                        result[0]["evidence"])

    def test_03_exempt_target_is_not_reported(self):
        """同一违规 target 进豁免清单 ⇒ 不再报违规。"""
        make_tree(self.root)
        write(self.root, "crates/lengsuo-fake/tests/bogus.rs",
              'fn main() { let _ = std::env::var("LENGSUO_XRAY"); }\n')
        exempt = [{"crate": "lengsuo-fake", "target": "bogus",
                   "reason": "测试用结构性豁免", "evidence": "tests/bogus.rs:1"}]
        self.assertEqual(violations(self.root, exempt=exempt), [])

    def test_04_subdir_attribution_and_comment_exclusion(self):
        """tests/<t>/mod.rs 归 <t>；`// #[ignore]` 与注释里的变量名都不算。"""
        make_tree(self.root)
        write(self.root, "crates/lengsuo-fake/tests/trunc.rs", "mod edge;\n")
        write(self.root, "crates/lengsuo-fake/tests/trunc/mod.rs",
              '#[ignore = "需要参考服务端"]\n'
              'fn probe() { let _ = std::env::var("LENGSUO_ANYTLS_SERVER"); }\n')
        # 纯注释文件：既有 `// #[ignore]`，又有注释里提到变量名 ⇒ 都不是违规。
        write(self.root, "crates/lengsuo-fake/tests/comment.rs",
              "// #[ignore]\n// 本用例不依赖 LENGSUO_XRAY，只是注释里提一句。\n"
              "fn plain() {}\n")

        self.assertEqual(guard.target_of(Path("trunc/mod.rs")), "trunc")
        self.assertTrue(guard.is_ignore_line("    #[ignore]"))
        self.assertFalse(guard.is_ignore_line("// #[ignore]"))
        self.assertFalse(guard.is_ignore_line("/// #[ignore]"))

        result = violations(self.root)
        self.assertEqual(
            [(v["crate"], v["target"]) for v in result],
            [("lengsuo-fake", "trunc")])


if __name__ == "__main__":
    unittest.main()
