#!/usr/bin/env python3
"""机械守卫：「用了参考二进制、却没进官方门禁」的 target 一律报红。

    python3 scripts/check_gate_coverage.py [--root DIR]

官方门禁 = `scripts/reference_manifest.json` 的 `tests[].targets`
         ∪ `scripts/run_reference_tests.py` 的 `EXTRA_TESTS[].targets`。
后者用 `ast` 取字面量（不 import，避免副作用）。

## 判据

1. 枚举 `crates/*/tests/**/*.rs`，按目录归属 target：
   `tests/<t>.rs` 与 `tests/<t>/**.rs`（`main.rs` / `cases.rs` / `mod.rs` 等
   模块文件）都归 `<t>`。只有存在 `tests/<t>.rs` 的 `<t>` 才是 cargo 集成
   测试 target；`tests/support/` 这类无同名入口的目录是支撑模块（由别的
   target 经 `#[path]` 挂载），不单独成 target，也不会被 cargo 编译。
2. 去掉行首空白后以 `#[ignore` 开头的行 = ignored 测试。`//` / `///` / `//!`
   注释行与字符串字面量天然不匹配该前缀，无需额外排除。
3. target 的**全部归属文件**里出现参考环境变量名常量 = 用了参考对端。
   注释行（`//` 开头）里提到变量名不算「用了」——注释不是依赖。
4. 用了参考却不在登记集 ⇒ 违规，exit 1。

## 豁免

`EXEMPT` 只收两类结构性不可达（① 需 root / 真设备 / Windows 管理员 / 公网
VPS；② 参考侧未开放该能力），每项必须带 `crate` / `target` / `reason` /
`evidence`。能登记的必须登记，不许拿豁免清单当垃圾桶。
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 参考对端的环境变量名常量（出现即视为依赖参考二进制）。
REF_ENV_VARS = (
    "LENGSUO_XRAY",
    "LENGSUO_ANYTLS",
    "LENGSUO_ANYTLS_SERVER",
    "LENGSUO_WG_REFERENCE_BIN",
    "LENGSUO_OBFS_VECTOR",
)

# 结构性豁免（见模块文档）。能登记的必须登记。
EXEMPT = [
    {
        "crate": "lengsuo-tun",
        "target": "node_runtime",
        "reason": "需要 root 与真实 TUN 设备（`sudo -n`），门禁机器结构性不可达",
        "evidence": "crates/lengsuo-tun/tests/node_runtime.rs:346-349 "
                    "`#[ignore = \"需要 root 与真实 TUN 设备\"]`",
    },
]


def extra_tests(path):
    """用 ast 取 `EXTRA_TESTS` 字面量；找不到即报错，绝不静默当空。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(t, ast.Name) and t.id == "EXTRA_TESTS" for t in node.targets):
            return ast.literal_eval(node.value)
    raise SystemExit("{} 里找不到 EXTRA_TESTS 字面量".format(path))


def registered(root):
    """返回 (entry 列表, {crate: set(target)})。"""
    manifest = json.loads(
        (root / "scripts" / "reference_manifest.json").read_text(encoding="utf-8"))
    entries = list(manifest["tests"]) + list(
        extra_tests(root / "scripts" / "run_reference_tests.py"))
    table = {}
    for entry in entries:
        table.setdefault(entry["crate"], set()).update(entry["targets"])
    return entries, table


def is_ignore_line(line):
    """去掉行首空白后以 `#[ignore` 开头 ⇒ 真实 ignored 测试（注释行不会匹配）。"""
    return line.lstrip(" \t").startswith("#[ignore")


def target_of(rel):
    """相对 `tests/` 的路径 → target 名：`<t>.rs` 与 `<t>/**.rs` 都归 `<t>`。"""
    name = rel.parts[0]
    return name[:-3] if len(rel.parts) == 1 and name.endswith(".rs") else name


def reference_usage(path):
    """返回该文件第一处「用了参考」的 (行号, 变量名)，没有则 None。"""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip(" \t").startswith("//"):
            continue
        for name in REF_ENV_VARS:
            if name in line:
                return number, name
    return None


def ignore_lines(path):
    return [n for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if is_ignore_line(line)]


def find_violations(root, exempt=EXEMPT):
    """扫描整棵树，返回 (entries, 登记表, 违规列表, 统计)。

    违规项含 `crate` / `target` / `evidence`（`相对路径:行号`）。
    """
    entries, table = registered(root)
    exempt_pairs = {(e["crate"], e["target"]) for e in exempt}
    state = {}  # (crate, target) -> {"used": 证据|None, "ignored": bool}
    for crate_dir in sorted((root / "crates").iterdir()):
        tests = crate_dir / "tests"
        if not tests.is_dir():
            continue
        crate = crate_dir.name
        for source in sorted(tests.rglob("*.rs")):
            rel = source.relative_to(tests)
            target = target_of(rel)
            if not (tests / (target + ".rs")).is_file():
                continue  # 支撑模块，不是 cargo 集成测试 target
            slot = state.setdefault((crate, target), {"used": None, "ignored": False})
            if not slot["ignored"] and ignore_lines(source):
                slot["ignored"] = True
            usage = reference_usage(source)
            if slot["used"] is None and usage is not None:
                slot["used"] = "{}:{}".format(
                    source.relative_to(root).as_posix(), usage[0])
    violations, ignored_used = [], []
    for (crate, target), slot in sorted(state.items()):
        if slot["used"] is None:
            continue
        if slot["ignored"]:
            ignored_used.append((crate, target))
        if target in table.get(crate, ()) or (crate, target) in exempt_pairs:
            continue
        violations.append({"crate": crate, "target": target, "evidence": slot["used"]})
    stats = {"ignored_used": ignored_used, "exempt": exempt_pairs}
    return entries, table, violations, stats


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT, help="仓库根目录（默认本仓）")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    entries, table, violations, stats = find_violations(root)
    covered = sum(len(targets) for targets in table.values())
    print("登记 {} 条 entry / 覆盖 {} 个 target".format(len(entries), covered))
    ignored = stats["ignored_used"]
    registered_pairs = {(crate, target) for crate in table for target in table[crate]}
    print("带 #[ignore] 的参考 target {} 个（登记 {} / 豁免 {} / 违规 {}）".format(
        len(ignored),
        sum(1 for pair in ignored if pair in registered_pairs),
        sum(1 for pair in ignored if pair in stats["exempt"]),
        sum(1 for item in violations if (item["crate"], item["target"]) in ignored)))
    for item in violations:
        print("{}/{}  {}".format(item["crate"], item["target"], item["evidence"]))
    if not violations:
        print("OK：无「用参考却未登记」的 target")
        return 0
    sys.stdout.flush()
    print("违规 {} 个：用了参考对端却不在官方门禁登记集里".format(len(violations)),
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
