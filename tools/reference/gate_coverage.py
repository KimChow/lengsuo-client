#!/usr/bin/env python3
"""门禁覆盖差集：枚举 `crates/*/tests/*.rs`，减去两轮门禁清单。

两轮门禁清单的来源（只读，本脚本**不写**门禁清单）：
  - 参考轮：`scripts/reference_manifest.json` 的 `tests[]`
    + `scripts/run_reference_tests.py` 的 `EXTRA_TESTS`
  - 基线轮：`scripts/baseline_manifest.json`

输出每个 crate 的：test target 总数 / 参考轮已登记 / 基线轮已登记 / 未登记清单。
未登记 = 有实跑但不在任何一轮门禁 ⇒ 本仓既有覆盖缺口。

用法
----
    python3 tools/reference/gate_coverage.py [仓库根] [--json <输出路径>]
                                       [--only-crate <crate>] [--list-targets]

退出码：0 = 正常出报告；2 = 参数/仓库结构不对。
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path


def _parse_extra_tests(script_path: Path) -> list[dict]:
    """从 `run_reference_tests.py` 里静态取出 `EXTRA_TESTS` 字面量。

    用 AST 取常量而不是执行脚本 —— 执行会拉起参考夹具下载；本工具要能在
    离线机器上跑。取不到就抛错，不静默返回空列表（否则差集会虚高）。
    """
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "EXTRA_TESTS" not in names:
            continue
        value = ast.literal_eval(node.value)
        if not isinstance(value, list):
            raise ValueError("EXTRA_TESTS 不是列表字面量")
        return value
    raise ValueError("在 {} 里找不到 EXTRA_TESTS 赋值".format(script_path))


def _targets_of(entries) -> dict[str, set[str]]:
    """`[{"crate": ..., "targets": [...]}]` ⇒ `{crate: {target, ...}}`"""
    out: dict[str, set[str]] = {}
    for entry in entries:
        crate = entry["crate"]
        out.setdefault(crate, set()).update(entry.get("targets", []))
    return out


def _discover_targets(root: Path) -> dict[str, list[str]]:
    """`crates/*/tests/*.rs` ⇒ `{crate: [target, ...]}`（按名排序）。

    只认顶层 `tests/*.rs`：`tests/<dir>/` 下的是模块辅助目录（`support/`、
    `vectors/` 等），不是独立 test target ⇒ 不计入。
    """
    out: dict[str, list[str]] = {}
    crates_dir = root / "crates"
    if not crates_dir.is_dir():
        raise FileNotFoundError("找不到 crates 目录：{}".format(crates_dir))
    for crate_dir in sorted(crates_dir.iterdir()):
        tests_dir = crate_dir / "tests"
        if not tests_dir.is_dir():
            continue
        targets = sorted(p.stem for p in tests_dir.glob("*.rs") if p.is_file())
        if targets:
            out[crate_dir.name] = targets
    return out


def collect(root: Path) -> dict:
    scripts = root / "scripts"
    reference_manifest = json.loads(
        (scripts / "reference_manifest.json").read_text(encoding="utf-8"))
    baseline_manifest = json.loads(
        (scripts / "baseline_manifest.json").read_text(encoding="utf-8"))
    extra_tests = _parse_extra_tests(scripts / "run_reference_tests.py")

    # 参考轮 = manifest 的 tests[] ∪ EXTRA_TESTS；同一 crate 两处都有条目时
    # 必须**取并集**（`update` 会整块覆盖，hysteria 会从 4 个 target 缩成 1 个）。
    reference = _targets_of(reference_manifest.get("tests", []))
    for crate, targets in _targets_of(extra_tests).items():
        reference.setdefault(crate, set()).update(targets)
    baseline = _targets_of(baseline_manifest)

    discovered = _discover_targets(root)
    crates = {}
    for crate, targets in discovered.items():
        ref = sorted(reference.get(crate, set()))
        base = sorted(baseline.get(crate, set()))
        registered = set(ref) | set(base)
        missing = [t for t in targets if t not in registered]
        crates[crate] = {
            "targets": targets,
            "reference": ref,
            "baseline": base,
            "unregistered": missing,
            "unregistered_count": len(missing),
        }
    return {
        "root": str(root),
        "crates": crates,
        "totals": {
            "targets": sum(len(c["targets"]) for c in crates.values()),
            "unregistered": sum(c["unregistered_count"] for c in crates.values()),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="仓库根（默认当前目录）")
    parser.add_argument("--json", type=Path, help="把完整结果写成 JSON")
    parser.add_argument("--only-crate", action="append", default=None,
                        help="只看某个 crate（可重复）")
    parser.add_argument("--list-targets", action="store_true",
                        help="逐条打印未登记 target")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not (root / "scripts" / "reference_manifest.json").is_file():
        print("错误：{} 不是仓库根（缺 scripts/reference_manifest.json）".format(root),
              file=sys.stderr)
        return 2
    try:
        report = collect(root)
    except Exception as error:  # noqa: BLE001 - 显式报错退出，不吞异常
        print("错误：差集计算失败：{}".format(error), file=sys.stderr)
        return 2

    wanted = set(args.only_crate or [])
    print("仓库：{}".format(root))
    header = "{:<28} {:>7} {:>7} {:>7} {:>7}".format(
        "crate", "tests", "参考", "基线", "未登记")
    print(header)
    print("-" * len(header))
    total = 0
    for crate, info in sorted(report["crates"].items()):
        if wanted and crate not in wanted:
            continue
        total += info["unregistered_count"]
        print("{:<28} {:>7} {:>7} {:>7} {:>7}".format(
            crate, len(info["targets"]), len(info["reference"]),
            len(info["baseline"]), info["unregistered_count"]))
        if args.list_targets and info["unregistered"]:
            for target in info["unregistered"]:
                print("    - {}".format(target))
    print("-" * len(header))
    print("合计：targets {}，未登记 {}".format(
        report["totals"]["targets"], report["totals"]["unregistered"]))
    if wanted:
        print("（过滤后）未登记 {}".format(total))

    if args.json:
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print("JSON：{}".format(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
