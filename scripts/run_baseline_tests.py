#!/usr/bin/env python3
"""基线轮门禁：把「Rust↔Rust 全链路互通」纳入官方验收（ALL-1 审计 P0-1）。

`run_reference_tests.py` 只跑 `-- --ignored`（参考互通方向）；八协议的
Rust↔Rust 互通用例是普通 `#[test]`，此前从未被任何门禁验证。本脚本按
`scripts/baseline_manifest.json` 的登记逐 crate 实跑默认套件（不带
`--ignored`），实际 passed 必须等于 `expected_passed`，否则非 0 退出。

与 reference 轮的关系：独立清单、独立计数、独立退出码；两脚本串跑即
「参考方向 + 回环方向」全闸。产物（报告/日志/target）一律写在仓外。
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def check_prerequisites(manifest):
    problems = []
    for case in manifest:
        crate_dir = ROOT / "crates" / case["crate"]
        for target in case["targets"]:
            if not (crate_dir / "tests" / (target + ".rs")).is_file():
                problems.append(
                    "测试目标不存在：crates/{}/tests/{}.rs（{} 需要）".format(
                        case["crate"], target, case["crate"]))
    if problems:
        raise RuntimeError("基线清单前置检查失败：" + "；".join(problems))


def execute(manifest, work):
    report = {"results": [], "success": False}
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(work / "target"),
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
               CARGO_TERM_COLOR="never", CARGO_PROFILE_TEST_DEBUG="0",
               RUST_TEST_THREADS="1")
    cargo = os.environ.get("CARGO", "cargo")
    for case in manifest:
        command = [cargo, "test", "-p", case["crate"], "--locked"]
        for target in case["targets"]:
            command.extend(["--test", target])
        # 不带 --ignored：普通用例全跑，参考互通用例自动跳过。
        command.extend(["--", "--nocapture"])
        entry = {"crate": case["crate"], "command": command,
                 "expected_passed": case["expected_passed"]}
        report["results"].append(entry)
        log = work / (case["crate"] + ".log")
        result = subprocess.run(command, cwd=ROOT, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=600)
        log.write_text(result.stdout, encoding="utf-8")
        passed = sum(int(count) for count in re.findall(
            r"test result: ok\. (\d+) passed;", result.stdout))
        entry.update(exit_code=result.returncode, passed=passed,
                     log=log.name)
        print(case["crate"], "exit", result.returncode, "passed", passed,
              flush=True)
        if result.returncode != 0 or passed != case["expected_passed"]:
            raise RuntimeError(
                "基线失败或实际通过数量与清单不一致：" + case["crate"])
    report["success"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    if not args.work_dir.is_absolute():
        parser.error("--work-dir 必须是绝对路径")
    work = args.work_dir.resolve()
    if work == ROOT or ROOT in work.parents:
        parser.error("报告、日志与构建产物必须在仓库外")
    work.mkdir(parents=True, exist_ok=True)
    manifest_path = ROOT / "scripts/baseline_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=True)
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                           capture_output=True, text=True, check=True)
    report = {"started_utc": datetime.now(timezone.utc).isoformat(),
              "git_commit": revision.stdout.strip(),
              "working_tree_dirty": bool(dirty.stdout.strip()),
              "results": [], "success": False}
    try:
        check_prerequisites(manifest)
        report.update(execute(manifest, work))
    except Exception as error:
        report["error"] = str(error)
        print("基线检查失败：", error, file=sys.stderr)
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (work / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
