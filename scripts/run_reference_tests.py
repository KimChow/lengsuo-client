#!/usr/bin/env python3
"""显式执行固定参考矩阵，校验官方包并拒绝零用例成功；产物必须在仓库外。"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reference_fixtures as fixtures

platform_key = fixtures.platform_key

ROOT = Path(__file__).resolve().parents[1]

# 清单文件（reference_manifest.json）由基建卡独占维护，本卡新增条目就地登记，
# 语义与清单一致：实际 passed 必须等于 expected_passed，否则非 0 退出。
# AnyTLS / wireguard-go 参考夹具由 reference_fixtures.py 自助取齐（固定哈希 /
# 固定 commit 校验），干净机器上无需预置 ~/ref；环境变量仍可覆盖为既有夹具。
EXTRA_TESTS = [
    {"crate": "lengsuo-vmess",
     "targets": ["xray_tcp", "xray_vmess_server", "xray_udp", "xray_mux",
                 "xray_multitier", "xray_multitier_server"],
     "expected_passed": 24},
    # AnyTLS：Windows 上 `interop_udp` 的 2 个用例**不编译**——官方 anytls-go
    # v0.0.13 服务端在该平台自身崩溃（上游缺陷，见 docs/anytls-status.md
    # 偏离清单「平台差异」条）。按平台如实登记通过数，**不冒充通过**。
    # `tamper_matrix` 的 3 条参考对端用例走**官方 anytls-server 的 TCP 路径**
    # （篡改认证块 / 命令字节 / 长度字段），不经过 UDP 路径 ⇒ 不受上述上游
    # 缺陷影响，与 Linux 同数。
    {"crate": "lengsuo-anytls",
     "targets": ["interop_client", "interop_server", "interop_udp", "interop",
                 "lifecycle", "tamper_matrix"],
     "expected_passed": 12, "requires_commands": ["openssl"],
     "expected_passed_by_platform": {"windows": 10}},
    # hysteria 混淆（ Salamander）互通：需要**参考生成的确定性向量**做逐字节对照。
    # 生成器已收进仓内 tools/reference/gen_salamander_vector.py（纯 Python，
    # 只依赖 hashlib），因此门禁可自洽生成，不依赖仓外夹具。
    {"crate": "lengsuo-hysteria",
     "targets": ["xray_hysteria_obfs"],
     "expected_passed": 2,
     "env": {"LENGSUO_OBFS_VECTOR": "@@SALAMANDER_VECTOR@@"}},
    # hysteria Salamander 混淆互通：需参考 Xray（Salamander + 端口跳跃），
    # 已实跑通过 4 个用例，补登记。
    {"crate": "lengsuo-hysteria",
     "targets": ["obfs_hop_wire"],
     "expected_passed": 4},
    # hysteria 0-RTT：参考 Xray 作服务端，本仓客户端两次建连的 0-RTT 取证。
    # 实跑日志显示参考侧早数据上限为 0（回退 1-RTT），用例按该结果断言并
    # 通过 1 个用例，补登记。
    {"crate": "lengsuo-hysteria",
     "targets": ["zero_rtt"],
     "expected_passed": 1},
    # vless Vision 响应头与参考 Xray 逐字节互通：已实跑通过 1 个用例，补登记。
    {"crate": "lengsuo-vless",
     "targets": ["vision_wire"],
     "expected_passed": 1},
    # vless XEL 二进制协议与参考 Xray 的拒收/接受取证：已实跑通过 2 个用例，补登记。
    {"crate": "lengsuo-vless",
     "targets": ["xel_wire"],
     "expected_passed": 2},
    # vless 传输（WS/HTTPUpgrade）与参考 Xray 双向互通：已实跑通过 4 个用例，补登记。
    {"crate": "lengsuo-vless",
     "targets": ["vless_transport"],
     "expected_passed": 4},
    # AnyTLS UDP-over-TCP 服务端：官方 anytls-client ↔ 本仓服务端，已实跑通过
    # 1 个用例，需 openssl，补登记。
    {"crate": "lengsuo-anytls",
     "targets": ["udp_over_tcp_server"],
     "expected_passed": 1, "requires_commands": ["openssl"]},
    # vmess 安全档位矩阵与参考 Xray 的档位互通/拒收：已实跑通过 3 个用例，
    # 补登记。
    {"crate": "lengsuo-vmess",
     "targets": ["security_matrix_extra"],
     "expected_passed": 3},
    # 跳过登记：lengsuo-tun node_runtime —— 需 root 与真实 TUN 设备（`sudo -n`），
    # 门禁机器无此环境，实跑以 exit 101 收场，结构性不可达，不登记。
    # 证据：crates/lengsuo-tun/tests/node_runtime.rs:346-349
    # `#[ignore = "需要 root 与真实 TUN 设备"]`。
    #
    # 非候选（不登记）：`tests/support/` 与 `tests/xray_mux_helpers/` 是 support
    # 模块（顶层无同名 .rs 测试入口，cargo 不会把它们当 target）；
    # `tests/reality_main_link.rs` 无 `#[ignore]` 且只做本仓回环，不在
    # 「带参考对端但未进门禁」之列。
]


# hysteria 混淆（Salamander）互通条目需要**参考生成的确定性向量**做逐字节对照。
# 生成器已收进仓内 tools/reference/gen_salamander_vector.py（纯 Python，只依赖
# hashlib），因此门禁可自洽生成，不依赖仓外夹具 —— 与 WireGuard 适配器同一范式。
SALAMANDER_GENERATOR = ROOT / "tools" / "reference" / "gen_salamander_vector.py"


def build_salamander_vectors(work):
    """生成 Salamander 混淆的确定性参考向量文件，返回其路径。

    生成器缺失 / 执行失败 / 产物为空一律显式报错退出，绝不静默跳过，
    也不把「缺失」当通过。
    """
    if not SALAMANDER_GENERATOR.is_file():
        raise RuntimeError(
            "Salamander 向量生成器不存在：{}（--test xray_hysteria_obfs 需要）".format(
                SALAMANDER_GENERATOR))
    out_path = work / "salamander_vectors.txt"
    command = [sys.executable, str(SALAMANDER_GENERATOR), str(out_path)]
    result = subprocess.run(command, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120)
    if result.returncode != 0 or not out_path.is_file() or out_path.stat().st_size == 0:
        raise RuntimeError("生成 Salamander 参考向量失败（{}）：\n{}{}".format(
            " ".join(command), result.stdout, result.stderr))
    return out_path


# WireGuard 条目（--test wireguard_go）用官方 wireguard-go 核心当真实参考：
# 由 reference_fixtures.build_wireguard_reference 按固定 commit 检出、复制
# tools/reference/wireguard_go_udp_test.go 适配器并编译成测试二进制，再经
# LENGSUO_WG_REFERENCE_BIN 注入 cargo 子进程。缺 Go / 缺检出 / 编译失败一律
# 显式报错退出，绝不静默跳过或把缺失当通过。


def check_prerequisites(tests):
    problems = []
    for case in tests:
        for command in case.get("requires_commands", []):
            if shutil.which(command) is None:
                problems.append("缺少命令 {}（{} 需要）".format(command, case["crate"]))
        for path in case.get("requires_files", []):
            if not path.is_file():
                problems.append("参考二进制不存在：{}（{} 需要）".format(path, case["crate"]))
        # 每个 target 对应的 tests/<target>.rs 必须存在，否则 cargo 会以编译错误收场、
        # 被误读成“测试失败”。这里显式报错，缺失即退出，绝不静默跳过或降级为通过。
        crate_dir = ROOT / "crates" / case["crate"]
        for target in case["targets"]:
            if not (crate_dir / "tests" / (target + ".rs")).is_file():
                problems.append("参考测试目标不存在：crates/{}/tests/{}.rs（{} 需要）"
                                .format(case["crate"], target, case["crate"]))
    if problems:
        raise RuntimeError("参考矩阵前置检查失败：" + "；".join(problems))


def execute(manifest, work, archive, report):
    tests = manifest["tests"] + EXTRA_TESTS
    check_prerequisites(tests)
    binary, checksum, version = fixtures.prepare_xray(manifest, work, archive)
    report.update(archive_sha256=checksum, version=version)
    env = os.environ.copy()
    env.update(LENGSUO_XRAY=str(binary), CARGO_TARGET_DIR=str(work / "target"),
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               RUST_TEST_THREADS="1")
    # AnyTLS 参考夹具：固定哈希校验后取用；环境变量可指向研究机上的既有夹具。
    if any(case["crate"] == "lengsuo-anytls" for case in tests):
        anytls_client, anytls_server = fixtures.prepare_anytls(manifest, work)
        env["LENGSUO_ANYTLS"] = str(anytls_client)
        env["LENGSUO_ANYTLS_SERVER"] = str(anytls_server)
        report["anytls_reference"] = str(anytls_client)
    if any(case["crate"] == "lengsuo-wireguard" for case in tests):
        env["LENGSUO_WG_REFERENCE_BIN"] = str(
            fixtures.build_wireguard_reference(manifest, work))
    cargo = os.environ.get("CARGO", "cargo")
    for case in tests:
        command = [cargo, "test", "-p", case["crate"], "--locked"]
        for target in case["targets"]:
            command.extend(["--test", target])
        command.extend(["--", "--ignored", "--nocapture"])
        expected = case.get("expected_passed_by_platform", {}).get(
            platform_key(), case["expected_passed"])
        entry = {"crate": case["crate"], "command": command,
                 "expected_passed": expected}
        report["results"].append(entry)
        log = work / (case["crate"] + ".log")
        case_env = env.copy()
        case_env.update(case.get("env", {}))
        # 占位符替换：需要运行时生成产物的条目（如 Salamander 混淆向量）
        # 在这里注入真实路径，生成失败一律显式报错，绝不静默跳过。
        if case_env.get("LENGSUO_OBFS_VECTOR") == "@@SALAMANDER_VECTOR@@":
            case_env["LENGSUO_OBFS_VECTOR"] = str(build_salamander_vectors(work))
        try:
            result = subprocess.run(command, cwd=ROOT, env=case_env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", timeout=600)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            log.write_text(output, encoding="utf-8")
            entry.update(exit_code=None, timeout=True, log=log.name)
            raise
        log.write_text(result.stdout, encoding="utf-8")
        passed = sum(int(count) for count in re.findall(
            r"test result: ok\. (\d+) passed;", result.stdout))
        entry.update(exit_code=result.returncode, passed=passed, log=log.name)
        print(case["crate"], "exit", result.returncode, "passed", passed, flush=True)
        if result.returncode != 0 or passed != expected:
            raise RuntimeError("参考矩阵失败或实际通过数量与清单不一致：" + case["crate"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--archive", type=Path, help="复用本机已下载的官方 ZIP，仍强制校验哈希")
    args = parser.parse_args()
    if not args.work_dir.is_absolute():
        parser.error("--work-dir 必须是绝对路径")
    work = args.work_dir.resolve()
    if work == ROOT or ROOT in work.parents:
        parser.error("参考下载、日志与构建产物必须在仓库外")
    work.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "scripts/reference_manifest.json").read_text(encoding="utf-8"))
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
                           text=True, check=True).stdout
    report = {"started_utc": datetime.now(timezone.utc).isoformat(),
              "git_commit": revision, "working_tree_dirty": bool(dirty),
              "reference_commit": manifest["commit"], "results": [], "success": False}
    try:
        execute(manifest, work, args.archive, report)
        report["success"] = True
    except Exception as error:
        report["error"] = str(error)
        print("参考检查失败：", error, file=sys.stderr)
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (work / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                         encoding="utf-8")
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
