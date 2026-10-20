#!/usr/bin/env python3
"""显式执行固定参考矩阵，校验官方包并拒绝零用例成功；产物必须在仓库外。"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]

# 清单文件（reference_manifest.json）由基建卡独占维护，本卡新增条目就地登记，
# 语义与清单一致：实际 passed 必须等于 expected_passed，否则非 0 退出。
ANYTLS_HOME = Path.home() / "ref" / "bin" / "anytls"
ANYTLS_CLIENT = Path(os.environ.get("LENGSUO_ANYTLS") or ANYTLS_HOME / "anytls-client")
ANYTLS_SERVER = Path(os.environ.get("LENGSUO_ANYTLS_SERVER") or ANYTLS_HOME / "anytls-server")


def anytls_files():
    if ANYTLS_CLIENT.is_dir():
        return [ANYTLS_CLIENT / "anytls-client", ANYTLS_CLIENT / "anytls-server",
                ANYTLS_SERVER]
    return [ANYTLS_CLIENT, ANYTLS_SERVER]


EXTRA_TESTS = [
    {"crate": "lengsuo-vmess",
     "targets": ["xray_tcp", "xray_vmess_server", "xray_udp", "xray_mux",
                 "xray_multitier", "xray_multitier_server"],
     "expected_passed": 24},
    {"crate": "lengsuo-anytls",
     "targets": ["interop_client", "interop_server", "interop_udp"],
     "expected_passed": 6, "requires_commands": ["openssl"],
     "requires_files": anytls_files(),
     "env": {"LENGSUO_ANYTLS": str(ANYTLS_CLIENT),
             "LENGSUO_ANYTLS_SERVER": str(ANYTLS_SERVER)}},
]


# WireGuard 条目（--test wireguard_go）用官方 wireguard-go 核心当真实参考：跑之前
# 必须把 tools/reference/wireguard_go_udp_test.go 复制进固定的官方检出并编译成
# 测试二进制，再经 LENGSUO_WG_REFERENCE_BIN 注入 cargo 子进程。缺 Go / 缺检出 /
# 编译失败一律显式报错退出，绝不静默跳过或把缺失当通过。
WIREGUARD_ADAPTER = ROOT / "tools" / "reference" / "wireguard_go_udp_test.go"
WIREGUARD_HOME = Path.home() / "ref" / "wireguard-go"


def build_wireguard_reference(work):
    go = shutil.which("go")
    if go is None:
        raise RuntimeError(
            "缺少 Go 工具链（go 命令）：--test wireguard_go 需要把官方 "
            "wireguard-go 适配器编译成参考二进制，请先安装 Go 并确保其在 PATH 中")
    if not WIREGUARD_HOME.is_dir():
        raise RuntimeError("官方 wireguard-go 检出不存在：{}（--test wireguard_go 需要）"
                           .format(WIREGUARD_HOME))
    if not WIREGUARD_ADAPTER.is_file():
        raise RuntimeError("WireGuard 参考适配器不存在：{}".format(WIREGUARD_ADAPTER))
    installed = WIREGUARD_HOME / "device" / "lengsuo_wg_udp_test.go"
    if installed.is_symlink():
        raise ValueError("拒绝符号链接适配器目标")
    shutil.copyfile(WIREGUARD_ADAPTER, installed)
    binary = work / "wg_reference_test"
    if binary.is_symlink():
        raise ValueError("拒绝符号链接可执行目标")
    command = [go, "test", "-c", "-o", str(binary), "./device"]
    result = subprocess.run(command, cwd=str(WIREGUARD_HOME), capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=900)
    if result.returncode != 0 or not binary.is_file():
        raise RuntimeError("编译 WireGuard 参考适配器失败（{}）：\n{}{}".format(
            " ".join(command), result.stdout, result.stderr))
    binary.chmod(0o755)
    return binary


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def platform_key():
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("参考矩阵目前只核验 x86_64")
    key = platform.system().lower()
    if key not in {"linux", "windows"}:
        raise ValueError("参考矩阵目前只核验 Linux 与 Windows")
    return key


def prepare_binary(manifest, work, archive):
    selected = manifest["platforms"][platform_key()]
    if archive is None:
        archive = work / selected["asset"]
        if archive.is_symlink():
            raise ValueError("拒绝符号链接下载目标")
        if not archive.exists() or sha256(archive) != selected["sha256"]:
            url = ("https://github.com/XTLS/Xray-core/releases/download/"
                   + manifest["tag"] + "/" + selected["asset"])
            partial = work / (selected["asset"] + ".part")
            if partial.is_symlink():
                raise ValueError("拒绝符号链接临时文件")
            with urllib.request.urlopen(url, timeout=60) as response:
                with partial.open("wb") as output:
                    shutil.copyfileobj(response, output)
            if sha256(partial) != selected["sha256"]:
                raise ValueError("官方参考包 SHA256 不匹配")
            partial.replace(archive)
    else:
        archive = archive.resolve(strict=True)
    if sha256(archive) != selected["sha256"]:
        raise ValueError("参考包 SHA256 不匹配")
    binary = work / selected["binary"]
    if binary.is_symlink():
        raise ValueError("拒绝符号链接可执行目标")
    # 不解压整个 archive，只读取经过固定哈希验证的单个根目录成员。
    with zipfile.ZipFile(archive) as source:
        content = source.read(selected["binary"])
    binary.write_bytes(content)
    if platform_key() == "linux":
        binary.chmod(0o755)
    result = subprocess.run([str(binary), "version"], capture_output=True,
                            text=True, encoding="utf-8", timeout=20, check=True)
    if (manifest["tag"].removeprefix("v") not in result.stdout
            or manifest["commit"][:7] not in result.stdout):
        raise ValueError("参考二进制版本与基线不一致")
    return binary, selected["sha256"], result.stdout.strip()


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
    binary, checksum, version = prepare_binary(manifest, work, archive)
    report.update(archive_sha256=checksum, version=version)
    env = os.environ.copy()
    env.update(LENGSUO_XRAY=str(binary), CARGO_TARGET_DIR=str(work / "target"),
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               RUST_TEST_THREADS="1")
    if any(case["crate"] == "lengsuo-wireguard" for case in tests):
        env["LENGSUO_WG_REFERENCE_BIN"] = str(build_wireguard_reference(work))
    cargo = os.environ.get("CARGO", "cargo")
    for case in tests:
        command = [cargo, "test", "-p", case["crate"], "--locked"]
        for target in case["targets"]:
            command.extend(["--test", target])
        command.extend(["--", "--ignored", "--nocapture"])
        entry = {"crate": case["crate"], "command": command,
                 "expected_passed": case["expected_passed"]}
        report["results"].append(entry)
        log = work / (case["crate"] + ".log")
        case_env = env.copy()
        case_env.update(case.get("env", {}))
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
        if result.returncode != 0 or passed != case["expected_passed"]:
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
