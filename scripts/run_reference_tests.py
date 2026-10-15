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


def execute(manifest, work, archive, report):
    binary, checksum, version = prepare_binary(manifest, work, archive)
    report.update(archive_sha256=checksum, version=version)
    env = os.environ.copy()
    env.update(LENGSUO_XRAY=str(binary), CARGO_TARGET_DIR=str(work / "target"),
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               RUST_TEST_THREADS="1")
    cargo = os.environ.get("CARGO", "cargo")
    for case in manifest["tests"]:
        command = [cargo, "test", "-p", case["crate"], "--locked"]
        for target in case["targets"]:
            command.extend(["--test", target])
        command.extend(["--", "--ignored", "--nocapture"])
        entry = {"crate": case["crate"], "command": command,
                 "expected_passed": case["expected_passed"]}
        report["results"].append(entry)
        log = work / (case["crate"] + ".log")
        try:
            result = subprocess.run(command, cwd=ROOT, env=env,
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
