#!/usr/bin/env python3
"""固定参考夹具的自助获取：下载官方发布包、校验固定哈希、拒绝符号链接与未知成员。

门禁的每个参考（Xray、AnyTLS、wireguard-go）都必须能在一台只装了
git / python / cargo / go 的干净机器上自助取齐；取不齐一律显式报错退出，
绝不静默跳过，也绝不把「缺失」当成通过。
"""
import hashlib
import os
import platform
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_URL = "https://github.com/{repo}/releases/download/{tag}/{asset}"


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


def _reject_symlink(path, what):
    if path.is_symlink():
        raise ValueError("拒绝符号链接" + what)


def download_verified(url, dest, expected_sha256):
    """下载官方包到 dest 并校验固定 SHA256。

    哈希不符即删除临时文件并报错；已存在且哈希正确则复用，避免重复下载。
    """
    _reject_symlink(dest, "下载目标")
    if dest.exists() and sha256(dest) == expected_sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    _reject_symlink(partial, "临时文件")
    with urllib.request.urlopen(url, timeout=180) as response:
        with partial.open("wb") as output:
            shutil.copyfileobj(response, output)
    if sha256(partial) != expected_sha256:
        partial.unlink(missing_ok=True)
        raise ValueError("官方参考包 SHA256 不匹配：" + url)
    partial.replace(dest)
    return dest


def prepare_xray(manifest, work, archive):
    """准备固定 Xray 参考：校验官方包哈希，只取清单指定的单个可执行成员。"""
    selected = manifest["platforms"][platform_key()]
    if archive is None:
        archive = download_verified(
            RELEASE_URL.format(repo="XTLS/Xray-core", tag=manifest["tag"],
                               asset=selected["asset"]),
            work / selected["asset"], selected["sha256"])
    else:
        archive = archive.resolve(strict=True)
        if sha256(archive) != selected["sha256"]:
            raise ValueError("参考包 SHA256 不匹配")
    binary = work / selected["binary"]
    _reject_symlink(binary, "可执行目标")
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


def prepare_anytls(manifest, work):
    """准备 AnyTLS 参考：官方 anytls-go 发布包按固定哈希校验后只取两个可执行成员。

    查找顺序：LENGSUO_ANYTLS / LENGSUO_ANYTLS_SERVER 环境变量（研究机上的既有
    固定夹具）→ ~/ref/bin/anytls 既有夹具 → 自助下载。既有夹具同样按固定
    版本目录名限定，取用前逐一确认文件存在。
    """
    override_client = os.environ.get("LENGSUO_ANYTLS")
    override_server = os.environ.get("LENGSUO_ANYTLS_SERVER")
    if override_client and override_server:
        client = Path(override_client)
        server = Path(override_server)
        if client.is_dir():
            server = client / "anytls-server"
            client = client / "anytls-client"
        if client.is_file() and server.is_file():
            return client, server

    home = Path.home() / "ref" / "bin" / "anytls"
    home_client = home / "anytls-client"
    home_server = home / "anytls-server"
    if home_client.is_file() and home_server.is_file():
        return home_client, home_server

    spec = manifest["anytls"]
    selected = spec["platforms"][platform_key()]
    archive = download_verified(
        RELEASE_URL.format(repo=spec["repo"], tag=spec["tag"],
                           asset=selected["asset"]),
        work / selected["asset"], selected["sha256"])
    out_dir = work / "anytls"
    out_dir.mkdir(parents=True, exist_ok=True)
    # 落盘名固定为**无扩展名**的 anytls-client / anytls-server：
    # 仓内测试用 `dir.join("anytls-server")` 定位夹具（不带 .exe），
    # Windows 上若落盘为 `anytls-server.exe` 则 `fs::read` 找不到文件。
    # Windows 的 CreateProcess 对无扩展名的 PE 仍可执行（已实测），
    # 因此统一用无扩展名落盘，两个平台的定位语义一致。
    client = out_dir / "anytls-client"
    server = out_dir / "anytls-server"
    with zipfile.ZipFile(archive) as source:
        for member, target in ((selected["client_member"], client),
                               (selected["server_member"], server)):
            _reject_symlink(target, "参考可执行目标")
            target.write_bytes(source.read(member))
    for target in (client, server):
        if platform_key() == "linux":
            target.chmod(0o755)
    return client, server


def prepare_wireguard_source(manifest, work):
    """准备官方 wireguard-go 检出：按清单固定 commit 浅克隆并核对 HEAD。

    环境变量 LENGSUO_WG_SOURCE 可指向既有检出（研究机上的 ~/ref/wireguard-go），
    但仍须核对 HEAD 与固定基线一致，绝不因为「本地已存在」就跳过校验。
    """
    spec = manifest["wireguard_go"]
    override = os.environ.get("LENGSUO_WG_SOURCE")
    if override:
        checkout = Path(override)
    else:
        home = Path.home() / "ref" / "wireguard-go"
        checkout = home if (home / ".git").is_dir() else work / "wireguard-go"
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("缺少 git：wireguard-go 参考检出需要 git")
    if not (checkout / ".git").is_dir():
        checkout.mkdir(parents=True, exist_ok=True)
        steps = [
            [git, "init", "-q", "."],
            [git, "remote", "add", "origin", spec["repo"]],
            [git, "fetch", "-q", "--depth", "1", "origin", spec["commit"]],
            [git, "checkout", "-q", "FETCH_HEAD"],
        ]
        for command in steps:
            result = subprocess.run(command, cwd=str(checkout), capture_output=True,
                                    text=True, encoding="utf-8", errors="replace",
                                    timeout=900)
            if result.returncode != 0:
                raise RuntimeError("准备 wireguard-go 参考检出失败（{}）：\n{}{}".format(
                    " ".join(command), result.stdout, result.stderr))
    head = subprocess.run([git, "rev-parse", "HEAD"], cwd=str(checkout),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=60, check=True).stdout.strip()
    if head != spec["commit"]:
        raise ValueError("wireguard-go 检出 commit 与固定基线不一致：{}".format(head))
    return checkout


def build_wireguard_reference(manifest, work):
    """把官方 wireguard-go 编译成参考测试二进制；缺 Go / 缺检出 / 编译失败一律报错。"""
    go = shutil.which("go")
    if go is None:
        raise RuntimeError(
            "缺少 Go 工具链（go 命令）：--test wireguard_go 需要把官方 "
            "wireguard-go 适配器编译成参考二进制，请先安装 Go 并确保其在 PATH 中")
    source = prepare_wireguard_source(manifest, work)
    adapter = ROOT / "tools" / "reference" / "wireguard_go_udp_test.go"
    if not adapter.is_file():
        raise RuntimeError("WireGuard 参考适配器不存在：{}".format(adapter))
    installed = source / "device" / "lengsuo_wg_udp_test.go"
    _reject_symlink(installed, "适配器目标")
    shutil.copyfile(adapter, installed)
    binary = work / ("wg_reference_test.exe" if platform_key() == "windows"
                     else "wg_reference_test")
    _reject_symlink(binary, "可执行目标")
    command = [go, "test", "-c", "-o", str(binary), "./device"]
    result = subprocess.run(command, cwd=str(source), capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=1800)
    if result.returncode != 0 or not binary.is_file():
        raise RuntimeError("编译 WireGuard 参考适配器失败（{}）：\n{}{}".format(
            " ".join(command), result.stdout, result.stderr))
    if platform_key() == "linux":
        binary.chmod(0o755)
    return binary
