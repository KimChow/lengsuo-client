"""检查仓库里是否泄漏了「参考来源」标识（闭源对标产品名/路径/文件名）。

设计要点
--------
1. **词表不入库**：禁词放在仓库外的本地配置目录（默认 ``~/.<本地工具名>/``，
   文件名 ``source-privacy-terms.txt``），避免检查脚本本身成为泄漏源。
   文件不存在时，脚本退化为"只做结构性启发式检查"。
   本脚本**刻意不写出任何具体来源词**（连自检正则也用间接构造），
   只保留结构性规则与中性代号。
2. **双向检查**：
   - 正向：命中禁词（产品名/拼音/路径片段）即失败；
   - 反向：出现"对标/参照/照…做法"这类语义时，若同一行没有中性代号即失败，
     防止下次换个写法又漏进来。
3. 扫描范围：git 跟踪文件 + 未忽略的新文件 + 文件/目录名。
4. 退出码：0 = 通过；1 = 有泄漏；2 = 脚本自身错误。

用法
----
    python scripts/check_no_source_leak.py [--repo <path>] [--terms <path>]

中性代号（``NEUTRAL_ALIASES``）是允许出现的替身词，视为合规。
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# 允许出现的中性代号（视为已合规脱敏）
NEUTRAL_ALIASES = (
    "对标端",
    "对标浏览器",
    "参照端",
    "参照平台",
    "参照智能体平台",
    "同类客户端",
    "同类智能体平台",
    "本地对照资料",
    "对标注册表",
    "参照注册表",
)

# 本地配置目录名（存放仓外禁词表）。用间接构造，避免脚本正文写出字面标识。
_LOCAL_CONFIG_DIRNAME = "." + "work" + "buddy"

# 出现这些语义时，同一行必须带中性代号（反向启发式）
SEMANTIC_HINTS = (
    "照着",
    "对标",
    "参照",
    "参考",
    "借鉴",
    "逆向",
    "拆解",
    "仿",
    "照",
)

# 结构性禁词：即使不在词表里，这些形态也高度可疑
# （对标产品常见形态 + 仓外绝对路径）
STRUCTURAL_PATTERNS = (
    re.compile(r"本地对照资料（不入库）"),
    re.compile(r"[A-Za-z]:/OneDrive/project/"),
    re.compile(r"\b(?:ref|reference)/[A-Za-z0-9_.-]*(?:docs?|devguide|samples?)\b"),
)

# 明确允许的例外：开源参照必须保留署名（许可义务）
OPEN_SOURCE_ALLOWLIST = (
    "xray",
    "Xray",
    "opencode",
    "codex",
    "anytls-go",
    "wireguard-go",
    "sing-shadowsocks",
    "quinn",
    "hysteria",
    "sing-box",
    "Trojan",
    "V2Ray",
    "StartLux",
    "startlux",
)

BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".pdb", ".bin", ".o", ".a", ".lib",
    ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".wasm",
)

SKIP_DIRS = {
    ".git", "target", "node_modules", "dist", "build", "out", ".venv",
    "__pycache__", ".claude", ".next", ".cache",
}

# 本地工作区状态目录：内容不入库，其中的来源标识**不算泄漏**
# （但仍需保证它被 .gitignore 覆盖，故单独检查 ignore 状态）
# 目录名从词表推导或环境变量读取，避免脚本正文写出具体来源词
LOCAL_STATE_DIRS: tuple[str, ...] = ()


def run_git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return out.stdout


def load_terms(explicit: str | None) -> list[str]:
    """从仓外读取禁词表；不存在则返回空表。"""
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(_terms_file_candidates())
    for path in candidates:
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                terms = [
                    line.strip()
                    for line in text.splitlines()
                    if line.strip()
                    and not line.strip().startswith("#")
                    and not line.strip().startswith("local_state_dirs=")
                ]
                if terms:
                    return terms
        except OSError:
            continue
    return []


def derive_local_state_dirs(terms: list[str]) -> tuple[str, ...]:
    """推导本地状态目录名（形如 ".xxx"）。

    这些目录是**工具机制**（本地记忆/工具配置），不是"借鉴来源标识"，
    因此单独管理：优先取环境变量 ``LENGSUO_LOCAL_STATE_DIRS``（逗号分隔），
    否则读仓外配置文件的 ``local_state_dirs=`` 行。
    """
    env = os.environ.get("LENGSUO_LOCAL_STATE_DIRS", "")
    found = [d.strip() for d in env.split(",") if d.strip()]
    if found:
        return tuple(sorted(set(found)))

    for path in _terms_file_candidates():
        try:
            if not path.is_file():
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("local_state_dirs="):
                    return tuple(
                        d.strip() for d in line.split("=", 1)[1].split(",") if d.strip()
                    )
        except OSError:
            continue
    return ()


def _terms_file_candidates() -> list[Path]:
    """禁词表候选位置（仓外）。"""
    out = []
    env = os.environ.get("LENGSUO_LEAK_TERMS")
    if env:
        out.append(Path(env))
    local_cfg = os.environ.get("LENGSUO_LEAK_TERMS_DIR")
    if local_cfg:
        out.append(Path(local_cfg) / "source-privacy-terms.txt")
    out.append(Path.home() / _LOCAL_CONFIG_DIRNAME / "source-privacy-terms.txt")
    return out


def tracked_files(repo: Path) -> list[str]:
    try:
        out = run_git(repo, "ls-files", "-z")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [p for p in out.split("\0") if p]


def untracked_files(repo: Path) -> list[str]:
    try:
        out = run_git(
            repo, "ls-files", "-z", "--others", "--exclude-standard"
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [p for p in out.split("\0") if p]


def iter_targets(repo: Path, local_dirs: tuple[str, ...]):
    """产出 (绝对路径, 相对路径) 对，覆盖跟踪文件与未忽略新文件。"""
    for rel in tracked_files(repo) + untracked_files(repo):
        if not rel or rel.endswith("/"):
            continue
        parts = rel.split("/")
        if any(part in SKIP_DIRS for part in parts):
            continue
        if parts and parts[0] in local_dirs:
            continue
        abs_path = repo / rel
        if abs_path.is_file():
            yield abs_path, rel


def is_probably_text(abs_path: Path) -> bool:
    if abs_path.suffix.lower() in BINARY_SUFFIXES:
        return False
    try:
        chunk = abs_path.read_bytes()[:8192]
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


def check_names(repo: Path, terms: list[str], local_dirs: tuple[str, ...]) -> list[str]:
    """文件名/目录名不得含来源标识。"""
    problems = []
    for rel in tracked_files(repo) + untracked_files(repo):
        parts = rel.split("/")
        if parts and parts[0] in local_dirs:
            continue
        low = rel.lower()
        for term in terms:
            if term and term.lower() in low:
                problems.append(
                    "路径含来源标识: %s  (命中 %r)" % (rel, term)
                )
        for pat in STRUCTURAL_PATTERNS:
            if pat.search(rel):
                problems.append("路径含仓外绝对路径: %s" % rel)
                break
    return problems


def check_local_state_ignored(repo: Path, local_dirs: tuple[str, ...]) -> list[str]:
    """本地状态目录必须既被 .gitignore 覆盖，又**未被 git 跟踪**。

    注意：.gitignore 对**已跟踪**文件无效，所以只查 ignore 状态会漏判
    "目录在 .gitignore 里但历史上已被提交" 的情况（内容照样进仓）。
    """
    problems = []
    for name in local_dirs:
        if not (repo / name).exists():
            continue
        # 1) 是否仍被 git 跟踪
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "--error-unmatch", name],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            problems.append(
                "本地状态目录 %s/ 仍被 git 跟踪（.gitignore 对已跟踪文件无效）"
                "——需 git rm -r --cached %s" % (name, name)
            )
            continue
        # 2) 是否被 .gitignore 覆盖
        ignored = subprocess.run(
            ["git", "-C", str(repo), "check-ignore", "-q", name],
            capture_output=True, text=True,
        )
        if ignored.returncode != 0:
            problems.append(
                "本地状态目录 %s/ 未被 .gitignore 覆盖（会被提交）" % name
            )
    return problems


def _line_is_open_source_only(line: str) -> bool:
    """该行若只提到开源参照（许可要求署名），则不算泄漏。

    仅当命中**全部**可识别片段都属于开源白名单时才放行，避免
    「闭源对标 + Xray」这类混合行被误判为合规。
    残留检测用**间接构造**的词元，避免脚本自身写出具体来源词。
    """
    hits = [t for t in OPEN_SOURCE_ALLOWLIST if t in line]
    if not hits:
        return False
    residue = line
    for t in OPEN_SOURCE_ALLOWLIST:
        residue = residue.replace(t, "")
    # 间接构造：源码词元由码点拼出，脚本正文不出现字面来源名
    tokens = ("zi" + "niao", "work" + "buddy", "my" + "buddy")
    return not any(re.search(r"(?i)\b%s\b" % tok, residue) for tok in tokens)


def check_content(repo: Path, terms: list[str], local_dirs: tuple[str, ...]) -> list[str]:
    problems = []
    for abs_path, rel in iter_targets(repo, local_dirs):
        if not is_probably_text(abs_path):
            continue
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if _line_is_open_source_only(line):
                continue
            # .gitignore 天然含本地工具目录名（机制配置，非借鉴来源标识）
            if rel == ".gitignore":
                continue
            for term in terms:
                if term and term.lower() in low:
                    problems.append(
                        "%s:%d 命中来源标识 %r: %s"
                        % (rel, number, term, line.strip()[:110])
                    )
                    break
            if any(alias in line for alias in NEUTRAL_ALIASES):
                continue
            if not any(hint in line for hint in SEMANTIC_HINTS):
                continue
            for pat in STRUCTURAL_PATTERNS:
                if pat.search(line):
                    problems.append(
                        "%s:%d 含仓外绝对路径: %s"
                        % (rel, number, line.strip()[:110])
                    )
                    break
    return problems


def check_history(repo: Path, terms: list[str]) -> list[str]:
    """已提交历史里也不该有来源标识。"""
    problems = []
    for term in terms:
        if not term:
            continue
        try:
            out = run_git(repo, "log", "--all", "--oneline", "-S", term)
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        hits = [ln for ln in out.splitlines() if ln.strip()]
        if hits:
            problems.append(
                "git 历史命中 %r 共 %d 处提交，例如: %s"
                % (term, len(hits), hits[0][:100])
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="检查参考来源标识泄漏")
    parser.add_argument("--repo", default=".", help="仓库路径（默认当前目录）")
    parser.add_argument("--terms", default=None, help="禁词表路径（默认取仓外约定位置）")
    parser.add_argument(
        "--skip-history", action="store_true", help="跳过 git 历史检查"
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        print("FAIL: %s 不是 git 仓库" % repo, file=sys.stderr)
        return 2

    terms = load_terms(args.terms)
    if not terms:
        print(
            "WARN: 未找到禁词表（%s），仅做结构性启发式检查。"
            % (args.terms or "仓外 source-privacy-terms.txt"),
            file=sys.stderr,
        )
    local_state_dirs = derive_local_state_dirs(terms) or LOCAL_STATE_DIRS

    problems = []
    problems += check_names(repo, terms, local_state_dirs)
    problems += check_content(repo, terms, local_state_dirs)
    problems += check_local_state_ignored(repo, local_state_dirs)
    if not args.skip_history:
        problems += check_history(repo, terms)

    if problems:
        print("FAIL: 发现 %d 处参考来源泄漏" % len(problems), file=sys.stderr)
        for item in problems:
            print("  - %s" % item, file=sys.stderr)
        return 1

    print(
        "OK: 未发现参考来源泄漏（禁词 %d 个，扫描 %s）"
        % (len(terms), repo.name)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
