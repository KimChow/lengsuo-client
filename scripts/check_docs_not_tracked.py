"""检查仓库的 `docs/` 是否真的「只留本地、不入库」。

规则来源：各仓 `AGENTS.md` 的「文档放置规则」段。三个判据：

1. **索引为空**：`git ls-files docs` 必须没有输出（docs/ 未被跟踪）。
2. **历史无残留**：`git rev-list --all --objects` 里不得出现 ` docs/` 路径
   （历史提交曾带过 docs ⇒ 别人 clone 下来仍能翻出旧版本）。
3. **工作区干净**：`git status --porcelain docs` 必须为空
   （有输出说明有 docs 文件被误加进暂存区或被改动追踪）。

用法
----
    python tools/check_docs_not_tracked.py [--repo <path>] [--allow-history]

    --allow-history   只查索引与工作区，跳过历史检查（历史重写未完成时用）

退出码：0 = 通过；1 = 有问题；2 = 脚本自身错误。
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(repo: Path, args: list[str], timeout: int = 600) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args,
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout


def check(repo: Path, allow_history: bool) -> int:
    if not (repo / ".git").exists():
        print("错误：%s 不是 git 仓库" % repo, file=sys.stderr)
        return 2

    rc, tracked = run(repo, ["ls-files", "docs"])
    if rc != 0:
        print("错误：git ls-files 失败", file=sys.stderr)
        return 2
    tracked = [l for l in tracked.splitlines() if l.strip()]

    rc, status = run(repo, ["status", "--porcelain", "docs"])
    if rc != 0:
        print("错误：git status 失败", file=sys.stderr)
        return 2
    dirty = [l for l in status.splitlines() if l.strip()]

    history_files: list[str] = []
    if not allow_history:
        rc, objs = run(repo, ["rev-list", "--all", "--objects"])
        if rc != 0:
            print("错误：git rev-list 失败", file=sys.stderr)
            return 2
        for line in objs.splitlines():
            # 格式：<sha> <path>；只带路径的行才是带路径的对象
            if " " in line and " docs/" in line:
                history_files.append(line.split(" ", 1)[1])

    failed = False

    if tracked:
        failed = True
        print("✘ 索引里仍有 %d 个 docs 文件（应取消跟踪）：" % len(tracked))
        for f in tracked[:10]:
            print("    %s" % f)
        if len(tracked) > 10:
            print("    ... 其余 %d 个" % (len(tracked) - 10))
        print("  修复：git rm -r --cached docs")
    else:
        print("✔ 索引无 docs 跟踪")

    if dirty:
        failed = True
        print("✘ 工作区有 %d 项 docs 变动（不应被 git 跟踪）：" % len(dirty))
        for f in dirty[:10]:
            print("    %s" % f)
    else:
        print("✔ 工作区无 docs 变动")

    if allow_history:
        print("– 历史检查已跳过（--allow-history）")
    elif history_files:
        failed = True
        print("✘ git 历史里仍有 %d 个 docs 对象（clone 下来仍能翻出旧版）："
              % len(history_files))
        for f in history_files[:10]:
            print("    %s" % f)
        if len(history_files) > 10:
            print("    ... 其余 %d 个" % (len(history_files) - 10))
        print("  修复：用 rewrite_identity.py --drop-path docs 重写历史")
    else:
        print("✔ git 历史无 docs 残留")

    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".", help="仓库路径（默认当前目录）")
    ap.add_argument("--allow-history", action="store_true",
                    help="跳过历史检查")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    print("检查仓库：%s" % repo)
    code = check(repo, args.allow_history)
    print("结果：%s" % ("通过" if code == 0 else "不通过"))
    return code


if __name__ == "__main__":
    sys.exit(main())
