#!/usr/bin/env python3
"""协作式本地集成，非安全沙箱；gates/hooks 具有当前用户的全部权限。

integrate(led, task) -> dict：led 为 Ledger，task 为任务名（不含 .json）。
成功 ok=True；任何失败都返回 ok=False、state=blocked/failed、gate 证据和
候选/日志路径，并且 occupied=True（占用保留，须人工处理后释放）。

root/config.json：{"gates": [["program", "arg"]], "gate_timeout": 300}。
gates 必须是非空列表；gate_timeout 是每条命令的有限正秒数，必须显式配置。
没有默认生产测试。所有命令 shell=False、带超时，不 push/reset、不禁用 hooks。

专用集成锁覆盖冻结校验、候选合并、gates、main 快进与结果记账；台账锁只在
读写状态时短暂持有。候选和日志始终保留，便于人工复核。
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from card_ledger import LedgerError, atomic_write, read_json_strict
from card_rules import worktree_fingerprint

VERIFY_TIMEOUT = 300.0
_TASK = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class ScopeError(LedgerError):
    """验收/边界失败：实质问题，标 failed 而非可重试的 blocked。"""


class StaleError(LedgerError):
    """source 或冻结值在 verify 后变化：必须重新 verify，标 failed。"""


@contextlib.contextmanager
def _integration_lock(root: Path, timeout: float = 300.0):
    """独立跨进程锁；积压的目录锁只能人工确认后清理。"""
    deadline = time.monotonic() + timeout
    if os.name == "nt":
        path = root / ".integrate.lock.d"
        while True:
            try:
                path.mkdir()
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise LedgerError("等待集成锁超时，不修改正在集成的卡")
                time.sleep(0.05)
        try:
            yield
        finally:
            path.rmdir()
    else:
        import fcntl

        with (root / ".integrate.lock").open("a") as fh:
            while True:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise LedgerError("等待集成锁超时，不修改正在集成的卡")
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)


def _env() -> dict:
    """去掉可能把 git 指向别的仓库的继承变量，但不改 PATH/hooks。"""
    env = dict(os.environ)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    return env


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120, shell=False,
        stdin=subprocess.DEVNULL, env=_env(),
    )
    if proc.returncode:
        raise LedgerError(f"git {' '.join(args)} 失败：{proc.stderr.strip()[:1200]}")
    return proc.stdout


def _commit(cwd: Path, ref: str) -> str:
    if not isinstance(ref, str) or not ref or "\x00" in ref or ref.startswith("-"):
        raise LedgerError("提交或基线引用非法")
    return _git(cwd, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def _clean(cwd: Path, *, untracked: bool = True) -> None:
    if _git(cwd, "status", "--porcelain",
            f"--untracked-files={'all' if untracked else 'no'}").strip():
        raise LedgerError(f"工作区不干净：{cwd}")
    git_dir = Path(_git(cwd, "rev-parse", "--absolute-git-dir").strip())
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
                 "rebase-merge", "rebase-apply"):
        if (git_dir / name).exists():
            raise LedgerError(f"工作区有未完成操作 {name}：{cwd}")


def _path(value: str, base: Path | None = None) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else base / path).resolve() if base else path.resolve()


def _same_path(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a)) == os.path.normcase(str(b))


def _main(repo: Path) -> str:
    if not _same_path(_path(_git(repo, "rev-parse", "--show-toplevel").strip()), repo):
        raise LedgerError("repo 必须是目标 worktree 根目录")
    if _git(repo, "symbolic-ref", "--quiet", "HEAD").strip() != "refs/heads/main":
        raise LedgerError("目标仓库必须检出本地 main")
    _clean(repo)
    return _commit(repo, "HEAD")


def _source(source: Path, sha: str, fp: str) -> None:
    """source 必须干净且冻结在 verified_sha/verified_fp；否则须重新 verify。"""
    if not _same_path(_path(_git(source, "rev-parse", "--show-toplevel").strip()), source):
        raise LedgerError("task spec worktree 必须指向 worktree 根目录")
    if _commit(source, "HEAD") != sha:
        raise StaleError("source HEAD 不等于 verified_sha，请重新 verify")
    try:
        _clean(source)
    except LedgerError as exc:
        raise StaleError(f"source 不干净，请重新 verify：{exc}") from exc
    before = worktree_fingerprint(source, sha)
    _clean(source)
    if _commit(source, "HEAD") != sha or before != fp:
        raise StaleError("source 指纹不等于 verified_fp 或检查期间被改动，请重新 verify")


def _same_worktrees(source: Path, repo: Path) -> None:
    def common(path: Path) -> Path:
        return _path(_git(path, "rev-parse", "--git-common-dir").strip(), path)

    if not _same_path(common(source), common(repo)):
        raise LedgerError("source 必须与目标 repo 属于同一 worktree 集合")


def _gates(root: Path) -> tuple[list[list[str]], float, str]:
    try:
        raw = (root / "config.json").read_bytes()
        cfg = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise LedgerError(f"config.json 缺失或不可读：{exc}") from exc
    gates = cfg.get("gates") if isinstance(cfg, dict) else None
    if not isinstance(gates, list) or not gates:
        raise LedgerError("config.json 的 gates 必须是非空 argv 列表的列表")
    for argv in gates:
        if not isinstance(argv, list) or not argv:
            raise LedgerError("每条 gate 必须是非空 argv 列表，不允许 shell 字符串")
        if not all(isinstance(a, str) and a and "\x00" not in a for a in argv):
            raise LedgerError("gate argv 只能包含非空字符串参数")
    timeout = cfg.get("gate_timeout")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise LedgerError("必须显式配置有限正数 gate_timeout（秒）")
    return gates, float(timeout), hashlib.sha256(raw).hexdigest()


def _logged(argv: list[str], cwd: Path, log: Path, timeout: float, evidence: list) -> None:
    """记录命令和证据；失败/超时抛出，由 integrate 统一转 blocked/failed。"""
    item = {"argv": argv, "cwd": str(cwd), "log": str(log), "timeout": timeout,
            "returncode": None, "timed_out": False, "ok": False}
    evidence.append(item)
    started = time.monotonic()
    try:
        with log.open("w", encoding="utf-8") as fh:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
            fh.flush()
            try:
                item["returncode"] = subprocess.run(
                    argv, cwd=str(cwd), stdout=fh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, timeout=timeout, shell=False, env=_env(),
                ).returncode
                item["ok"] = item["returncode"] == 0
            except subprocess.TimeoutExpired:
                item["timed_out"] = True
                item["error"] = "命令超时"
            except OSError as exc:
                item["error"] = str(exc)
            fh.write("\n" + json.dumps(item, ensure_ascii=False) + "\n")
    finally:
        item["duration_s"] = round(time.monotonic() - started, 3)
    if not item["ok"]:
        raise LedgerError(f"命令未通过，查看日志：{log}")


def _verify(led, task: str, root: Path, log: Path) -> None:
    """以子进程调用主脚本 verify，冻结 SHA；避免循环导入。"""
    guard = Path(__file__).resolve().with_name("card_guard.py")
    if not guard.is_file():
        raise LedgerError(f"找不到主验收脚本：{guard}")
    env = _env()
    env["LENGSUO_DEV_ROOT"] = str(root)
    try:
        proc = subprocess.run(
            [sys.executable, str(guard), "verify", task], capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=VERIFY_TIMEOUT,
            shell=False, stdin=subprocess.DEVNULL, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LedgerError(f"fresh scope verify 无法完成：{exc}") from exc
    log.write_text((proc.stdout or "") + (proc.stderr or ""), encoding="utf-8")
    if proc.returncode:
        raise ScopeError(f"fresh scope verify 未通过，查看日志：{log}")


def _snapshot(led, task: str) -> tuple[dict, dict]:
    root = Path(led.root)
    with led.lock():
        spec = read_json_strict(root / "tasks" / f"{task}.json")
        state = read_json_strict(root / "state" / f"{task}.json")
    if not isinstance(spec, dict) or not isinstance(state, dict):
        raise LedgerError("任务单和状态必须是 JSON 对象")
    return spec, state


def _same(values: dict, keys: tuple[str, ...], expected: dict) -> None:
    if any(values.get(k) != expected.get(k) for k in keys):
        raise StaleError("任务单、占用状态或验证冻结值在集成期间变化，请重新 verify")


def _perform(led, task: str, root: Path, ctx: dict, attempt: str) -> dict:
    spec, state = _snapshot(led, task)
    if state.get("state") != "verifying":
        raise LedgerError("任务必须已 verify 且处于 verifying")
    sha = state.get("verified_sha")
    fp = state.get("verified_fp")
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        raise LedgerError("缺少有效的 verified_sha")
    if not isinstance(fp, str) or not _SHA.fullmatch(fp):
        raise LedgerError("缺少有效的 verified_fp")
    worktree = spec.get("worktree")
    if not isinstance(worktree, str) or not worktree:
        raise LedgerError("任务缺少 worktree")
    source = Path(worktree).expanduser()
    source = (source if source.is_absolute() else root / source).resolve()
    repo = root / "repo"
    gates, gate_timeout, config_sha = _gates(root)
    ctx.update(head=sha, source_sha=sha, source_fp=fp, gate_config_sha256=config_sha)
    ctx["main_before"] = _main(repo)
    if source == repo:
        raise LedgerError("source 不能是目标 main worktree")
    _same_worktrees(source, repo)
    _source(source, sha, fp)

    log_dir = root / "logs" / "integrate" / attempt
    log_dir.mkdir(parents=True, exist_ok=True)
    ctx["log_dir"] = str(log_dir)
    _verify(led, task, root, log_dir / "verify.log")
    spec_now, state = _snapshot(led, task)
    if spec_now != spec:
        raise StaleError("verify 后任务单变化，拒绝集成")
    _same(state, ("state", "verified_sha", "verified_fp"),
          {"state": "verifying", "verified_sha": sha, "verified_fp": fp})
    _source(source, sha, fp)
    if _main(repo) != ctx["main_before"]:
        raise LedgerError("verify 期间 main 变化，拒绝集成")
    frozen = {"state": "merging", "verified_sha": sha, "verified_fp": fp}
    with led.lock():
        # 锁内复读后再切 merging；此前没有 git 或长 gate，台账锁不会覆盖集成。
        current = read_json_strict(root / "state" / f"{task}.json")
        _same(current, ("state", "verified_sha", "verified_fp"),
              {"state": "verifying", "verified_sha": sha, "verified_fp": fp})
        led.update(task, state="merging", held=True, integrate_started_at=time.time(),
                   main_before=ctx["main_before"], integration_attempt=attempt)

    candidate = root / "integration" / attempt
    ctx["candidate_worktree"] = str(candidate)
    _logged(["git", "worktree", "add", "--detach", str(candidate),
             ctx["main_before"]], repo, log_dir / "worktree.log", 120,
            ctx["integration_evidence"])
    try:
        _logged(["git", "merge", "--no-ff", "--no-edit", sha], candidate,
                log_dir / "merge.log", 120, ctx["integration_evidence"])
    except LedgerError:
        subprocess.run(["git", "-C", str(candidate), "merge", "--abort"],
                       capture_output=True, timeout=60, shell=False, env=_env())
        raise
    merge_sha = _commit(candidate, "HEAD")
    ctx["merge_sha"] = ctx["candidate_sha"] = merge_sha
    parents = _git(candidate, "rev-list", "--parents", "-n", "1", merge_sha).split()
    if parents != [merge_sha, ctx["main_before"], sha]:
        raise LedgerError("候选不是冻结 main/source 的双亲合并提交")
    for number, argv in enumerate(gates, 1):
        _logged(argv, candidate, log_dir / f"gate-{number:02d}.log",
                gate_timeout, ctx["gate_evidence"])
    _source(source, sha, fp)
    _clean(candidate, untracked=False)
    if _git(candidate, "rev-parse", "--abbrev-ref", "HEAD").strip() != "HEAD":
        raise LedgerError("gate 改变了候选的 detached 状态")
    if _commit(candidate, "HEAD") != merge_sha:
        raise LedgerError("gate 改变了候选提交")
    _snapshot_check = _snapshot(led, task)[1]
    _same(_snapshot_check, ("state", "verified_sha", "verified_fp"), frozen)
    if _main(repo) != ctx["main_before"]:
        raise LedgerError("gate 期间 main 变化，拒绝快进")

    # 先落盘通过 gates 的凭据，再推进 main；存储失败发生在主线变化之前。
    atomic_write(log_dir / "receipt.json", dict(ctx, state="ready"))
    _logged(["git", "merge", "--ff-only", merge_sha], repo,
            log_dir / "ff.log", 120, ctx["integration_evidence"])
    ctx["main_after"] = _commit(repo, "HEAD")
    if ctx["main_after"] != merge_sha:
        raise LedgerError("main 快进结果与候选不一致，需人工检查")
    with led.lock():
        led.update(task, **ctx, state="merged", held=False, reason=None,
                   merged_at=time.time())
    cleanup = None
    try:
        # 只清理成功集成且干净的临时 worktree；提交已由 main 可达。
        _git(repo, "worktree", "remove", str(candidate))
    except LedgerError as exc:
        cleanup = str(exc)
    return dict(ctx, ok=True, state="merged", occupied=False,
                main_unchanged=False, reason=None, cleanup_error=cleanup)


def _failure(led, task: str, root: Path, ctx: dict, exc: Exception) -> dict:
    reason = f"{type(exc).__name__}: {exc}"
    try:
        ctx["main_after"] = _commit(root / "repo", "refs/heads/main")
    except Exception:
        ctx["main_after"] = None
    advanced = bool(ctx.get("merge_sha") and ctx.get("main_after") == ctx["merge_sha"])
    if advanced:
        status = "merged"
        reason = "main 已到达候选，不做破坏性回滚；请核对台账。" + reason
    else:
        status = "failed" if isinstance(exc, (ScopeError, StaleError)) else "blocked"
    result = dict(ctx, ok=False, state=status, reason=reason, occupied=True,
                  main_unchanged=(ctx.get("main_before") is None
                                  or ctx.get("main_before") == ctx.get("main_after")))
    try:
        with led.lock():
            led.update(task, **ctx, state=status, held=True, reason=reason,
                       failed_at=time.time())
    except Exception as error:
        result["ledger_error"] = f"{type(error).__name__}: {error}"
    if ctx.get("log_dir"):
        try:
            atomic_write(Path(ctx["log_dir"]) / "failure.json", result)
        except Exception as error:
            result["evidence_error"] = str(error)
    return result


def integrate(led, task: str) -> dict:
    """集成一张卡到本地 main；失败转 blocked/failed，占用保留，需人工处理。

    led: Ledger 实例，root 内含 repo/tasks/state/config.json。
    task: 任务名（对应 tasks/<task>.json）。调用方不得已持有台账锁。
    """
    ctx = {"gate_evidence": [], "integration_evidence": []}
    if not isinstance(task, str) or not _TASK.fullmatch(task):
        return dict(ctx, ok=False, task=task, state="blocked", occupied=True,
                    reason="任务名非法，未修改台账")
    root = Path(led.root).resolve()
    attempt = f"{task}-{uuid.uuid4().hex}"
    try:
        with _integration_lock(root):
            try:
                return _perform(led, task, root, ctx, attempt)
            except Exception as exc:  # 单张卡失败不能拖垮调度器
                return _failure(led, task, root, ctx, exc)
    except Exception as exc:
        # 没有集成锁时绝不写台账，避免覆盖另一集成进程持有的同一张卡。
        return dict(ctx, ok=False, task=task, state="blocked", occupied=True,
                    reason=f"集成锁不可用或释放失败：{type(exc).__name__}: {exc}")
