"""Per-domain gate runner (agent / network / browser).

Purpose: let parallel worktrees run a *lane-fast* gate over only their own
domain, instead of forcing every lane to compile and lint the whole workspace.
This does NOT replace the full-workspace merge gate required by AGENTS.md §5 —
the full gate still runs at merge time. This is the fast, per-lane check.

Domain membership is derived from real crate dependencies, not from name
prefixes (e.g. ``lengsuo-shell`` is an agent-line crate even though it is
prefixed ``lengsuo-``; ``policy-engine`` / ``credential-ref`` are agent-line
without any prefix). Keep this map in sync with docs/agent-split-plan.md.

Usage:
    python scripts/run_domain_gate.py agent
    python scripts/run_domain_gate.py network --tests-only
    python scripts/run_domain_gate.py --changed        # infer from git diff
    python scripts/run_domain_gate.py --list
"""
from pathlib import Path
import argparse
import subprocess
import sys

# Domain -> crate package names. Derived from measured Cargo.toml dependencies
# (see docs/agent-split-plan.md §3), NOT from directory name prefixes.
DOMAINS = {
    "agent": [
        "agent-acp", "agent-core", "agent-execpolicy", "agent-gateway",
        "agent-mcp", "agent-memory", "agent-prompts", "agent-pty",
        "agent-sandbox", "agent-skills", "agent-tasks", "agent-tools",
        "agent-tools-exec", "credential-ref", "lengsuo-shell", "policy-engine",
    ],
    "network": [
        "lengsuo-anytls", "lengsuo-environment", "lengsuo-hysteria",
        "lengsuo-node", "lengsuo-shadowsocks", "lengsuo-ss2022",
        "lengsuo-tls", "lengsuo-trojan", "lengsuo-tun", "lengsuo-vless",
        "lengsuo-vmess", "lengsuo-wireguard", "ss-client", "ss-core",
    ],
    "browser": [
        "lengsuo-browser-installer", "lengsuo-browser-lifecycle",
        "lengsuo-browser-package", "lengsuo-browser-profile",
        "lengsuo-browser-signature", "lengsuo-browser-state",
    ],
}

CRATE_TO_DOMAIN = {c: d for d, cs in DOMAINS.items() for c in cs}

# Shared files that can affect every domain; a change here means "run all".
SHARED_PREFIXES = ("Cargo.toml", "Cargo.lock", "scripts/", ".github/")


def run(cmd, root):
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=root).returncode


def domain_pkgs(domain):
    """Flatten a domain's crate list into repeated ``-p <crate>`` args."""
    return sum([["-p", c] for c in DOMAINS[domain]], [])


def changed_domains(root):
    out = subprocess.run(
        ["git", "diff", "--name-only", "HEAD"], cwd=root,
        capture_output=True, text=True, check=True,
    ).stdout.split()
    out += subprocess.run(
        ["git", "ls-files", "-o", "--exclude-standard"], cwd=root,
        capture_output=True, text=True, check=True,
    ).stdout.split()
    touched = set()
    for path in out:
        if path.startswith(SHARED_PREFIXES):
            return sorted(DOMAINS)
        parts = Path(path).parts
        if len(parts) >= 2 and parts[0] == "crates":
            dom = CRATE_TO_DOMAIN.get(parts[1])
            if dom:
                touched.add(dom)
    return sorted(touched)


def main():
    parser = argparse.ArgumentParser(description="Run a per-domain gate.")
    parser.add_argument("domain", nargs="?", choices=sorted(DOMAINS))
    parser.add_argument("--changed", action="store_true",
                        help="infer domains from git working-tree changes")
    parser.add_argument("--tests-only", action="store_true",
                        help="skip fmt/clippy, run tests only")
    parser.add_argument("--list", action="store_true", help="print the domain map")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    if args.list:
        for d, cs in DOMAINS.items():
            print(f"{d} ({len(cs)}): {' '.join(cs)}")
        return 0

    domains = []
    if args.changed:
        domains = changed_domains(root)
        print(f"changed -> domains: {domains or '(none; nothing to check)'}")
    elif args.domain:
        domains = [args.domain]
    else:
        parser.error("give a domain, or use --changed")

    if not domains:
        print("no affected domain; skip")
        return 0

    rc = 0
    for d in domains:
        pkgs = domain_pkgs(d)
        print(f"\n===== domain: {d} =====", flush=True)
        if not args.tests_only:
            rc |= run(["cargo", "fmt", "--all", "--", "--check"], root)
            rc |= run(["cargo", "clippy", "--locked", "--all-targets",
                       *pkgs, "--", "-D", "warnings"], root)
        rc |= run(["cargo", "test", "--locked", *pkgs], root)
        rc |= run(["cargo", "build", "--locked", *pkgs], root)
    print(f"\ndomain gate rc={rc} domains={domains}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
