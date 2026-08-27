#!/usr/bin/env python3
"""Lint: keep the three shipped documents honest against the actual binary.

Every defect this catches was found by hand while preparing 2.4.0, and all but
one had the same shape: README.md was updated for a change and README.RUS.md or
README-IMAGE.md was not. Russian build instructions told users to install
OpenSSL for two releases after it was removed; --generate-account-key-if-missing
shipped in 2.2.1 and was never translated; the account-registration change in
2.4.0 reached the English subcommand table and neither of the others. Docs drift
silently because nothing executes them, so these checks execute them instead.

Run: python3 tests/lint-docs.py   (ACME_BIN=path/to/binary to skip the build)
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["README.md", "README.RUS.md", "README-IMAGE.md"]
PARITY = ["README.md", "README.RUS.md"]

# Commands that stopped registering an ACME account implicitly in 2.4.0. An
# example invoking one of these with neither --account-url nor --agree-tos now
# fails against a key that has no account, so the section must say so.
NEEDS_ACCOUNT = ("revoke-cert", "show-dns-persist-01", "pre-authorize", "key-rollover")

# TLS has been rustls + aws-lc-rs since 2.2.0; any of these means a document
# still describes the OpenSSL build that no longer exists.
STALE_TLS = re.compile(r"openssl-dev|OPENSSL_STATIC|openssl-sys|libssl|native-tls")

failures: list[str] = []


def fail(doc: str, msg: str) -> None:
    failures.append(f"{doc}: {msg}")


def run_bin(args: list[str]) -> str:
    binary = os.environ.get("ACME_BIN")
    cmd = [binary, *args] if binary else ["cargo", "run", "--quiet", "--", *args]
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    return p.stdout + p.stderr


def slug(text: str) -> str:
    """GitHub's heading slug: strip punctuation, then replace EACH whitespace
    character. Runs are NOT collapsed, so `Hardened / production run` becomes
    `hardened--production-run` with two hyphens."""
    s = re.sub(r"<[^>]+>", "", text.strip().lower())
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s", "-", s)


def structure(raw: str) -> tuple[list[str], int, int]:
    """Headings, fenced-block count and table-row count, ignoring fenced code.
    Code fences matter: a shell comment like `# Revoke (no reason code)` is not
    a markdown heading."""
    heads, blocks, rows, fenced = [], 0, 0, False
    for line in raw.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            if fenced:
                blocks += 1
            continue
        if fenced:
            continue
        if m := re.match(r"^#{1,6}\s+(.*)", line):
            heads.append(m.group(1))
        elif m := re.match(r"^\s*<summary><h\d>(.*?)</h\d></summary>", line):
            heads.append(m.group(1))
        if line.startswith("|"):
            rows += 1
    return heads, blocks, rows


def main() -> int:
    top = run_bin(["--help"])
    if "Commands:" not in top:
        print("could not read --help from the binary", file=sys.stderr)
        return 2
    subs = sorted(
        set(re.findall(r"^\s{2}([a-z][a-z0-9-]+)", top.split("Commands:")[1].split("Options:")[0], re.M))
        - {"help"}
    )
    global_flags = set(re.findall(r"(--[a-z0-9-]+)", top))
    sub_help = {s: run_bin([s, "--help"]) for s in subs}
    sub_flags = {s: set(re.findall(r"(--[a-z0-9-]+)", sub_help[s])) | global_flags for s in subs}

    # Required flags, taken from what clap reports when the command is run bare,
    # rather than from anyone's memory of which arguments are mandatory.
    required: dict[str, list[str]] = {}
    for s in subs:
        err = run_bin([s])
        if "required arguments were not provided:" in err:
            block = err.split("required arguments were not provided:")[1].split("Usage:")[0]
            if flags := sorted(set(re.findall(r"--[a-z-]+", block))):
                required[s] = flags

    env_vars = {v for txt in [top, *sub_help.values()] for v in re.findall(r"\[env: (ACME_[A-Z_]+)", txt)}

    artifacts = set()
    for wf in (ROOT / ".github/workflows").glob("release*.yaml"):
        artifacts |= set(re.findall(r"acme-client-rs-[a-z0-9_.-]+\.(?:tar\.gz|zip)", wf.read_text()))

    for doc in DOCS:
        path = ROOT / doc
        if not path.exists():
            fail(doc, "missing")
            continue
        raw = path.read_text(encoding="utf-8")
        joined = re.sub(r"\\\n\s*", " ", raw)  # shell line continuations
        lines = joined.splitlines()

        fenced, is_heading, slugs = False, [False] * len(lines), set()
        for i, line in enumerate(lines):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            if m := re.match(r"^#{1,6}\s+(.*)", line):
                is_heading[i] = True
                slugs.add(slug(m.group(1)))
            elif m := re.match(r"^\s*<summary><h\d>(.*?)</h\d></summary>", line):
                slugs.add(slug(m.group(1)))

        for n, line in enumerate(lines, 1):
            s = line.strip()
            if not re.search(r"acme-client-rs(\.exe)?\s", s) or s.startswith((">", "|")):
                continue
            tokens = s.split()
            try:
                start = next(i for i, t in enumerate(tokens) if "acme-client-rs" in t)
            except StopIteration:
                continue
            tokens = tokens[start + 1 :]
            sub = next((t for t in tokens if t in subs), None)
            if sub is None:
                continue
            used = [t.split("=")[0] for t in tokens if t.startswith("--")]
            if bad := [u for u in used if u not in sub_flags[sub]]:
                fail(doc, f"line {n}: `{sub}` example uses unknown flag(s) {bad}")
            if sub in NEEDS_ACCOUNT:
                sec_start = next((j for j in range(n - 2, -1, -1) if is_heading[j]), 0)
                section = "\n".join(lines[sec_start:n])
                preceding = "\n".join(lines[max(0, n - 30) : n])
                if not (
                    "--account-url" in s
                    or "--agree-tos" in s
                    or "ACME_ACCOUNT_URL" in preceding
                    or "--agree-tos" in section
                ):
                    fail(doc, f"line {n}: `{sub}` example needs a registered account, unmentioned in its section")

        for sub, flags in required.items():
            row = next((l for l in raw.splitlines() if l.startswith(f"| `{sub}`") or l.startswith(f"| `{sub} ")), None)
            if row is None:
                continue  # not every document carries a full subcommand table
            if missing := [f for f in flags if f not in row]:
                fail(doc, f"subcommand table row for `{sub}` omits required {missing}")

        if broken := [a for a in re.findall(r"\]\(#([^)]+)\)", raw) if a not in slugs]:
            fail(doc, f"broken internal link(s): {broken}")

        if hits := STALE_TLS.findall(raw):
            fail(doc, f"describes the pre-2.2.0 OpenSSL build ({sorted(set(hits))})")

        if "| Artifact |" in raw or "acme-client-rs-linux-x86_64-musl" in raw:
            documented = set(re.findall(r"acme-client-rs-[a-z0-9_.-]+\.(?:tar\.gz|zip)", raw))
            if undocumented := sorted(artifacts - documented):
                fail(doc, f"release publishes artifacts the install table omits: {undocumented}")

        if "`ACME_DIRECTORY_URL`" in raw:  # has an environment-variable table
            if missing_env := sorted(v for v in env_vars if f"`{v}`" not in raw):
                fail(doc, f"binary reads env vars this document never mentions: {missing_env}")

    en, ru = (structure((ROOT / d).read_text(encoding="utf-8")) for d in PARITY)
    for label, a, b in (("headings", len(en[0]), len(ru[0])), ("code blocks", en[1], ru[1]), ("table rows", en[2], ru[2])):
        if a != b:
            fail("README.RUS.md", f"out of sync with README.md: {a} vs {b} {label}")

    generated = run_bin(["generate-config"])
    example = (ROOT / "acme-client-rs.toml.example").read_text(encoding="utf-8")

    def keys(text: str) -> set[str]:
        out, section = set(), None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line.strip("[]")
            elif (m := re.match(r"#?\s*([a-z_]+)\s*=", line)) and section:
                out.add(f"{section}.{m.group(1)}")
        return out

    if drift := keys(generated) ^ keys(example):
        fail("acme-client-rs.toml.example", f"differs from `generate-config` output: {sorted(drift)}")

    if failures:
        print(f"FAIL: {len(failures)} documentation issue(s)\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"OK: {len(DOCS)} documents consistent with the binary, the release workflows and each other")
    return 0


if __name__ == "__main__":
    sys.exit(main())
