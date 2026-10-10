#!/usr/bin/env python3
"""Convert the IPsum blocklist (https://github.com/stamparm/ipsum) to nftables.

Downloads the feed over HTTPS (full file each run, no git dependency),
filters it by blacklist score, and emits an nftables file defining a table
with an address set and optional drop chains. With --install the table is
(re)loaded into the running kernel (requires root). Re-running the same
command line with --install is the update procedure: when the table structure
is unchanged the set contents are refreshed in place in a single atomic nft
batch; first install or a structure change does an atomic delete+load in a
single batch as well (no gap; a failed load keeps the previous table intact).

Examples:
  ./ipsum2nft.py                        # all IPs (min score 1)
  ./ipsum2nft.py --min-score 3          # upstream-recommended threshold
  ./ipsum2nft.py --install              # generate and load (as root)
  ./ipsum2nft.py --chains input --merge # INPUT chain only, merge prefixes
  ./ipsum2nft.py --chains all --install # router: also block transit (forward) traffic
   ./ipsum2nft.py --add 203.0.113.7      # also block a test IP not in the feed
   ./ipsum2nft.py uninstall              # remove the table from the kernel (root)
    ./ipsum2nft.py daemon                 # NFLOG hit notification daemon (mail alerts)
"""
from __future__ import annotations

import argparse
import configparser
import errno
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import smtplib
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
SCRIPT_DIR = Path(__file__).resolve().parent
NETFILTER = shutil.which("nft") or "/usr/bin/nft"
DEFAULT_CONF = "/etc/ipsum2nft.conf"
CHAINS_CHOICES = ("both", "all", "input", "output", "forward", "none")


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_feed(data: bytes) -> int:
    """Strictly validate downloaded feed content; return the entry count.

    Unlike parse_list (lenient, also for user files via --list), a downloaded
    feed must be completely clean: the IPsum header, a 'Last update' line,
    every data line exactly 'IP SCORE' (a valid IPv4/IPv6 address or CIDR
    prefix and a positive integer score), and a non-trivial number of
    entries. Anything else raises ValueError, so a corrupt or error-page
    response can never clobber the last good cache. CIDR prefixes are
    allowed (a future v6 feed may provide /64-style entries; the block
    scope is exactly what the feed states). The score is mandatory because
    parse_list treats a missing score as 'infinite' (always kept), which
    would silently defeat --min-score filtering on a tampered cache.
    """
    text = data.decode("utf-8", errors="replace")
    head = text[:200]
    if not head.startswith("# IPsum") or "Last update" not in text[:500]:
        raise ValueError("missing the IPsum feed header / 'Last update' line")
    entries = 0
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2:
            bad += 1
            continue
        try:
            ipaddress.ip_network(fields[0], strict=False)
        except ValueError:
            bad += 1
            continue
        if not fields[1].isdigit() or int(fields[1]) < 1:
            bad += 1
            continue
        entries += 1
    if bad:
        raise ValueError(f"{bad} malformed data line(s)")
    if entries < 1000:
        raise ValueError(f"only {entries} entries (expected thousands)")
    return entries


def fetch_url(url: str, dest: Path, timeout: int = 30) -> str:
    """Download url, validate it, then atomically replace dest.

    Return the sha256 of the content. The local copy is only replaced after
    the whole download passes validate_feed, so a bad response cannot destroy
    the last good cache.
    """
    log(f"[fetch] {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ipsum2nft"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    entries = validate_feed(data)  # raises before touching dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)
    log(f"[fetch] ok: {entries} entries")
    return hashlib.sha256(data).hexdigest()


def parse_list(path: Path, min_score: int) -> tuple[list, int, str]:
    """Return (networks, skipped_lines, feed_last_update)."""
    entries: dict = {}
    skipped = 0
    feed_update = "unknown"
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("# Last update:"):
                    feed_update = line[len("# Last update:"):].strip()
                continue
            fields = line.split()
            raw = fields[0]
            # Lines without a score column (e.g. levels/*.txt) are always kept.
            score = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else float("inf")
            if score < min_score:
                continue
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                skipped += 1
                continue
            old = entries.get(net)
            if old is None or score > old:
                entries[net] = score
    if skipped:
        log(f"[parse] warning: skipped {skipped} unparseable line(s)")
    return sorted(entries, key=_sortkey), skipped, feed_update


def _sortkey(n):
    return (n.version, int(n.network_address), n.prefixlen)


def _drop_subsumed(nets: list) -> list:
    """Remove networks contained in another one.

    CIDR networks only ever overlap by containment, so dropping the contained
    network keeps the union exactly (lossless). Required because an nftables
    interval set rejects overlapping entries - e.g. --add 192.0.2.0/24 while
    the list contains 192.0.2.1/32 would fail to load ("conflicting
    intervals"). Adjacent (non-overlapping) prefixes are left for --merge.
    """
    out = []
    for ver in (4, 6):
        # For identical start addresses the wider prefix (smaller prefixlen)
        # must be processed first so it can subsume the narrower one.
        ns = sorted((n for n in nets if n.version == ver),
                    key=lambda n: (int(n.network_address), n.prefixlen))
        active = []  # end addresses of wider prefixes that started earlier
        for n in ns:
            start, end = int(n.network_address), int(n.broadcast_address)
            while active and active[-1] < start:
                active.pop()
            if any(e >= end for e in active):
                continue
            active.append(end)
            out.append(n)
    return sorted(out, key=_sortkey)


def parse_extra(items: list[str]) -> list:
    """Parse user-supplied extra IPs/CIDRs (repeatable --add, comma separated)."""
    nets = []
    for item in items:
        for part in item.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as e:
                log(f"error: --add: invalid address {part!r}: {e}")
                sys.exit(1)
    return nets


def build_nft(
    nets: list, table: str, setname: str, chains: str,
    header: list[str], chunk: int,
    logspec=None, log_rate: str = "10/minute",
) -> tuple[str, list[str]]:
    """Return (main_file_text, [extra_file_texts]).

    logspec: None | "kernel" | ("nflog", group). Logging applies to the
    outbound directions only (output daddr, forward daddr) - i.e. our side
    (host itself or an internal host) contacting a blocked IP.
    """
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]

    def fmt(nets: list) -> str:
        return ", ".join(str(n) for n in nets)

    extras: list[str] = []
    body: list[str] = []
    body.append(f"table inet {table} {{")

    def add_set(family: str, name: str, elems: list) -> None:
        body.append(f"    set {name} {{")
        body.append(f"        type {family}")
        body.append("        flags interval")
        if elems:
            body.append(f"        elements = {{ {fmt(elems)} }}")
        body.append("    }")

    def queue_elems(name: str, elems: list) -> None:
        if chunk > 0 and len(elems) > chunk:
            for i in range(0, len(elems), chunk):
                extras.append(
                    f"add element inet {table} {name} {{ {fmt(elems[i:i + chunk])} }}\n"
                )

    if v4:
        add_set("ipv4_addr", setname, [] if (chunk > 0 and len(v4) > chunk) else v4)
        queue_elems(setname, v4)
    if v6:
        add_set("ipv6_addr", setname + "6", [] if (chunk > 0 and len(v6) > chunk) else v6)
        queue_elems(setname + "6", v6)

    def drop_stmts(fam: str, field: str, ref: str, logdir: str | None) -> list[str]:
        """Rule lines for a drop; logdir 'out'/'fwd' enables logging."""
        base = f"        {fam} {field} @{ref}"
        if logdir is None or logspec is None:
            return [base + " counter drop"]
        prefix = f"ipsum-{logdir}: "
        if logspec == "kernel":
            # skuid: log the socket owner (UID/GID) - identifies the local
            # user/process that contacted the blocked IP (e.g. web user after
            # a compromise). OUTPUT only: FORWARD has no local socket.
            flags = " flags skuid" if logdir == "out" else ""
            return [
                f"{base} limit rate {log_rate} counter log prefix \"{prefix}\"{flags} drop",
                f"{base} counter drop",
            ]
        return [f"{base} counter log group {logspec[1]} prefix \"{prefix}\" snaplen 128 drop"]

    if chains in ("both", "all", "input"):
        body.append("    chain input {")
        body.append("        type filter hook input priority -200; policy accept;")
        if v4:
            body += drop_stmts("ip", "saddr", setname, None)
        if v6:
            body += drop_stmts("ip6", "saddr", setname + "6", None)
        body.append("    }")
    if chains in ("both", "all", "output"):
        body.append("    chain output {")
        body.append("        type filter hook output priority -200; policy accept;")
        if v4:
            body += drop_stmts("ip", "daddr", setname, "out")
        if v6:
            body += drop_stmts("ip6", "daddr", setname + "6", "out")
        body.append("    }")
    if chains in ("all", "forward"):
        body.append("    chain forward {")
        body.append("        type filter hook forward priority -200; policy accept;")
        if v4:
            body += drop_stmts("ip", "saddr", setname, None)
            body += drop_stmts("ip", "daddr", setname, "fwd")
        if v6:
            body += drop_stmts("ip6", "saddr", setname + "6", None)
            body += drop_stmts("ip6", "daddr", setname + "6", "fwd")
        body.append("    }")

    body.append("}")
    return "\n".join(header + body) + "\n", extras


def uninstall(table: str, state_path: Path) -> None:
    if os.geteuid() != 0:
        log("[uninstall] error: requires root privileges (re-run as root, e.g. via sudo)")
        sys.exit(1)
    r = subprocess.run(
        [NETFILTER, "delete", "table", "inet", table],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        log(f"[uninstall] removed table inet {table}")
    elif "No such file or directory" in (r.stderr or ""):
        log(f"[uninstall] table inet {table} not present (nothing to do)")
    else:
        log(f"[uninstall] error: {(r.stderr or r.stdout).strip()}")
        sys.exit(1)
    if state_path.is_file():
        state_path.unlink()
        log(f"[uninstall] removed state file {state_path}")


# Bump when the generated rule schema changes (chain set, priorities,
# rule statements) so that previously installed tables get a full reload.
# v2: kernel-log OUTPUT rules gained 'flags skuid'.
SCHEMA_VERSION = 2


def _fingerprint(table: str, setname: str, chains: str,
                 logspec, log_rate: str, sets: list[str]) -> str:
    """Hash of everything that defines the table structure (not its contents)."""
    raw = json.dumps(
        [SCHEMA_VERSION, table, setname, chains, logspec, log_rate, sets],
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _parse_table(text: str) -> tuple[dict, dict]:
    """Parse `nft list table` text. Return (sets, chains).

    sets:  {name: type}
    chains: {name: {"hook", "priority", "policy",
                    "rules": [(fam, field, setref, middle)]}}
    middle = the rule body between the set match and the 'drop' verdict,
    with the dynamic counter state normalized to 'counter'.
    """
    sets: dict = {}
    chains: dict = {}
    cur = None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"set (\S+) \{", s)
        if m:
            cur = ("set", m.group(1))
            sets[m.group(1)] = None
            continue
        m = re.match(r"chain (\S+) \{", s)
        if m:
            cur = ("chain", m.group(1))
            chains[m.group(1)] = {"hook": None, "priority": None,
                                  "policy": None, "rules": []}
            continue
        if s == "}":
            cur = None
            continue
        if cur is None:
            continue
        if cur[0] == "set":
            m = re.match(r"type (\S+)", s)
            if m:
                sets[cur[1]] = m.group(1)
        else:
            m = re.match(r"type filter hook (\S+) priority (-?\d+); policy (\S+);", s)
            if m:
                chains[cur[1]].update(hook=m.group(1), priority=m.group(2),
                                      policy=m.group(3))
                continue
            m = re.match(r"(ip6?|ether|meta) (saddr|daddr) @(\S+) (.+)$", s)
            if m and m.group(4).split()[-1] == "drop":
                body = m.group(4)[:-len("drop")].strip()
                body = re.sub(r"counter packets \d+ bytes \d+", "counter", body)
                chains[cur[1]]["rules"].append(
                    (m.group(1), m.group(2), m.group(3), body))
    return sets, chains


def _expected_structure(setname: str, chains: str, v4: bool, v6: bool) -> tuple[dict, dict]:
    """Expected sets/chains for these options.

    Rules: chain -> [(fam, field, setref, logdir)]; logdir is None, "out"
    (output daddr) or "fwd" (forward daddr) - the logged directions.
    """
    want_sets = {}
    if v4:
        want_sets[setname] = "ipv4_addr"
    if v6:
        want_sets[setname + "6"] = "ipv6_addr"
    want_chains: dict = {}

    def add(chain: str, hook: str, fams: list) -> None:
        if not fams:
            return
        want_chains[chain] = (hook, fams)

    fams_in = []
    if v4:
        fams_in.append(("ip", "saddr", setname, None))
    if v6:
        fams_in.append(("ip6", "saddr", setname + "6", None))
    fams_out = []
    if v4:
        fams_out.append(("ip", "daddr", setname, "out"))
    if v6:
        fams_out.append(("ip6", "daddr", setname + "6", "out"))
    fams_fwd = []
    if v4:
        fams_fwd += [("ip", "saddr", setname, None), ("ip", "daddr", setname, "fwd")]
    if v6:
        fams_fwd += [("ip6", "saddr", setname + "6", None),
                     ("ip6", "daddr", setname + "6", "fwd")]
    if chains in ("both", "all", "input"):
        add("input", "input", fams_in)
    if chains in ("both", "all", "output"):
        add("output", "output", fams_out)
    if chains in ("all", "forward"):
        add("forward", "forward", fams_fwd)
    return want_sets, want_chains


def _canonical_body(body: str):
    """Decompose a rule body (between the set match and the drop verdict)
    into the statements the generator may emit.

    Returns {"counter": ..., "limit": ..., "log": ...} with the statement
    text, or None if the body contains anything else at all (extra match
    conditions such as 'meta skuid N', quota, comment, a second limit, ...).
    Substring checks are not safe here: 'group 5' matches inside 'group 50',
    and an extra condition would otherwise be invisible.
    """
    pats = {
        "counter": r"counter ",
        "limit": r"limit rate \d+/\S+(?: burst \d+ packets)? ",
        "log": r"log (?:prefix \"[^\"]*\" |group \d+ |snaplen \d+ |flags \S+ )*",
    }
    found = {}
    rest = f" {body} "
    changed = True
    while changed:
        changed = False
        for name, pat in pats.items():
            if name in found:
                continue
            m = re.search(pat, rest)
            if m:
                found[name] = m.group(0).strip()
                rest = rest[:m.start()] + " " + rest[m.end():]
                changed = True
    if rest.strip():
        return None
    return found


def _log_attrs(stmt: str):
    """Canonical (sorted) attribute tuple of a 'log ...' statement."""
    attrs = []
    m = re.search(r'prefix "([^"]*)"', stmt)
    if m:
        attrs.append(("prefix", m.group(1)))
    m = re.search(r" group (\d+) ", " " + stmt + " ")
    if m:
        attrs.append(("group", m.group(1)))
    m = re.search(r" snaplen (\d+) ", " " + stmt + " ")
    if m:
        attrs.append(("snaplen", m.group(1)))
    m = re.search(r" flags (\S+) ", " " + stmt + " ")
    if m:
        attrs.append(("flags", m.group(1)))
    return tuple(sorted(attrs))


def _plain_rule_ok(body: str) -> bool:
    """True iff the rule body is exactly 'counter' (the unconditional drop
    backstop the generator emits - set match only, no other statements)."""
    canon = _canonical_body(body)
    return canon is not None and set(canon) == {"counter"}


def _log_rule_ok(body: str, logdir: str, logspec, log_rate: str) -> bool:
    """Check the log-bearing rule of a logged direction against what the
    generator emits, by full canonical equality (no substring matching)."""
    canon = _canonical_body(body)
    if canon is None or "log" not in canon:
        return False
    want_log = [("prefix", f"ipsum-{logdir}: ")]
    if logspec == "kernel":
        # must be exactly: limit (exact rate) + counter + log
        if set(canon) != {"counter", "limit", "log"}:
            return False
        m = re.fullmatch(r"limit rate (\d+/\S+)(?: burst \d+ packets)?",
                         canon["limit"])
        if not m or m.group(1) != log_rate:
            return False
        # OUTPUT also logs the socket owner (UID/GID of the local process)
        if logdir == "out":
            want_log.append(("flags", "skuid"))
    else:
        # NFLOG rule must be exactly counter + log (unconditional drop, no
        # limit that could be starved into passing traffic)
        if set(canon) != {"counter", "log"}:
            return False
        want_log += [("group", str(logspec[1])), ("snaplen", "128")]
    return _log_attrs(canon["log"]) == tuple(sorted(want_log))


def _structure_ok(table: str, setname: str, chains: str, v4: bool, v6: bool,
                  logspec, log_rate: str) -> bool:
    """Check the kernel table actually has the structure we expect (sets,
    chains, hook/priority/policy, and the required drop rules with their
    full conditions).

    Every logged direction needs a PLAIN rule (set match only, unconditional
    drop): a rate-limited log rule alone can be starved into passing traffic.
    Extra rules (e.g. a manual whitelist) are tolerated; missing or weakened
    required rules are not. Returns False on any discrepancy or read error.
    """
    r = subprocess.run([NETFILTER, "list", "table", "inet", table],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False
    sets, chains_found = _parse_table(r.stdout)
    want_sets, want_chains = _expected_structure(setname, chains, v4, v6)
    for name, typ in want_sets.items():
        if sets.get(name) != typ:
            return False
    for name, (hook, fams) in want_chains.items():
        c = chains_found.get(name)
        if c is None:
            return False
        if (c["hook"], c["priority"], c["policy"]) != (hook, "-200", "accept"):
            return False
        for fam, field, sref, logdir in fams:
            matches = [rl for rl in c["rules"] if rl[:3] == (fam, field, sref)]
            if logdir is None or logspec is None:
                if len(matches) != 1 or not _plain_rule_ok(matches[0][3]):
                    return False
                continue
            if logspec == "kernel":
                # rate-limited log rule + unconditional plain backstop
                if len(matches) != 2:
                    return False
                if sum(1 for rl in matches if _plain_rule_ok(rl[3])) != 1:
                    return False
                if not any(_log_rule_ok(rl[3], logdir, logspec, log_rate)
                           for rl in matches):
                    return False
            else:
                if len(matches) != 1:
                    return False
                if not _log_rule_ok(matches[0][3], logdir, logspec, log_rate):
                    return False
    return True


def install(nets: list, files: list[Path], table: str, setname: str,
            chains: str, logspec, log_rate: str, state_path: Path,
            fingerprint: str) -> None:
    if os.geteuid() != 0:
        log(f"[install] error: requires root privileges (re-run as root, e.g. via sudo)")
        sys.exit(1)

    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]

    def fmt(ns: list) -> str:
        return ", ".join(str(n) for n in ns)

    existing = subprocess.run(
        [NETFILTER, "list", "table", "inet", table],
        capture_output=True, text=True,
    ).returncode == 0
    state = state_path.read_text() if state_path.is_file() else ""
    in_place = (
        existing
        and f"fingerprint={fingerprint}" in state
        and _structure_ok(table, setname, chains, bool(v4), bool(v6),
                          logspec, log_rate)
    )

    if in_place:
        # Same structure as what we installed before: refresh only the set
        # contents. flush + add in ONE nft invocation = one netlink batch,
        # committed atomically by the kernel, so there is no moment where
        # the set is empty (verified: 0/225 probe pings got through).
        lines = []
        if v4:
            lines.append(f"flush set inet {table} {setname}")
            lines.append(f"add element inet {table} {setname} {{ {fmt(v4)} }}")
        if v6:
            lines.append(f"flush set inet {table} {setname + '6'}")
            lines.append(f"add element inet {table} {setname + '6'} {{ {fmt(v6)} }}")
        upd = state_path.parent / (state_path.name + ".upd")
        upd.write_text("\n".join(lines) + "\n")
        try:
            log(f"[install] atomic in-place update: {NETFILTER} -f {upd}")
            subprocess.run([NETFILTER, "-f", str(upd)], check=True)
        except subprocess.CalledProcessError as e:
            log(f"[install] error: in-place update failed ({e}); table kept intact")
            sys.exit(1)
        finally:
            upd.unlink(missing_ok=True)
        log("[install] set contents updated in place (no gap)")
        return

    if existing:
        log("[install] note: full atomic replacement (structure change, "
            "missing state, or table structure does not match)")
    # One file, one nft invocation = one netlink batch, committed atomically:
    # either the old table or the new one is active, never a broken mix, and
    # a failed load leaves the previous table intact (verified in a sandbox).
    parts = []
    if existing:
        parts.append(f"delete table inet {table}")
    for f in files:
        parts.append(f.read_text())
    load_path = state_path.parent / (state_path.name + ".load")
    load_path.write_text("\n".join(parts) + "\n")
    log(f"[install] atomic (re)load: {NETFILTER} -f {load_path}")
    r = subprocess.run([NETFILTER, "-f", str(load_path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        log(f"[install] error: load failed; previous table kept intact")
        log(f"[install] error output: {(r.stderr or '').strip()}")
        log(f"[install] kept {load_path} for inspection")
        sys.exit(1)
    load_path.unlink()
    state_path.write_text(
        f"fingerprint={fingerprint}\ntable={table}\nset={setname}\n"
    )


def _normalize_log_rate(rate: str):
    """Validate --log-rate against what nft 'limit rate' actually accepts
    and return the canonical form, or None if invalid.

    nft requires the full unit name (second/minute/hour/day/week - 'sec' is
    a syntax error), a unit is mandatory, and numbers with leading zeros
    are parsed as OCTAL ('010/minute' loads as '8/minute'), which would
    never match the structure check's exact string and force a full
    replacement on every run. We require a positive decimal integer and a
    full unit name, and canonicalize to 'int/unit' so generation, the
    fingerprint and the structure check all compare the same string.
    """
    m = re.fullmatch(r"(\d+)/(second|minute|hour|day|week)", rate)
    if not m or int(m.group(1)) < 1:
        return None
    return f"{int(m.group(1))}/{m.group(2)}"


# ---------------------------------------------------------------------------
# Notification daemon (the 'daemon' subcommand)
#
# Reads the NFLOG group the drop rules send to (--log-group N), aggregates
# the hits per aggregation window with a per-source cooldown, and mails an
# alert. The NFLOG reading part is the same mechanism as the lateral-hoihoi
# daemon (https://github.com/shimarin/lateral-hoihoi, copied from commit
# bc6013e; bundled here so ipsum2nft stays a single-file, stdlib-only
# tool): an NFLOG group can be bound by only ONE reader, so if
# lateral-hoihoi also runs on this host use a different group number.
# Fixes applied here (e.g. the bounded config-ACK wait, TLS verification,
# bounded aggregation) should be tracked back to lateral-hoihoi as well.
# ---------------------------------------------------------------------------

dlog = logging.getLogger("ipsum2nft")

# netlink / nfnetlink (NFULNL) constants
NETLINK_NETFILTER = getattr(socket, "NETLINK_NETFILTER", 12)
NFNL_SUBSYS_ULOG = 4  # linux/netfilter/nfnetlink.h (nfnetlink_log subsystem)
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1

NLMSG_ERROR = 2

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04

# config commands (struct nfulnl_msg_config_cmd { u8 command; })
NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_PF_BIND = 3

# config attributes
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2

NFULNL_COPY_PACKET = 2

# packet attributes (values per <linux/netfilter/nfnetlink_log.h>)
NFULA_PACKET_HDR = 1
NFULA_MARK = 2
NFULA_TIMESTAMP = 3
NFULA_IFINDEX_INDEV = 4
NFULA_HWADDR = 8
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10
NFULA_UID = 11     # user id of the socket (fsuid, munged to our ns; __be32)
NFULA_GID = 14     # group id of the socket (fsgid, munged to our ns; __be32)
NFULA_HWHEADER = 16

# The kernel attaches NFULA_UID/NFULA_GID to an NFLOG message whenever the
# packet has a related local socket - no nft rule option is needed (and an
# NFLOG rule cannot take 'flags skuid' anyway; that flag belongs to the
# kernel-log backend only). Forwarded packets have no local socket, so
# hits from the 'ipsum-fwd: ' direction carry no UID/GID.

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
AF_UNSPEC = 0

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

IPPROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6-encap",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

# IPv6 extension headers (skip these and continue with the next header)
IP6_EXT_STD = {0, 43, 60}   # hop-by-hop / routing / destination-options
IP6_EXT_FRAG = 44
IP6_EXT_AH = 51

FAMILY_NAMES = {"inet": AF_INET, "inet6": AF_INET6, "ipv4": AF_INET, "ipv6": AF_INET6}


def align4(n):
    return (n + 3) & ~3


def fmt_mac(b):
    return ":".join("%02x" % x for x in b) if b else "-"


def nla(attr_type, payload):
    """Build one netlink attribute (TLV, 4-byte aligned)."""
    length = 4 + len(payload)
    return struct.pack("=HH", length, attr_type) + payload + b"\x00" * (align4(length) - length)


def parse_nlas(data):
    """Parse a netlink attribute list into {type: value}."""
    attrs = {}
    off = 0
    end = len(data)
    while off + 4 <= end:
        length, atype = struct.unpack_from("=HH", data, off)
        if length < 4 or off + length > end:
            break
        attrs[atype & 0x3FFF] = data[off + 4: off + length]
        off += align4(length)
    return attrs


# ---------------------------------------------------------------------------
# event
# ---------------------------------------------------------------------------
class Event:
    __slots__ = ("ts", "family", "proto", "proto_num", "src_ip", "dst_ip",
                 "src_port", "dst_port", "icmp_type", "icmp_code",
                 "src_mac", "dst_mac", "indev", "prefix", "mark", "hook",
                 "uid", "gid")

    def __init__(self):
        self.ts = time.time()
        self.family = "?"
        self.proto = "?"
        self.proto_num = None
        self.src_ip = "?"
        self.dst_ip = "?"
        self.src_port = None
        self.dst_port = None
        self.icmp_type = None
        self.icmp_code = None
        self.src_mac = "-"
        self.dst_mac = "-"
        self.indev = 0
        self.prefix = ""
        self.mark = 0
        self.hook = None
        self.uid = None
        self.gid = None

    def dst_label(self):
        if self.dst_port is not None:
            if self.family == "IPv6":
                return "[%s]:%d" % (self.dst_ip, self.dst_port)
            return "%s:%d" % (self.dst_ip, self.dst_port)
        if self.icmp_type is not None:
            return "%s type=%d/code=%d" % (self.dst_ip, self.icmp_type, self.icmp_code)
        return self.dst_ip

    def agg_key(self):
        return (self.proto, self.dst_ip, self.dst_port, self.icmp_type, self.prefix)


# ---------------------------------------------------------------------------
# NFLOG reader
# ---------------------------------------------------------------------------
class NflogReader:
    def __init__(self, group, families, copy_range=0xFFFF, rcvbuf=8 * 1024 * 1024):
        self.group = group
        self.seq = 0
        self._pending = []  # packet messages arrived while waiting for the config ACKs
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except OSError:
            pass
        self.sock.bind((0, 0))

        # Register protocol families (for older kernels; failures ignored)
        for pf in families:
            self._send_config(pf, 0, self._cmd_attr(NFULNL_CFG_CMD_PF_BIND), ack=False)
        # Bind the group. A failed BIND (no privilege, group already bound by
        # another reader) must abort: the socket would stay open but never
        # receive anything, hiding the misconfiguration.
        self._send_config(AF_UNSPEC, group, self._cmd_attr(NFULNL_CFG_CMD_BIND))
        bind_seq = self.seq
        # Copy mode (whole packet up to snaplen)
        mode = struct.pack(">IBB", copy_range, NFULNL_COPY_PACKET, 0)
        self._send_config(AF_UNSPEC, group, nla(NFULA_CFG_MODE, mode))
        self._wait_config_acks([bind_seq, self.seq])

    # -- config messages -----------------------------------------------------
    def _cmd_attr(self, command):
        return nla(NFULA_CFG_CMD, struct.pack("=B", command))

    def _send_config(self, family, res_id, attr_bytes, ack=True):
        self.seq += 1
        # struct nfgenmsg { u8 family; u8 version; be16 res_id; }
        nfgen = struct.pack("!BBH", family, 0, res_id)
        body = nfgen + attr_bytes
        mtype = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
        flags = NLM_F_REQUEST | (NLM_F_ACK if ack else 0)
        total = 16 + len(body)
        hdr = struct.pack("=IHHII", total, mtype, flags, self.seq, 0)
        self.sock.send(hdr + body)

    def _wait_config_acks(self, seqs, timeout=2.0):
        """Wait for the config ACKs of the given message seqs and return.

        Packet messages arriving while we wait are kept in self._pending
        (read_events serves them first) - the group can deliver traffic as
        soon as the BIND is processed, so dropping them here would lose
        events exactly when hits are continuous. Raises OSError if any ACK
        reports an error, or if any is still missing after timeout: a group
        that never confirmed its bind delivers nothing, so starting anyway
        would hide the failure (fail-fast)."""
        needed = set(seqs)
        errs = {}
        deadline = time.monotonic() + timeout
        self.sock.settimeout(0.1)
        try:
            while needed and time.monotonic() < deadline:
                try:
                    data = self.sock.recv(1 << 20)
                except socket.timeout:
                    continue
                off = 0
                n = len(data)
                while off + 16 <= n:
                    length, mtype, flags, seq, pid = struct.unpack_from("=IHHII", data, off)
                    if length < 16 or off + length > n:
                        break
                    if mtype == NLMSG_ERROR:
                        (err,) = struct.unpack_from("=i", data, off + 16)
                        if seq in needed:
                            needed.discard(seq)
                            if err:
                                errs[seq] = err
                        elif err:
                            # e.g. PF_BIND on a kernel that rejects it: tolerated
                            dlog.warning("netlink config error: %s (seq=%d)",
                                         os.strerror(-err), seq)
                    elif ((mtype >> 8) == NFNL_SUBSYS_ULOG and
                          (mtype & 0xFF) == NFULNL_MSG_PACKET):
                        self._pending.append(data[off:off + align4(length)])
                    off += align4(length)
        finally:
            self.sock.settimeout(None)
        if needed:
            raise OSError("NFLOG group %d: no config ACK (seq %s) within %.0fs"
                          % (self.group, "/".join(str(s) for s in sorted(needed)), timeout))
        if errs:
            raise OSError("NFLOG group %d bind failed: %s"
                          % (self.group, os.strerror(-next(iter(errs.values())))))

    # -- receive ---------------------------------------------------------------
    def read_events(self, timeout):
        """Wait up to timeout seconds and return the packets received as a list of Event."""
        evs = []
        pending, self._pending = self._pending, []
        for msg in pending:
            ev = self._parse_packet(msg[16:])
            if ev is not None:
                evs.append(ev)
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(1 << 20)
        except socket.timeout:
            return evs
        except OSError as e:
            if e.errno == errno.ENOBUFS:
                dlog.warning("NFLOG buffer overflow (ENOBUFS) - some packets were missed")
                return evs
            raise
        evs.extend(self._parse(data))
        return evs

    def _parse(self, data):
        off = 0
        n = len(data)
        while off + 16 <= n:
            length, mtype, flags, seq, pid = struct.unpack_from("=IHHII", data, off)
            if length < 16 or off + length > n:
                break
            if (mtype >> 8) == NFNL_SUBSYS_ULOG and (mtype & 0xFF) == NFULNL_MSG_PACKET:
                ev = self._parse_packet(data[off + 16: off + length])
                if ev is not None:
                    yield ev
            off += align4(length)

    def _parse_packet(self, body):
        # Skip the leading nfgenmsg (family,version,res_id)
        if len(body) < 4:
            return None
        attrs = parse_nlas(body[4:])
        ev = Event()

        ts = attrs.get(NFULA_TIMESTAMP)
        if ts and len(ts) >= 16:
            sec, usec = struct.unpack(">QQ", ts[:16])
            ev.ts = sec + usec / 1e6

        hwproto = None
        hdr = attrs.get(NFULA_PACKET_HDR)
        if hdr and len(hdr) >= 4:
            hwproto, hook, _pad = struct.unpack(">HBB", hdr[:4])
            ev.hook = hook

        if NFULA_MARK in attrs:
            ev.mark = struct.unpack(">I", attrs[NFULA_MARK][:4])[0]
        if NFULA_IFINDEX_INDEV in attrs:
            ev.indev = struct.unpack(">I", attrs[NFULA_IFINDEX_INDEV][:4])[0]
        if NFULA_UID in attrs:
            ev.uid = struct.unpack(">I", attrs[NFULA_UID][:4])[0]
        if NFULA_GID in attrs:
            ev.gid = struct.unpack(">I", attrs[NFULA_GID][:4])[0]
        if NFULA_PREFIX in attrs:
            ev.prefix = attrs[NFULA_PREFIX].split(b"\x00", 1)[0].decode("ascii", "replace")

        hw = attrs.get(NFULA_HWADDR)
        if hw and len(hw) >= 4:
            hlen = struct.unpack(">H", hw[:2])[0]
            ev.src_mac = fmt_mac(hw[4:4 + min(hlen, 6)])
        # If the whole Ethernet header (dst[6] src[6] type[2]) is present the dst MAC is available too
        ethhdr = attrs.get(NFULA_HWHEADER)
        if ethhdr and len(ethhdr) >= 12:
            ev.dst_mac = fmt_mac(ethhdr[0:6])
            if ev.src_mac == "-":
                ev.src_mac = fmt_mac(ethhdr[6:12])

        self._parse_l3(ev, hwproto, attrs.get(NFULA_PAYLOAD, b""))
        return ev

    def _parse_l3(self, ev, hwproto, p):
        is_v4 = hwproto == ETH_P_IP or (hwproto is None and p and (p[0] >> 4) == 4)
        is_v6 = hwproto == ETH_P_IPV6 or (hwproto is None and p and (p[0] >> 4) == 6)
        if is_v4 and len(p) >= 20:
            ev.family = "IPv4"
            ihl = (p[0] & 0x0F) * 4
            ev.proto_num = p[9]
            ev.src_ip = socket.inet_ntop(AF_INET, p[12:16])
            ev.dst_ip = socket.inet_ntop(AF_INET, p[16:20])
            self._parse_l4(ev, p[ihl:])
        elif is_v6 and len(p) >= 40:
            ev.family = "IPv6"
            ev.src_ip = socket.inet_ntop(AF_INET6, p[8:24])
            ev.dst_ip = socket.inet_ntop(AF_INET6, p[24:40])
            nexthdr, off = self._skip_ext6(p[6], p, 40)
            ev.proto_num = nexthdr
            self._parse_l4(ev, p[off:])
        if ev.proto_num is not None:
            ev.proto = IPPROTO_NAMES.get(ev.proto_num, str(ev.proto_num))

    def _skip_ext6(self, nexthdr, p, off):
        # Skip known extension headers, up to 8 levels
        for _ in range(8):
            if off + 2 > len(p):
                break
            if nexthdr in IP6_EXT_STD:
                ext_len = (p[off + 1] + 1) * 8
            elif nexthdr == IP6_EXT_FRAG:
                ext_len = 8
            elif nexthdr == IP6_EXT_AH:
                ext_len = (p[off + 1] + 2) * 4
            else:
                break
            nexthdr = p[off]
            off += ext_len
        return nexthdr, off

    def _parse_l4(self, ev, seg):
        if ev.proto_num in (6, 17, 132) and len(seg) >= 4:      # TCP / UDP / SCTP
            ev.src_port, ev.dst_port = struct.unpack(">HH", seg[:4])
        elif ev.proto_num in (1, 58) and len(seg) >= 2:         # ICMP / ICMPv6
            ev.icmp_type, ev.icmp_code = seg[0], seg[1]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# aggregation & notification
# ---------------------------------------------------------------------------
class Alerter:
    # The NFLOG rule has no rate limit, so one window can contain an
    # unbounded number of packets. Aggregate incrementally in add() (never
    # store raw events) and cap the number of (source, key) pairs to bound
    # memory and mail size; excess events are counted, not stored. The cap
    # is a single budget shared by the current window AND events deferred
    # for retry after a failed send, so a prolonged SMTP outage cannot grow
    # the stored state without bound. On a merge, already-stored keys keep
    # their count updates and only NEW keys are dropped to overflow (the
    # oldest pending alerts get priority over newer detections).
    MAX_AGG_KEYS = 4096

    def __init__(self, cfg):
        self.cfg = cfg
        self.stats = {}        # src_ip -> {agg_key: {"n", "first", "last", "ev"}}
        self.deferred = {}     # src_ip -> stats of the last failed send (retried)
        self.overflow = 0      # events not stored this window (cap exceeded)
        self._deferred_overflow = 0  # overflow of failed sends, carried until a
                                     # successful notification reports it
        self._nkeys = 0        # keys stored in stats + deferred (shared budget)
        self._uids = {}        # src_ip -> set of observed uids (display only)
        self.last_alert = {}   # src_ip -> monotonic time (cooldown management)

    def add(self, ev):
        if ev.uid is not None:
            self._uids.setdefault(ev.src_ip, set()).add(ev.uid)
        # an already-stored key (in the current window OR in the deferred
        # retry set) just updates its count; only a genuinely new pair
        # competes for the shared key budget
        key = ev.agg_key()
        a = self.deferred.get(ev.src_ip, {}).get(key)
        if a is None:
            per = self.stats.get(ev.src_ip)
            a = per.get(key) if per is not None else None
        if a is not None:
            a["n"] += 1
            if ev.ts < a["first"]:
                a["first"] = ev.ts
            if ev.ts > a["last"]:
                a["last"] = ev.ts
            return
        if self._nkeys >= self.MAX_AGG_KEYS:
            self.overflow += 1
            return
        per = self.stats.get(ev.src_ip)
        if per is None:
            per = {}
            self.stats[ev.src_ip] = per
        per[key] = {"n": 1, "first": ev.ts, "last": ev.ts, "ev": ev}
        self._nkeys += 1

    @staticmethod
    def _src_n(per):
        """Total event count of one source's aggregation {agg_key: entry}."""
        return sum(a["n"] for a in per.values())

    def _total_n(self, stats):
        return sum(self._src_n(per) for per in stats.values())

    def _prune_cooldown(self, now):
        # last_alert grows unboundedly without this (one entry per source
        # ever seen, even long-silent ones)
        for src in [s for s, t in self.last_alert.items()
                    if now - t >= self.cfg.cooldown]:
            del self.last_alert[src]

    def flush(self):
        """Report the current window plus events deferred by a previous
        failed send. Return True unless a mail was due and the send failed:
        the failure is then kept in self.deferred (within the same key
        budget) for the next flush, and the cooldown is NOT advanced (only
        a successful send confirms it, so a transient SMTP outage does not
        suppress a source for the whole cooldown period)."""
        if not self.stats and not self.overflow and not self.deferred:
            return True
        now = time.monotonic()
        self._prune_cooldown(now)

        # overflow of earlier failed sends is carried into this report
        overflow = self._deferred_overflow
        self._deferred_overflow = 0
        overflow += self.overflow
        self.overflow = 0

        # merge the current window into the deferred stats. New keys were
        # already budget-checked in add() (which sees stats + deferred
        # together), so no cap check is needed here; only duplicates can
        # shrink the key count, hence the exact recount afterwards.
        stats = self.deferred
        self.deferred = {}
        if self.stats:
            for src, per in self.stats.items():
                d = stats.setdefault(src, {})
                for key, a in per.items():
                    old = d.get(key)
                    if old is None:
                        d[key] = a
                    else:
                        # same key in a deferred window: combine the counts
                        old["n"] += a["n"]
                        old["first"] = min(old["first"], a["first"])
                        old["last"] = max(old["last"], a["last"])
        self.stats = {}
        self._nkeys = sum(len(per) for per in stats.values())

        to_report = {}
        sup_n = 0
        for src, per in stats.items():
            if not per:
                continue
            if now - self.last_alert.get(src, -1e18) >= self.cfg.cooldown:
                to_report[src] = per
            else:
                sup_n += self._src_n(per)
        uids = self._uids
        self._uids = {}
        if not to_report:
            # everything is in cooldown: nothing to send, but the overflow
            # count is kept for the next successful notification
            self._deferred_overflow = overflow
            self._nkeys = 0
            if sup_n or overflow:
                dlog.info("window flushed: %d event(s) in cooldown, %d omitted "
                          "(cap) - no notification", sup_n, overflow)
            return True

        rep_uids = {s: u for s, u in uids.items() if s in to_report}
        ok = self._notify(to_report, sup_n, self._total_n(to_report), overflow,
                          rep_uids)
        if not ok:
            # kept for retry at the next flush (natural backoff: one
            # window); the omitted-count and the observed uids travel with
            # the deferred stats so a later successful report still
            # discloses them
            self.deferred = to_report
            self._deferred_overflow = overflow
            self._nkeys = sum(len(per) for per in to_report.values())
            self._uids = rep_uids
        else:
            self._nkeys = 0
        return ok

    def _notify(self, to_report, suppressed_n, total_events, overflow, uids):
        subject = "%s %s: contact with a blocklisted IP - sources: %d" % (
            self.cfg.subject_prefix, self.cfg.hostname, len(to_report))
        body = self._build_body(to_report, suppressed_n, total_events, overflow,
                                uids)
        if self.cfg.dump:
            print("---- (dump) %s ----\n%s" % (subject, body))
            sent = True
        else:
            try:
                self._send_mail(subject, body)
                dlog.info("alert sent: sources %d / events %d", len(to_report), total_events)
                sent = True
            except Exception as e:
                dlog.error("mail send failed: %s", e)
                sent = False
        if sent:
            # only a delivered notification confirms the cooldown
            for src in to_report:
                self.last_alert[src] = time.monotonic()
        return sent

    def _build_body(self, to_report, suppressed_n, total_events, overflow, uids):
        lines = []
        lines.append("Host %s: contact with an IP on the IPsum blocklist was detected." % self.cfg.hostname)
        lines.append("Aggregation window: %d sec / Cooldown: %d sec" % (self.cfg.window, self.cfg.cooldown))
        lines.append("This window: events %d / sources %d" % (total_events, len(to_report)))
        if suppressed_n:
            lines.append("(another %d event(s) omitted: sources in cooldown)" % suppressed_n)
        if overflow:
            lines.append("(another %d event(s) omitted: aggregation cap exceeded)" % overflow)
        lines.append("(direction: prefix 'ipsum-out: ' = this host itself, 'ipsum-fwd: ' = an internal host, via forward)")
        lines.append("(uid = the local user whose socket made the contact; output only -")
        lines.append("forwarded packets have no local socket and setuid binaries show the fsuid)")
        lines.append("")

        for src in sorted(to_report):
            agg = to_report[src]  # {agg_key: {"n", "first", "last", "ev"}}
            samples = [a["ev"] for a in agg.values()]
            src_mac = next((e.src_mac for e in samples if e.src_mac != "-"), "-")
            devs = sorted({str(e.indev) for e in samples if e.indev})
            uidstr = ""
            if uids.get(src):
                uidstr = "uid %s  " % ",".join(str(u) for u in sorted(uids[src]))
            lines.append("■ Source %s  (%sMAC %s%s)" % (
                src, uidstr, src_mac, "  IF#" + ",".join(devs) if devs else ""))

            lines.append("   %-19s %-8s %-42s %6s  %s" %
                         ("last time", "proto", "dst (blocklisted)", "count", "prefix/mark"))
            for key in sorted(agg, key=lambda k: agg[k]["last"], reverse=True):
                a = agg[key]
                e = a["ev"]
                pm = e.prefix or "-"
                if e.mark:
                    pm += " mark=0x%x" % e.mark
                lines.append("   %-19s %-8s %-42s %6d  %s" % (
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["last"])),
                    e.proto, e.dst_label(), a["n"], pm))
            lines.append("")

        lines.append("-- ipsum2nft")
        return "\n".join(lines)

    def _send_mail(self, subject, body):
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = c.mail_from
        msg["To"] = ", ".join(c.mail_to)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=c.hostname if "." in c.hostname else None)
        msg.set_content(body)

        # smtplib's implicit default (no context passed) does NOT verify the
        # server certificate or hostname (CERT_NONE) - verify explicitly.
        # Optional CA file/dir for a private CA.
        ctx = ssl.create_default_context()
        if c.smtp_cafile:
            ctx.load_verify_locations(cafile=c.smtp_cafile)
        if c.smtp_capath:
            ctx.load_verify_locations(capath=c.smtp_capath)
        if c.smtp_tls == "ssl":
            server = smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, timeout=c.smtp_timeout,
                                      context=ctx)
        else:
            server = smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=c.smtp_timeout)
        try:
            server.ehlo()
            if c.smtp_tls == "starttls":
                server.starttls(context=ctx)
                server.ehlo()
            if c.smtp_user:
                server.login(c.smtp_user, c.smtp_password)
            server.send_message(msg)
        finally:
            try:
                server.quit()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
class Config:
    pass


def _getint(parser, section, option, lo=None, hi=None):
    """getint + range check (a typoed value should fail startup loudly)."""
    try:
        v = parser.getint(section, option)
    except ValueError as e:
        raise SystemExit("config error [%s] %s: %s" % (section, option, e))
    if lo is not None and v < lo:
        raise SystemExit("config error [%s] %s: %d (must be >= %d)" % (section, option, v, lo))
    if hi is not None and v > hi:
        raise SystemExit("config error [%s] %s: %d (must be <= %d)" % (section, option, v, hi))
    return v


def load_config(path):
    # interpolation=None: values are used verbatim - a '%' in the SMTP
    # password (or anywhere else) must not be treated as an interpolation
    # directive or cause an error.
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict({
        "nflog": {"group": "6", "families": "inet, inet6", "copy_range": "65535"},
        "detection": {"aggregation_window": "60", "cooldown": "3600"},
        "smtp": {"port": "587", "tls": "starttls", "user": "", "password": "",
                 "cafile": "", "capath": "", "timeout": "30"},
        "mail": {"subject_prefix": "[ipsum2nft]", "hostname": "auto"},
    })
    if not parser.read(path, encoding="utf-8"):
        raise SystemExit("cannot read config file: %s" % path)

    c = Config()
    c.group = _getint(parser, "nflog", "group", 0, 65535)
    c.copy_range = _getint(parser, "nflog", "copy_range", 1, 0xFFFFFFFF)
    fams = []
    for tok in parser.get("nflog", "families").replace(",", " ").split():
        key = tok.strip().lower()
        if key not in FAMILY_NAMES:
            raise SystemExit("families has an invalid value: %s" % tok)
        af = FAMILY_NAMES[key]
        if af not in fams:
            fams.append(af)
    if not fams:
        raise SystemExit("families is empty")
    c.families = fams

    c.window = _getint(parser, "detection", "aggregation_window", 1)
    c.cooldown = _getint(parser, "detection", "cooldown", 0)

    c.smtp_host = parser.get("smtp", "host", fallback="").strip()
    c.smtp_port = _getint(parser, "smtp", "port", 1, 65535)
    c.smtp_tls = parser.get("smtp", "tls").strip().lower()
    if c.smtp_tls not in ("none", "starttls", "ssl"):
        raise SystemExit("smtp.tls must be one of none/starttls/ssl")
    c.smtp_user = parser.get("smtp", "user").strip()
    c.smtp_password = parser.get("smtp", "password")
    c.smtp_cafile = parser.get("smtp", "cafile").strip()
    c.smtp_capath = parser.get("smtp", "capath").strip()
    c.smtp_timeout = _getint(parser, "smtp", "timeout", 1)

    c.subject_prefix = parser.get("mail", "subject_prefix").strip()
    hostname = parser.get("mail", "hostname").strip()
    c.hostname = socket.gethostname() if hostname in ("", "auto") else hostname
    c.mail_from = parser.get("mail", "from", fallback="").strip()
    c.mail_to = [a.strip() for a in parser.get("mail", "to", fallback="").replace(",", " ").split() if a.strip()]

    c.dump = False
    return c


def validate_for_mail(c):
    missing = []
    if not c.smtp_host:
        missing.append("smtp.host")
    if not c.mail_from:
        missing.append("mail.from")
    if not c.mail_to:
        missing.append("mail.to")
    if missing:
        raise SystemExit("config incomplete: " + ", ".join(missing))


def load_update_config(explicit):
    """Read the update-command options from a config file.

    Returns (path, values): values holds only the keys actually present in
    the file ([update] min_score/list_dir/output/chains, [nflog] group), so
    the command line (or the built-in defaults) fills in the rest. An absent
    or unreadable *default* file is not an error (built-in defaults apply);
    an explicitly requested file must be readable.
    """
    path = explicit or DEFAULT_CONF
    if not explicit and not os.path.isfile(path):
        return None, {}
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(path, encoding="utf-8"):
        if explicit:
            raise SystemExit("cannot read config file: %s" % path)
        return None, {}
    values = {}
    if parser.has_option("update", "min_score"):
        try:
            v = parser.getint("update", "min_score")
        except ValueError as e:
            raise SystemExit("config error [update] min_score: %s" % e)
        if v < 1:
            raise SystemExit("config error [update] min_score: %d (must be >= 1)" % v)
        values["min_score"] = v
    for opt in ("list_dir", "output"):
        if parser.has_option("update", opt):
            v = parser.get("update", opt).strip()
            if not v:
                raise SystemExit("config error [update] %s: empty" % opt)
            values[opt] = Path(v)
    if parser.has_option("update", "chains"):
        v = parser.get("update", "chains").strip()
        if v not in CHAINS_CHOICES:
            raise SystemExit("config error [update] chains: %r (choose from %s)"
                             % (v, "/".join(CHAINS_CHOICES)))
        values["chains"] = v
    if parser.has_option("nflog", "group"):
        try:
            v = parser.getint("nflog", "group")
        except ValueError as e:
            raise SystemExit("config error [nflog] group: %s" % e)
        if not (0 <= v <= 65535):
            raise SystemExit("config error [nflog] group: %d (must be in 0..65535)" % v)
        values["log_group"] = v
    return path, values


def run_daemon(args) -> None:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")

    cfg = load_config(args.config or DEFAULT_CONF)
    cfg.dump = args.dump

    if args.test_mail:
        validate_for_mail(cfg)
        alerter = Alerter(cfg)
        ev = Event()
        ev.family, ev.proto, ev.proto_num = "IPv4", "TCP", 6
        ev.src_ip, ev.dst_ip, ev.dst_port = "192.0.2.10", "203.0.113.9", 443
        ev.src_mac, ev.dst_mac, ev.indev = "de:ad:be:ef:00:01", "02:00:00:00:00:99", 2
        ev.prefix = "ipsum-fwd: "
        alerter.add(ev)
        # the whole point is verifying the SMTP path: a failed send must be
        # a non-zero exit (for provisioning / smoke checks)
        raise SystemExit(0 if alerter.flush() else 1)

    if not cfg.dump:
        validate_for_mail(cfg)
        if cfg.smtp_cafile or cfg.smtp_capath:
            # Fail early on a broken CA file/dir instead of at the first
            # alert. cafile is loaded eagerly by ssl, but capath is read
            # lazily at handshake time - a nonexistent directory would not
            # raise here - so check its existence explicitly. The hashed
            # CA layout itself is only fully validated at the TLS handshake.
            if cfg.smtp_cafile and not os.path.isfile(cfg.smtp_cafile):
                raise SystemExit("smtp.cafile not found: %s" % cfg.smtp_cafile)
            if cfg.smtp_capath and not os.path.isdir(cfg.smtp_capath):
                raise SystemExit("smtp.capath is not a directory: %s" % cfg.smtp_capath)
            _ctx = ssl.create_default_context()
            if cfg.smtp_cafile:
                _ctx.load_verify_locations(cafile=cfg.smtp_cafile)
            if cfg.smtp_capath:
                _ctx.load_verify_locations(capath=cfg.smtp_capath)

    try:
        reader = NflogReader(cfg.group, cfg.families, copy_range=cfg.copy_range)
    except OSError as e:
        dlog.error("%s", e)
        raise SystemExit(1)
    alerter = Alerter(cfg)
    dlog.info("started: NFLOG group=%d families=%s window=%ds cooldown=%ds",
              cfg.group, [("inet" if f == AF_INET else "inet6") for f in cfg.families],
              cfg.window, cfg.cooldown)

    running = {"go": True}

    def _stop(signum, frame):
        running["go"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    next_flush = time.monotonic() + cfg.window
    try:
        while running["go"]:
            # Slice the recv block to at most 1 second (responsiveness to SIGTERM
            # while window boundaries are decided by the monotonic clock)
            timeout = max(0.2, min(next_flush - time.monotonic(), 1.0))
            for ev in reader.read_events(timeout):
                alerter.add(ev)
            if time.monotonic() >= next_flush:
                alerter.flush()
                next_flush = time.monotonic() + cfg.window
    finally:
        alerter.flush()
        reader.close()
        dlog.info("stopped")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert the IPsum blocklist into an nftables table.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = ap.add_subparsers(dest="command")
    up = sub.add_parser("uninstall", help="remove the table from the running kernel (root)")
    up.add_argument("--table", default="ipsum",
                    help="nftables table name to remove (default: %(default)s)")
    up.add_argument("--output", type=Path, default=SCRIPT_DIR / "ipsum.nft",
                    help="output file whose .state sidecar will be removed "
                         "(default: %(default)s)")
    dp = sub.add_parser("daemon", help="NFLOG notification daemon: aggregate hits "
                                        "sent by --log-group and mail an alert")
    # default=SUPPRESS: when not given on the daemon line, keep the value
    # parsed by the top-level -c (so 'ipsum2nft -c X daemon' works too);
    # run_daemon resolves a missing value to DEFAULT_CONF.
    dp.add_argument("-c", "--config", default=argparse.SUPPRESS, metavar="FILE",
                    help="config file (see ipsum2nft.conf.example; default: %s)"
                         % DEFAULT_CONF)
    dpmode = dp.add_mutually_exclusive_group()
    dpmode.add_argument("--dump", action="store_true",
                        help="print the alerts to stdout instead of sending mail (testing)")
    dpmode.add_argument("--test-mail", action="store_true",
                        help="send one test mail with the configured SMTP settings, "
                             "then exit (non-zero exit on a failed send)")
    dp.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-c", "--config", default=None, metavar="FILE",
                    help="config file for --min-score/--list-dir/--output/--log-group "
                         "(default: %s when present; the command line wins)" % DEFAULT_CONF)
    ap.add_argument("--list-dir", type=Path, default=None,
                    help="directory where the downloaded feed is kept "
                         "(default: %s, or [update] list_dir in the config file)"
                         % (SCRIPT_DIR / "ipsum",))
    ap.add_argument("--url", default=FEED_URL, metavar="URL",
                    help="feed URL to download (default: %(default)s)")
    ap.add_argument("--list", type=Path, default=None, metavar="FILE",
                    help="parse FILE instead of downloading the feed")
    ap.add_argument("--no-fetch", action="store_true",
                    help="do not download the feed; use the last local copy")
    ap.add_argument("--min-score", type=int, default=None, metavar="N",
                    help="only include IPs listed on >= N blacklists (upstream recommends 3; "
                         "default: 1, or [update] min_score in the config file)")
    ap.add_argument("--add", action="append", default=[], metavar="IP",
                    help="extra IP or CIDR to always include (repeatable, comma-separated OK); "
                         "not subject to --min-score, merged when --merge is used")
    ap.add_argument("--merge", action="store_true",
                    help="merge adjacent/overlapping prefixes (e.g. 256 x /32 -> /24)")
    ap.add_argument("--table", default="ipsum", help="nftables table name")
    ap.add_argument("--set", default="blocklist", help="nftables set name")
    ap.add_argument("--chains", default=None, choices=list(CHAINS_CHOICES),
                    help="drop chains to generate (all = input+output+forward, for routers; "
                         "default: both, or [update] chains in the config file)")
    ap.add_argument("--output", type=Path, default=None,
                    help="output file (chunk files are written next to it; "
                         "default: %s, or [update] output in the config file)"
                         % (SCRIPT_DIR / "ipsum.nft",))
    ap.add_argument("--chunk", type=int, default=0, metavar="N",
                    help="split element adds into N-element files (0 = single file)")
    loggrp = ap.add_mutually_exclusive_group()
    loggrp.add_argument("--log", action="store_true",
                        help="rate-limited kernel log (journald) for outbound hits "
                             "(output daddr + forward daddr = our side contacting a blocked IP)")
    loggrp.add_argument("--log-group", type=int, default=None, metavar="N",
                        help="send outbound hits to NFLOG group N for a userspace reader "
                             "(the 'daemon' subcommand of this tool, or lateral-hoihoi: "
                             "full record incl. src/dst MAC; default: "
                             "[nflog] group in the config file, i.e. no NFLOG rule)")
    ap.add_argument("--log-rate", default="10/minute", metavar="RATE",
                     help="rate limit for --log: positive integer + unit "
                          "(second|minute|hour|day|week), default: %(default)s")
    ap.add_argument("--install", action="store_true",
                    help="load the generated file into the running kernel (root)")
    args = ap.parse_args()

    if args.command == "daemon":
        run_daemon(args)
        return

    if args.command == "uninstall":
        state = args.output.parent / (args.output.name + ".state")
        uninstall(args.table, state)
        return

    # Config file for the update options (see ipsum2nft.conf.example): the
    # command line wins over the file, the file wins over the built-in
    # defaults. A missing/unreadable default file just means built-ins.
    conf_path, conf = load_update_config(args.config)
    if conf_path is not None:
        log(f"[config] reading {conf_path}")
    for key in ("min_score", "list_dir", "output", "log_group", "chains"):
        if getattr(args, key) is None and key in conf:
            setattr(args, key, conf[key])
    if args.log and "log_group" in conf:
        log(f"[config] note: --log (kernel log) overrides [nflog] group "
            f"{conf['log_group']} from {conf_path}")
    if args.min_score is None:
        args.min_score = 1
    if args.list_dir is None:
        args.list_dir = SCRIPT_DIR / "ipsum"
    if args.output is None:
        args.output = SCRIPT_DIR / "ipsum.nft"
    if args.chains is None:
        args.chains = "both"

    log_rate = _normalize_log_rate(args.log_rate)
    if log_rate is None:
        log(f"error: --log-rate: invalid rate {args.log_rate!r} (need "
            "N/second|minute|hour|day|week with a positive integer N, "
            "e.g. 10/minute)")
        sys.exit(1)

    if args.list is not None:
        list_path = args.list
    elif args.no_fetch:
        list_path = args.list_dir / "ipsum.txt"
    else:
        list_path = args.list_dir / "ipsum.txt"
        try:
            fetch_url(args.url, list_path)
        except Exception as e:
            if list_path.is_file():
                mtime = list_path.stat().st_mtime
                age_d = (time.time() - mtime) / 86400
                ts = datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                log(f"[fetch] warning: {e}; using existing copy {list_path} "
                    f"(last downloaded {ts}, {age_d:.1f} days ago)")
            else:
                log(f"error: {e}")
                sys.exit(1)

    if not list_path.is_file():
        log(f"error: {list_path} not found")
        sys.exit(1)
    sha = file_sha256(list_path)

    nets, _skipped, feed_update = parse_list(list_path, args.min_score)

    n_extra = 0
    if args.add:
        extra = parse_extra(args.add)
        before = set(nets)
        nets = sorted(set(nets) | set(extra), key=_sortkey)
        n_extra = len(nets) - len(before)
        log(f"[add] extra: {len(extra)} specified, {n_extra} new")

    if not nets:
        log("error: no entries left after filtering")
        sys.exit(1)

    # An nftables interval set rejects overlapping prefixes, and CIDR overlap
    # is always containment - so always drop networks contained in a broader
    # one (lossless: the union is unchanged). --merge additionally collapses
    # adjacent prefixes. This is what lets --add 192.0.2.0/24 coexist with a
    # feed entry 192.0.2.1/32 without "conflicting intervals".
    n_before = len(nets)
    if args.merge:
        v4 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
        v6 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 6))
        nets = sorted(v4 + v6, key=_sortkey)
    else:
        nets = _drop_subsumed(nets)
    n_removed = n_before - len(nets)
    if n_removed:
        log(f"[merge] dropped {n_removed} subsumed prefix(es)"
            + (", collapsed adjacent ones" if args.merge else ""))

    if any(n.prefixlen == 0 for n in nets):
        log("[warn] list contains 0.0.0.0/0 or ::/0 - everything will be dropped")

    n_v4 = sum(1 for n in nets if n.version == 4)
    n_v6 = len(nets) - n_v4
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    source = str(list_path) if args.list is not None or args.no_fetch else args.url
    header = [
        f"#!/usr/bin/env -S nft -f",
        f"# Generated by {Path(sys.argv[0]).name} at {now} - do not edit by hand.",
        f"# Source: {source} (sha256 {sha[:16]})",
        f"# Feed last update: {feed_update}",
        f"# Entries: {len(nets)} (ipv4: {n_v4}, ipv6: {n_v6}), min-score {args.min_score}"
        + (f", extra {n_extra}" if n_extra else "")
        + (" [merged]" if args.merge else ""),
        "",
    ]
    logspec = None
    if args.log:
        logspec = "kernel"
    elif args.log_group is not None:
        if args.log_group < 0 or args.log_group > 65535:
            log("error: --log-group must be in 0..65535")
            sys.exit(1)
        logspec = ("nflog", args.log_group)
    if logspec is not None and args.chains in ("none", "input"):
        log("[warn] logging applies to output/forward chains, which are not generated "
            f"with --chains {args.chains}")

    main_text, extras = build_nft(
        nets, args.table, args.set, args.chains, header, args.chunk,
        logspec=logspec, log_rate=log_rate,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp.write_text(main_text, encoding="utf-8")
    tmp.replace(args.output)
    os.chmod(args.output, 0o755)

    files = [args.output]
    for i, text in enumerate(extras, 1):
        f = args.output.with_name(f"{args.output.stem}.{i:03d}{args.output.suffix}")
        f.write_text(text, encoding="utf-8")
        files.append(f)

    log(f"[write] {args.output}" + (f" (+{len(extras)} chunk file(s))" if extras else ""))
    log(f"[stats] entries: {len(nets)} (v4: {n_v4}, v6: {n_v6}), output: "
        f"{sum(f.stat().st_size for f in files)} bytes")
    if args.chains != "none":
        log(f"[stats] drop chains: {args.chains} (table inet {args.table}, set {args.set})")

    if args.install:
        v4nets = [n for n in nets if n.version == 4]
        v6nets = [n for n in nets if n.version == 6]
        sets = ([args.set] if v4nets else []) + ([args.set + "6"] if v6nets else [])
        fingerprint = _fingerprint(
            args.table, args.set, args.chains, logspec, log_rate, sets
        )
        state_path = args.output.parent / (args.output.name + ".state")
        install(nets, files, args.table, args.set, args.chains, logspec,
                log_rate, state_path, fingerprint)
        log("[install] done")
    else:
        loads = " && ".join(f"{NETFILTER} -f {f}" for f in files)
        log(f"[next ] as root: re-run with --install (atomic single batch), or: "
            f"nft delete table inet {args.table} 2>/dev/null; {loads}")


if __name__ == "__main__":
    main()
