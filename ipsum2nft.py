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
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
SCRIPT_DIR = Path(__file__).resolve().parent
NETFILTER = shutil.which("nft") or "/usr/bin/nft"


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
    ap.add_argument("--list-dir", type=Path, default=SCRIPT_DIR / "ipsum",
                    help="directory where the downloaded feed is kept "
                         "(default: %(default)s)")
    ap.add_argument("--url", default=FEED_URL, metavar="URL",
                    help="feed URL to download (default: %(default)s)")
    ap.add_argument("--list", type=Path, default=None, metavar="FILE",
                    help="parse FILE instead of downloading the feed")
    ap.add_argument("--no-fetch", action="store_true",
                    help="do not download the feed; use the last local copy")
    ap.add_argument("--min-score", type=int, default=1, metavar="N",
                    help="only include IPs listed on >= N blacklists (upstream recommends 3)")
    ap.add_argument("--add", action="append", default=[], metavar="IP",
                    help="extra IP or CIDR to always include (repeatable, comma-separated OK); "
                         "not subject to --min-score, merged when --merge is used")
    ap.add_argument("--merge", action="store_true",
                    help="merge adjacent/overlapping prefixes (e.g. 256 x /32 -> /24)")
    ap.add_argument("--table", default="ipsum", help="nftables table name")
    ap.add_argument("--set", default="blocklist", help="nftables set name")
    ap.add_argument("--chains", default="both",
                    choices=["both", "all", "input", "output", "forward", "none"],
                    help="drop chains to generate (all = input+output+forward, for routers)")
    ap.add_argument("--output", type=Path, default=SCRIPT_DIR / "ipsum.nft",
                    help="output file (chunk files are written next to it)")
    ap.add_argument("--chunk", type=int, default=0, metavar="N",
                    help="split element adds into N-element files (0 = single file)")
    loggrp = ap.add_mutually_exclusive_group()
    loggrp.add_argument("--log", action="store_true",
                        help="rate-limited kernel log (journald) for outbound hits "
                             "(output daddr + forward daddr = our side contacting a blocked IP)")
    loggrp.add_argument("--log-group", type=int, default=None, metavar="N",
                        help="send outbound hits to NFLOG group N for a userspace reader "
                             "(e.g. the lateral-hoihoi daemon: full record incl. src/dst MAC)")
    ap.add_argument("--log-rate", default="10/minute", metavar="RATE",
                     help="rate limit for --log: positive integer + unit "
                          "(second|minute|hour|day|week), default: %(default)s")
    ap.add_argument("--install", action="store_true",
                    help="load the generated file into the running kernel (root)")
    args = ap.parse_args()

    if args.command == "uninstall":
        state = args.output.parent / (args.output.name + ".state")
        uninstall(args.table, state)
        return

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
