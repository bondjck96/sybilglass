#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sybilglass — offline heuristics for airdrop-list health on EVM addresses.

Signals (address-only, no RPC):
  • Hamming distance pairs/clusters on the 160-bit address payload
  • Prefix/suffix collisions (e.g., many sharing 0x0000.. or ..ffff)
  • EIP-55 checksum usage ratio
  • Vanity features: repeated nibble runs, palindromes, ultra-low entropy
  • Simple per-address "suspicion score" and list-level summary

Outputs:
  • Console preview (top flagged addresses)
  • JSON summary (--json)
  • CSV per-address scores (--csv)
  • CSV near-duplicate pairs (--pairs)
  • SVG mini-badge (--svg-badge)

Examples:
  $ python sybilglass.py analyze airdrop.csv --csv addr_scores.csv --pairs pairs.csv --json report.json
  $ python sybilglass.py analyze addrs.txt --threshold 14 --svg-badge badge.svg
  $ cat addrs.json | python sybilglass.py analyze - --json report.json
"""

import csv
import json
import math
import os
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, List, Tuple, Dict, Optional, Set

import click

# ------------------------ Utilities ------------------------

HEXCHARS = set("0123456789abcdefABCDEF")

def is_hex_address(s: str) -> bool:
    if not isinstance(s, str): return False
    s = s.strip()
    if not (s.startswith("0x") or s.startswith("0X")): return False
    h = s[2:]
    return len(h) == 40 and all(c in HEXCHARS for c in h)

def norm_addr(s: str) -> str:
    """Lowercase normalized 0x...40 hex (no checksum enforcement)."""
    s = s.strip()
    if not s.startswith("0x"): s = "0x" + s
    return "0x" + s[2:].lower()

def checksum_style(s: str) -> str:
    """Classify how the user supplied checksum: all-lower, all-upper, or mixed (EIP-55-like)."""
    h = s[2:]
    if h.islower(): return "lower"
    if h.isupper(): return "upper"
    return "mixed"

def hex_to_int40(s: str) -> int:
    return int(s[2:], 16)

def popcount(n: int) -> int:
    # Avoid Python version dependency on int.bit_count()
    return bin(n).count("1")

def hamming_hex(a: str, b: str) -> int:
    return popcount(hex_to_int40(a) ^ hex_to_int40(b))

def run_lengths(h: str) -> int:
    """Max repeated-nibble run length in 40-char hex string."""
    mx = 1
    cur = 1
    for i in range(1, len(h)):
        if h[i] == h[i-1]:
            cur += 1
            mx = max(mx, cur)
        else:
            cur = 1
    return mx

def shannon_entropy(h: str) -> float:
    """Entropy in bits per nibble for the 40-hex payload."""
    from collections import Counter
    c = Counter(h)
    n = len(h)
    ent = 0.0
    for k, v in c.items():
        p = v / n
        ent -= p * math.log2(p)
    return ent  # Max ~ log2(16)=4.0

def is_palindrome(h: str) -> bool:
    return h == h[::-1]

def prefix(h: str, n: int) -> str:
    return h[:n]

def suffix(h: str, n: int) -> str:
    return h[-n:]

# ------------------------ Data ------------------------

@dataclass
class AddrScore:
    address: str
    checksum_style: str
    max_run: int
    entropy: float
    palindrome: bool
    prefix4: str
    suffix4: str
    suspicion: float  # 0..100
    notes: List[str]

# ------------------------ Scoring ------------------------

def score_address(addr_norm: str) -> AddrScore:
    h = addr_norm[2:]  # 40 hex
    cs = checksum_style(addr_norm)
    mx = run_lengths(h)
    ent = shannon_entropy(h)
    pal = is_palindrome(h)
    p4 = prefix(h, 4)
    s4 = suffix(h, 4)

    notes: List[str] = []
    score = 0.0

    if mx >= 6:
        notes.append(f"long repeated nibble run: {mx}")
        score += min(20 + (mx - 6) * 2, 35)
    if ent < 3.0:
        notes.append(f"low entropy: {ent:.2f} bits/nibble")
        score += 15
    if p4 in ("0000", "1111", "ffff"):
        notes.append(f"vanity prefix: {p4}")
        score += 10
    if s4 in ("0000", "1111", "ffff"):
        notes.append(f"vanity suffix: {s4}")
        score += 10
    if pal:
        notes.append("palindrome payload")
        score += 10
    if cs != "mixed":
        # many wallets output lowercase; mixed suggests intentional checksum usage
        notes.append(f"non-checksummed style: {cs}")
        score += 5

    score = max(0.0, min(100.0, score))
    return AddrScore(
        address=addr_norm, checksum_style=cs, max_run=mx, entropy=ent,
        palindrome=pal, prefix4=p4, suffix4=s4, suspicion=score, notes=notes
    )

# ------------------------ I/O ------------------------

def read_addresses(path: str) -> List[str]:
    """
    Accepts:
      - '-' for stdin (one address per line or JSON array or CSV with 'address' column)
      - .txt (one per line)
      - .csv (column 'address' or first column)
      - .json (array of strings or objects with 'address')
    """
    data: List[str] = []

    def push(addr: str):
        if is_hex_address(addr):
            data.append(norm_addr(addr))

    if path == "-":
        buf = sys.stdin.read()
        # try json
        try:
            obj = json.loads(buf)
            if isinstance(obj, list):
                for it in obj:
                    if isinstance(it, str): push(it)
                    elif isinstance(it, dict) and "address" in it: push(it["address"])
                return data
        except Exception:
            pass
        # try csv lines or plain lines
        lines = [l.strip() for l in buf.splitlines() if l.strip()]
        # detect CSV header
        if lines and ("address" in lines[0].lower().split(",")):
            reader = csv.DictReader(lines)
            for row in reader:
                push(row.get("address",""))
        else:
            for l in lines:
                # maybe comma separated
                for tok in l.replace(";",",").split(","):
                    tok = tok.strip()
                    if tok: push(tok)
        return data

    ext = os.path.splitext(path)[1].lower()
    if ext in (".txt", ""):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                push(line.strip())
    elif ext == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cols = reader.fieldnames or []
            use_first = True
            col_idx = 0
            if "address" in {c.lower(): c for c in cols}:
                use_first = False
            for row in reader:
                if not row: continue
                if not use_first:
                    push(row.get("address","") or row.get("Address",""))
                else:
                    # first column heuristic
                    first = next(iter(row.values()))
                    push(first)
    elif ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, list):
            for it in obj:
                if isinstance(it, str): push(it)
                elif isinstance(it, dict) and "address" in it: push(it["address"])
    else:
        raise click.ClickException(f"Unsupported file type: {ext}")

    return data

# ------------------------ Pairwise proximity ------------------------

def near_pairs(addrs: List[str], threshold: int = 12, sample_limit: int = 1200000) -> List[Tuple[str, str, int]]:
    """
    Find near-duplicate pairs by Hamming distance on 160-bit payloads.
    threshold: maximum distance (nibbles/bit-level via XOR popcount)
    sample_limit: cap on pair comparisons to avoid O(n^2) blow-ups
    """
    n = len(addrs)
    pairs: List[Tuple[str, str, int]] = []
    # Heuristic: compare within same 6-hex prefix buckets to reduce pairs drastically
    buckets: Dict[str, List[str]] = {}
    for a in addrs:
        buckets.setdefault(a[2:2+6], []).append(a)

    compared = 0
    for _, group in buckets.items():
        m = len(group)
        for i in range(m):
            for j in range(i+1, m):
                if compared >= sample_limit:
                    return pairs
                d = hamming_hex(group[i], group[j])
                compared += 1
                if d <= threshold:
                    pairs.append((group[i], group[j], d))
    return pairs

# ------------------------ CLI ------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """sybilglass — offline airdrop-list analyzer for EVM addresses."""
    pass

@cli.command("analyze")
@click.argument("input_path", type=str)
@click.option("--threshold", type=int, default=12, show_default=True,
              help="Hamming distance threshold for near-duplicate pairs (lower = stricter).")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None,
              help="Write JSON summary report.")
@click.option("--csv", "csv_out", type=click.Path(writable=True), default=None,
              help="Write per-address CSV scores.")
@click.option("--pairs", "pairs_out", type=click.Path(writable=True), default=None,
              help="Write CSV of near-duplicate address pairs.")
@click.option("--svg-badge", "svg_out", type=click.Path(writable=True), default=None,
              help="Write a tiny SVG badge summarizing list health.")
def analyze_cmd(input_path, threshold, json_out, csv_out, pairs_out, svg_out):
    """Analyze addresses from TXT/CSV/JSON or '-' for stdin."""
    addrs = read_addresses(input_path)
    if not addrs:
        raise click.ClickException("No valid addresses found.")

    unique = list(sorted(set(addrs)))
    dup_count = len(addrs) - len(unique)

    scores: List[AddrScore] = [score_address(a) for a in unique]

    # Aggregates
    cs_mix = {"lower":0, "upper":0, "mixed":0}
    pfx4: Dict[str,int] = {}
    sfx4: Dict[str,int] = {}
    vanity_runs = 0
    low_entropy = 0
    for s in scores:
        cs_mix[s.checksum_style] += 1
        pfx4[s.prefix4] = pfx4.get(s.prefix4, 0) + 1
        sfx4[s.suffix4] = sfx4.get(s.suffix4, 0) + 1
        if s.max_run >= 6: vanity_runs += 1
        if s.entropy < 3.0: low_entropy += 1

    # Identify heavy collisions
    top_pfx = sorted(pfx4.items(), key=lambda kv: -kv[1])[:5]
    top_sfx = sorted(sfx4.items(), key=lambda kv: -kv[1])[:5]

    # Near pairs by Hamming distance
    pairs = near_pairs(unique, threshold=threshold)

    # List-level health index (0..100; higher = riskier)
    # components: dup ratio, pairs density, vanity ratio, low-entropy ratio, checksum style skew
    n = len(unique)
    dup_ratio = dup_count / max(1, len(addrs))
    pair_density = len(pairs) / max(1, n)  # scaled per address
    vanity_ratio = vanity_runs / max(1, n)
    lowent_ratio = low_entropy / max(1, n)
    checksum_skew = 1.0 - (cs_mix["mixed"] / max(1, n))  # if many not mixed, skew larger

    health = min(100.0, (
        dup_ratio * 100 * 0.25 +
        pair_density * 100 * 0.30 +
        vanity_ratio * 100 * 0.20 +
        lowent_ratio * 100 * 0.15 +
        checksum_skew * 100 * 0.10
    ))

    # Console preview: top 10 suspicious
    top10 = sorted(scores, key=lambda s: -s.suspicion)[:10]
    preview = [{
        "address": s.address,
        "suspicion": round(s.suspicion, 2),
        "notes": s.notes[:3]
    } for s in top10]
    click.echo(json.dumps({
        "total_input": len(addrs),
        "unique": n,
        "duplicates": dup_count,
        "health_index": round(health, 2),
        "near_pairs": len(pairs),
        "preview_top10": preview
    }, indent=2))

    # Write outputs
    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["address","suspicion","checksum_style","max_run","entropy","palindrome","prefix4","suffix4","notes"])
            w.writeheader()
            for s in scores:
                row = asdict(s)
                row["notes"] = "; ".join(row["notes"])
                w.writerow(row)
        click.echo(f"Wrote per-address CSV: {csv_out}")

    if pairs_out:
        with open(pairs_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["addr1","addr2","hamming_distance"])
            for a,b,d in pairs:
                w.writerow([a,b,d])
        click.echo(f"Wrote near-duplicate pairs CSV: {pairs_out}")

    if json_out:
        report = {
            "totals": {
                "input": len(addrs),
                "unique": n,
                "duplicates": dup_count
            },
            "health_index": health,
            "checksum_mix": cs_mix,
            "top_prefix4": top_pfx,
            "top_suffix4": top_sfx,
            "vanity_runs_ge6": vanity_runs,
            "low_entropy_lt3": low_entropy,
            "threshold_hamming": threshold,
            "near_pairs_count": len(pairs)
        }
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        ok = max(0, 100 - int(round(health)))
        color = "#3fb950" if ok >= 66 else "#d29922" if ok >= 33 else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="370" height="48" role="img" aria-label="Airdrop list health">
  <rect width="370" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    sybilglass: health {100 - int(round(health))}/100
  </text>
  <circle cx="345" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

@cli.command("explain")
def explain_cmd():
    """Explain the heuristics and how to interpret results."""
    msg = {
        "signals": {
            "hamming_pairs": "Addresses very close in 160-bit space suggest scripted/vanity derivation.",
            "prefix_suffix_collisions": "Many addresses sharing the same first/last 4 hex nibbles.",
            "checksum_style": "Mixed-case (EIP-55) vs all-lower/upper; skew may indicate generation pipeline.",
            "vanity_runs": "Long sequences of the same nibble (e.g., 000000) are rare at random.",
            "entropy": "Per-nibble Shannon entropy; unusually low may mean constrained generation."
        },
        "health_index": "0..100 (higher = riskier). Combines duplicates, pair density, vanity & entropy ratios, checksum skew.",
        "advice": [
            "Investigate clusters in pairs.csv (low Hamming distance).",
            "Spot-check top suspicious addresses and their on-chain activity (outside this tool).",
            "Adjust --threshold to 10–16 depending on list size; lower is stricter."
        ]
    }
    click.echo(json.dumps(msg, indent=2))

if __name__ == "__main__":
    cli()
