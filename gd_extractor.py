#!/usr/bin/env python3
"""
gd_extractor.py - Geometry Dash save-file extractor (CLI)

Mirrors the HTML version: tries every known XOR / base64 / gzip combo to
decode CCGameManager(.dat|2.dat) / CCLocalLevels(.dat|2.dat), flags
credential-looking plist fields, tries the GJP-style secondary decode
(base64 -> XOR-37) on those, and ALSO scans the whole decoded output for
any other base64-looking substrings and attempts to decode those too.

Usage:
    python gd_extractor.py CCGameManager2.dat
    python gd_extractor.py CCGameManager2.dat -o decoded.xml
    python gd_extractor.py CCGameManager2.dat --no-scan-base64

Everything runs locally. No network access, nothing is uploaded.
"""

import argparse
import base64
import re
import sys
import zlib
from pathlib import Path

XOR_SAVE_KEY = 11   # outer save-file obfuscation key
XOR_GJP_KEY = 37    # legacy GJP password-field obfuscation key

CRED_PATTERN = re.compile(r"pass|pwd|usn|user|login|gjp|udid|account|token|secret|email", re.I)
KV_PATTERN = re.compile(r"<k>([^<]*)</k><([a-z]+)>([^<]*)</\2>", re.I)

# A substring worth trying as base64: reasonably long, valid base64 alphabet
# (with optional url-safe chars and padding).
BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")


# --------------------------------------------------------------------------
# Core decode chain
# --------------------------------------------------------------------------

def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def clean_b64(s: str, urlsafe: bool) -> str:
    allowed = re.compile(r"[^A-Za-z0-9\-_]" if urlsafe else r"[^A-Za-z0-9+/]")
    s = allowed.sub("", s)
    if urlsafe:
        s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return s


def inflate_any(raw: bytes):
    for fn in (
        lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS),  # gzip
        lambda d: zlib.decompress(d, zlib.MAX_WBITS),       # zlib
        lambda d: zlib.decompress(d, -zlib.MAX_WBITS),      # raw deflate
    ):
        try:
            return fn(raw)
        except Exception:
            continue
    return None


def decode_gd_save(raw_bytes: bytes):
    """
    Tries every known combination. Returns (xml_text, method_label).
    Raises ValueError if nothing worked.
    """
    attempts = []

    for key in (XOR_SAVE_KEY, 0):
        xored = xor_bytes(raw_bytes, key) if key else raw_bytes
        try:
            as_str = xored.decode("latin1")
        except Exception:
            continue
        for urlsafe in (True, False):
            def make_attempt(as_str=as_str, urlsafe=urlsafe, key=key):
                def run():
                    b64 = clean_b64(as_str, urlsafe)
                    raw = base64.b64decode(b64)
                    inflated = inflate_any(raw)
                    if inflated is None:
                        raise ValueError("inflate failed")
                    return inflated
                return run
            label = f"{'XOR-' + str(key) if key else 'no XOR'} -> {'url-safe' if urlsafe else 'standard'} base64 -> gzip/zlib"
            attempts.append((label, make_attempt()))

    # Fallback: maybe no base64 layer at all
    for key in (XOR_SAVE_KEY, 0):
        def make_attempt(key=key):
            def run():
                xored = xor_bytes(raw_bytes, key) if key else raw_bytes
                inflated = inflate_any(xored)
                if inflated is None:
                    raise ValueError("inflate failed")
                return inflated
            return run
        label = f"{'XOR-' + str(key) if key else 'no XOR'} -> gzip/zlib (no base64)"
        attempts.append((label, make_attempt()))

    weak_candidate = None
    for label, run in attempts:
        try:
            inflated = run()
            text = inflated.decode("utf-8", errors="replace")
            if "<plist" in text or "<dict" in text or text.strip().startswith("<"):
                return text, label
            if weak_candidate is None and len(text) > 20:
                weak_candidate = (text, label)
        except Exception:
            continue

    if weak_candidate:
        text, label = weak_candidate
        return text, label + " (unverified - output did not look like plist XML)"

    raise ValueError(
        "none of the known XOR/base64/gzip combinations produced readable output "
        "- this may not be a standard GD save file"
    )


# --------------------------------------------------------------------------
# Credential-field scan + GJP-style secondary decode
# --------------------------------------------------------------------------

def try_gjp_decode(value: str):
    """base64-decode -> XOR-37, return printable string or None."""
    if not value or len(value) < 4:
        return None
    try:
        b64 = value.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)
        out = bytes(b ^ XOR_GJP_KEY for b in raw)
        text = out.decode("ascii")
        if re.fullmatch(r"[\x20-\x7e]+", text) and len(text) >= 3:
            return text
    except Exception:
        pass
    return None


def find_credential_pairs(xml_text: str):
    hits = []
    for m in KV_PATTERN.finditer(xml_text):
        key, _type, val = m.group(1), m.group(2), m.group(3)
        if CRED_PATTERN.search(key):
            hits.append((key, val, try_gjp_decode(val)))
    return hits


# --------------------------------------------------------------------------
# Generic nested base64 extraction (the "extract base64'd content too" part)
# --------------------------------------------------------------------------

def scan_for_base64_blobs(xml_text: str, min_len: int = 24, max_results: int = 200):
    """
    Finds base64-looking substrings anywhere in the decoded XML (not just
    tagged credential fields) and tries to decode each one. Reports any
    that decode to printable text (raw) or, failing that, to printable
    text after an extra XOR-37 (in case it's a GJP-style blob that wasn't
    caught by the key-name heuristic).
    """
    seen = set()
    results = []
    for m in BASE64_CANDIDATE.finditer(xml_text):
        candidate = m.group(0)
        if candidate in seen or len(candidate) < min_len:
            continue
        seen.add(candidate)

        decoded_plain = None
        decoded_xor37 = None

        try:
            b64 = candidate.replace("-", "+").replace("_", "/")
            b64 += "=" * (-len(b64) % 4)
            raw = base64.b64decode(b64, validate=False)

            try:
                text = raw.decode("utf-8")
                if re.fullmatch(r"[\x20-\x7e\s]+", text) and len(text.strip()) >= 3:
                    decoded_plain = text
            except Exception:
                pass

            if decoded_plain is None:
                try:
                    xored = bytes(b ^ XOR_GJP_KEY for b in raw)
                    text = xored.decode("ascii")
                    if re.fullmatch(r"[\x20-\x7e]+", text) and len(text.strip()) >= 3:
                        decoded_xor37 = text
                except Exception:
                    pass
        except Exception:
            continue

        if decoded_plain or decoded_xor37:
            results.append({
                "blob": candidate if len(candidate) <= 80 else candidate[:77] + "...",
                "plain": decoded_plain,
                "xor37": decoded_xor37,
            })
            if len(results) >= max_results:
                break

    return results


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Decode Geometry Dash save files (.dat) locally.")
    ap.add_argument("input", help="Path to the .dat save file (e.g. CCGameManager2.dat)")
    ap.add_argument("-o", "--out", help="Write decoded plist XML to this path")
    ap.add_argument("--no-scan-base64", action="store_true",
                     help="Skip the generic nested-base64 scan of the whole file")
    ap.add_argument("--min-blob-len", type=int, default=24,
                     help="Minimum length of a substring to try as base64 (default: 24)")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"error: file not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    raw_bytes = in_path.read_bytes()
    print(f"[*] {in_path.name}  ({len(raw_bytes):,} bytes)")

    try:
        xml_text, method = decode_gd_save(raw_bytes)
    except ValueError as e:
        print(f"[!] decode failed: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"[+] decoded via: {method}")
    print(f"[+] output length: {len(xml_text):,} characters")

    out_path = Path(args.out) if args.out else in_path.with_suffix(".xml")
    out_path.write_text(xml_text, encoding="utf-8")
    print(f"[+] wrote decoded XML -> {out_path}")

    # Credential-looking plist fields (key-name based)
    hits = find_credential_pairs(xml_text)
    print(f"\n[*] credential-looking field(s): {len(hits)}")
    for key, val, decoded in hits:
        print(f"    {key} = {val}")
        if decoded:
            print(f"        -> (XOR-37 decode): {decoded}")

    # Generic base64 blob scan across the whole decoded output
    if not args.no_scan_base64:
        blobs = scan_for_base64_blobs(xml_text, min_len=args.min_blob_len)
        print(f"\n[*] other decodable base64 blob(s) found anywhere in the file: {len(blobs)}")
        for b in blobs:
            print(f"    {b['blob']}")
            if b["plain"]:
                print(f"        -> plain base64 decode: {b['plain']!r}")
            if b["xor37"]:
                print(f"        -> base64 + XOR-37 decode: {b['xor37']!r}")

    if not hits and (args.no_scan_base64 or not blobs):
        print("\n[*] nothing that looks like a password/token turned up.")


if __name__ == "__main__":
    main()
