#!/usr/bin/env python3
"""
StegoLens — LSB steganography & steganalysis toolkit (educational/defensive).

Hide messages inside images with LSB embedding (optional keyed PRNG
position shuffling), extract them back, and run steganalysis
(chi-square POV attack, bit-plane visualization) to detect hidden data.

Pure NumPy array math on top of OpenCV I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import sys
from pathlib import Path

import cv2
import numpy as np

MAGIC = "STGL1"          # 5-byte protocol marker
LEN_BYTES = 4            # payload length field
DEFAULT_BITS = 1         # LSBs per channel used for embedding


# ----------------------------------------------------------------------------
# carrier mapping (shared by embed & extract so they always agree)
# ----------------------------------------------------------------------------

def _carrier_map(shape, n_bits: int, bits: int, key: str | None):
    """Map stream bit index → (flat_pixel_idx, channel, sub-bit position).

    Order: pixels in (optionally shuffled) sequence; within a pixel,
    channels B→G→R, each carrying `bits` consecutive stream bits in its
    least-significant bit slots.
    """
    h, w, ch = shape
    per_pixel = ch * bits
    n_pixels = math.ceil(n_bits / per_pixel)
    if n_pixels > h * w:
        raise ValueError(
            f"message too large: needs {n_bits} carrier bits, "
            f"image holds {h*w*per_pixel}"
        )
    pixels = np.arange(h * w)
    if key:
        seed = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
        pixels = np.random.default_rng(seed).permutation(pixels)
    pixels = pixels[:n_pixels]

    carriers = np.repeat(pixels, per_pixel)[:n_bits]
    slots = np.tile(np.arange(per_pixel), n_pixels)[:n_bits]
    return carriers, slots // bits, slots % bits


# ----------------------------------------------------------------------------
# embed / extract
# ----------------------------------------------------------------------------

def embed(img: np.ndarray, message: bytes, bits: int = DEFAULT_BITS,
          key: str | None = None) -> np.ndarray:
    payload = MAGIC.encode() + len(message).to_bytes(LEN_BYTES, "big") + message
    stream = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    out = img.copy()
    flat = out.reshape(-1, img.shape[2])
    carriers, chans, sub = _carrier_map(img.shape, len(stream), bits, key)
    for b in range(bits):
        sel = sub == b
        flat[carriers[sel], chans[sel]] &= np.uint8(~(1 << b) & 0xFF)
        flat[carriers[sel], chans[sel]] |= stream[sel].astype(np.uint8) << np.uint8(b)
    return out


def extract(img: np.ndarray, bits: int = DEFAULT_BITS,
            key: str | None = None) -> bytes:
    flat = img.reshape(-1, img.shape[2])
    header_len = (len(MAGIC) + LEN_BYTES) * 8
    cap = flat.shape[0] * flat.shape[1] * bits

    def read(n_bits: int) -> np.ndarray:
        carriers, chans, sub = _carrier_map(img.shape, n_bits, bits, key)
        out = np.zeros(n_bits, dtype=np.uint8)
        for b in range(bits):
            sel = sub == b
            out[sel] = (flat[carriers[sel], chans[sel]] >> np.uint8(b)) & np.uint8(1)
        return out

    header = np.packbits(read(header_len)).tobytes()
    if not header.startswith(MAGIC.encode()):
        raise ValueError("no StegoLens payload found (wrong key, bit depth, or clean image)")
    n = int.from_bytes(header[len(MAGIC):], "big")
    if n < 0 or (header_len + n * 8) > cap:
        raise ValueError("corrupt header: implausible payload length")
    return np.packbits(read(header_len + n * 8)[header_len:]).tobytes()[:n]


# ----------------------------------------------------------------------------
# steganalysis
# ----------------------------------------------------------------------------

def _gammq(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) — p-value helper (no scipy)."""
    if x <= 0 or a <= 0:
        return 1.0
    lg = math.lgamma(a)
    if x < a + 1.0:                      # series for P, then Q = 1 - P
        ap, s, d = a, 1.0 / a, 1.0 / a
        for _ in range(1000):
            ap += 1.0
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-14:
                break
        return 1.0 - s * math.exp(-x + a * math.log(x) - lg)
    b, c, d, h = x + 1.0 - a, 1e300, 1.0 / (x + 1.0 - a), 1.0 / (x + 1.0 - a)
    for i in range(1, 1000):             # continued fraction for Q
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return math.exp(-x + a * math.log(x) - lg) * h


def chi_square_attack(img: np.ndarray, channel: int, min_expected: float = 4.0) -> float:
    """Westfeld–Pfitzmann chi-square POV attack. High p-value ⇒ suspicious."""
    hist = np.bincount(img[:, :, channel].ravel(), minlength=256).astype(float)
    obs, exp = hist[0::2], (hist[0::2] + hist[1::2]) / 2.0
    keep = exp > min_expected
    if keep.sum() < 4:
        return 0.0
    chi2 = float(np.sum((obs[keep] - exp[keep]) ** 2 / exp[keep]))
    dof = int(keep.sum()) - 1
    return _gammq(dof / 2.0, chi2 / 2.0)


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    mse = float(np.mean((a.astype(float) - b.astype(float)) ** 2))
    return float("inf") if mse == 0 else 10.0 * math.log10(255.0 ** 2 / mse)


def analyze(img: np.ndarray) -> dict:
    stats = {}
    for c, name in enumerate("BGR"):
        stats[name] = {
            "chi2_p": chi_square_attack(img, c),
            "lsb_mean": float(np.mean(img[:, :, c] & 1)),
        }
    p = max(v["chi2_p"] for v in stats.values())
    stats["verdict"] = (
        "⚠ HIGH suspicion of LSB steganography (PoV histogram near-uniform)"
        if p > 0.90 else
        "? WEAK suspicion — inconclusive"
        if p > 0.50 else
        "✔ likely clean (natural PoV asymmetry present)"
    )
    return stats


# ----------------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------------

def cmd_embed(args) -> None:
    img = cv2.imread(args.input, cv2.IMREAD_COLOR)
    if img is None:
        sys.exit(f"[!] cannot read image: {args.input}")
    stego = embed(img, args.message.encode("utf-8"), bits=args.bits, key=args.key)
    if not cv2.imwrite(args.output, stego):
        sys.exit(f"[!] cannot write: {args.output}")
    print(f"[+] embedded {len(args.message.encode())} bytes → {args.output}")
    print(f"    bits/LSB={args.bits}  key={'yes' if args.key else 'no (sequential)'}")
    print(f"    PSNR(cover, stego) = {psnr(img, stego):.2f} dB")


def cmd_extract(args) -> None:
    img = cv2.imread(args.input, cv2.IMREAD_COLOR)
    if img is None:
        sys.exit(f"[!] cannot read image: {args.input}")
    try:
        msg = extract(img, bits=args.bits, key=args.key)
    except ValueError as e:
        sys.exit(f"[!] {e}")
    print(f"[+] extracted {len(msg)} bytes:\n\n{msg.decode('utf-8', errors='replace')}")


def cmd_analyze(args) -> None:
    img = cv2.imread(args.input, cv2.IMREAD_COLOR)
    if img is None:
        sys.exit(f"[!] cannot read image: {args.input}")
    stats = analyze(img)
    print(f"[*] image: {args.input}  ({img.shape[1]}x{img.shape[0]}, 3 channels)")
    for name in ("B", "G", "R"):
        s = stats[name]
        print(f"    {name}: chi2 p={s['chi2_p']:.4f}   lsb_mean={s['lsb_mean']:.4f} (random≈0.5)")
    print(f"\n    {stats['verdict']}")
    if args.reference:
        ref = cv2.imread(args.reference, cv2.IMREAD_COLOR)
        if ref is not None:
            print(f"    PSNR vs reference = {psnr(ref, img):.2f} dB")


def cmd_planes(args) -> None:
    img = cv2.imread(args.input, cv2.IMREAD_COLOR)
    if img is None:
        sys.exit(f"[!] cannot read image: {args.input}")
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    bit_list = range(8) if args.all else (0,)
    for c, name in enumerate("BGR"):
        for p in bit_list:
            plane = ((img[:, :, c] >> p) & 1) * 255
            out = outdir / f"{Path(args.input).stem}_{name}_bit{p}.png"
            cv2.imwrite(str(out), plane)
    print(f"[+] wrote bit-plane images → {outdir}/ ({'all 8' if args.all else 'LSB only'})")


def main() -> None:
    p = argparse.ArgumentParser(description="StegoLens — LSB steganography & steganalysis toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("embed", help="hide a message inside an image")
    e.add_argument("-i", "--input", required=True)
    e.add_argument("-o", "--output", required=True)
    e.add_argument("-m", "--message", required=True)
    e.add_argument("-b", "--bits", type=int, default=DEFAULT_BITS, choices=(1, 2))
    e.add_argument("-k", "--key", help="shuffle carrier positions with this passphrase")
    e.set_defaults(fn=cmd_embed)

    x = sub.add_parser("extract", help="recover a hidden message")
    x.add_argument("-i", "--input", required=True)
    x.add_argument("-b", "--bits", type=int, default=DEFAULT_BITS, choices=(1, 2))
    x.add_argument("-k", "--key")
    x.set_defaults(fn=cmd_extract)

    a = sub.add_parser("analyze", help="steganalysis: chi-square POV attack + stats")
    a.add_argument("-i", "--input", required=True)
    a.add_argument("-r", "--reference", help="optional original cover for PSNR")
    a.set_defaults(fn=cmd_analyze)

    pl = sub.add_parser("planes", help="export bit-plane visualizations")
    pl.add_argument("-i", "--input", required=True)
    pl.add_argument("-o", "--output", default="planes")
    pl.add_argument("--all", action="store_true", help="all 8 bit-planes, not just LSB")
    pl.set_defaults(fn=cmd_planes)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
