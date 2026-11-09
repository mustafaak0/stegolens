# 🕵️ StegoLens

> LSB steganography & steganalysis toolkit — hide secrets in plain pixels, then learn how they get caught.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![OpenCV](https://img.shields.io/badge/OpenCV-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)](https://opencv.org)
[![NumPy](https://img.shields.io/badge/NumPy-4DABCF?style=for-the-badge&logo=numpy&logoColor=white)](https://numpy.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00E676?style=for-the-badge&labelColor=0D1117)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

## 🎯 What It Does

| Command | Purpose |
|---------|---------|
| `embed` | Hide a UTF-8 message in an image's LSBs (1 or 2 bits/channel) |
| `extract` | Recover the message (needs the same key & bit depth) |
| `analyze` | **Steganalysis**: Westfeld–Pfitzmann chi-square POV attack + LSB statistics |
| `planes` | Export bit-plane visualizations (spot hidden patterns with your eyes) |

Optional **keyed embedding**: a passphrase seeds a PRNG that shuffles carrier
pixels, spreading the payload across the image instead of a suspicious
sequential block.

## 🚀 Usage

```bash
pip install -r requirements.txt

# hide a message
python stegolens.py embed -i cover.png -o stego.png -m "SF:{gizli_proje}:2026" -k kaptan
# [+] embedded 21 bytes → stego.png
#     PSNR(cover, stego) = 86.26 dB   ← visually indistinguishable

# recover it
python stegolens.py extract -i stego.png -k kaptan
# SF:{gizli_proje}:2026

# hunt for hidden data
python stegolens.py analyze -i suspect.png
python stegolens.py planes -i suspect.png --all
```

## 🧪 Verified Behavior

| Test | Result |
|------|--------|
| Embed/extract roundtrip (sequential, keyed, 2-LSB) | ✅ byte-exact |
| Wrong key | ✅ rejected (`no payload found`) |
| PNG file roundtrip | ✅ lossless |
| Clean image chi-square | p = 0.0003 → *"likely clean"* ✔ |
| 120 KB random payload, 2-LSB | p = 0.9530 → *"⚠ HIGH suspicion"* |
| PSNR after small embed | ~86 dB (imperceptible) |

**Fun forensics fact discovered during testing:** a payload of only uppercase
ASCII (`A-Z`) is *harder* to detect than random bytes — those bytes carry
constant `0` bits in positions 7 and 5, which biases the LSB plane *toward*
natural-image statistics. Structure leaks; entropy doesn't hide.

## 🧠 How the Detection Works

LSB embedding randomizes the low bits of pixel values. Statistically this
flattens **Pairs of Values** (`2i` vs `2i+1`) in the histogram — natural
images have asymmetric pairs, fully embedded ones are near-uniform. The
chi-square test measures exactly that asymmetry:

```
H₀ (clean):      h[2i] significantly different from h[2i+1]  → low p
H₁ (embedded):   h[2i] ≈ h[2i+1]                              → p → 1
```

Payloads far below capacity (e.g. 21 bytes in a 512×512 image ≈ 0.02%)
evade this attack — the untouched 99.98% preserves natural asymmetry.
That's not a bug, that's operational security reality.

## ⚖️ Disclaimer

Built for **education, CTF challenges and defensive steganalysis research**.
Don't hide data where you're not allowed to, and don't assume LSB hiding is
safe — as this tool demonstrates, it's detectable.

---

<div align="center">

*The most dangerous place to hide a secret is where everyone can see it.*

</div>
