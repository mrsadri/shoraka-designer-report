#!/usr/bin/env python3
"""
Build step: produce a two-tier encrypted static report.

Tiers
-----
  * MAIN password  -> decrypts the ANONYMIZED report (names, salaries,
    companies, phones all redacted). This is the default view.
  * SECOND password -> decrypts the FULL report (real names/salaries/
    companies) AND the candidate PDFs. Required to turn the privacy
    switch off and to download files.

Because anonymization happens HERE (at build time), the real names and
numbers are NOT present in the main-encrypted payload at all — only the
anonymized text is. The full text and PDFs are separately encrypted with
the second password. The published site is pure ciphertext either way.

Crypto (compatible with browser SubtleCrypto AES-GCM):
  - one random 16-byte salt for the build
  - keyMain   = PBKDF2-SHA256(password1, salt, ITER)
  - keyReveal = PBKDF2-SHA256(password2, salt, ITER)
  - each blob = iv(12) || AESGCM(iv, plaintext)  (tag appended by GCM)

Plaintext inputs (git-ignored): src/report.html, files/<person>/*.pdf
Usage:  PASSWORD='...' PASSWORD2='...' python3 build/encrypt.py
"""
import base64
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent.parent
ITERATIONS = 250_000

# Passwords are read from the environment ONLY. They must never be written
# into this file — it is published to a public repository.
#   PASSWORD  = main password  (opens the anonymized report)
#   PASSWORD2 = second password (reveals full report + enables downloads)
_pw1 = os.environ.get("PASSWORD")
_pw2 = os.environ.get("PASSWORD2")
if not _pw1 or not _pw2:
    sys.exit(
        "Set both PASSWORD and PASSWORD2 environment variables, e.g.:\n"
        "  PASSWORD='...' PASSWORD2='...' python3 build/encrypt.py"
    )
PASSWORD = _pw1.encode("utf-8")
PASSWORD2 = _pw2.encode("utf-8")

MAP_RE = re.compile(
    r'<script[^>]*id="anon-map"[^>]*>([\s\S]*?)</script>\s*', re.IGNORECASE
)
SVAL_RE = re.compile(r'<span class="sval">[^<]*</span>')
REFTEL_RE = re.compile(r'<a class="reftel"[^>]*>[^<]*</a>')

SVAL_RED = (
    '<span class="sval red" title="مبلغ در حالت حریم خصوصی مخفی است">•••</span>'
)
REFTEL_RED = (
    '<span class="reftel red" title="شماره در حالت حریم خصوصی مخفی است">'
    "••• • •••• •••</span>"
)

PDFS = [
    ("ghazaleh-ebrahimi", "interview-report.pdf", "interview-report.enc"),
    ("ghazaleh-ebrahimi", "resume.pdf", "resume.enc"),
    ("amir-souri", "interview-report.pdf", "interview-report.enc"),
    ("amir-souri", "resume.pdf", "resume.enc"),
    ("yasaman-hajmoosa", "interview-report.pdf", "interview-report.enc"),
    ("yasaman-hajmoosa", "resume.pdf", "resume.enc"),
]


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS
    )
    return kdf.derive(password)


def seal(aes: AESGCM, plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + aes.encrypt(iv, plaintext, None)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def anonymize(html: str, name_map) -> str:
    out = html
    for frm, to in name_map:
        out = out.replace(frm, to)  # names + companies
    out = SVAL_RE.sub(SVAL_RED, out)  # salaries
    out = REFTEL_RE.sub(REFTEL_RED, out)  # phones
    return out


def main() -> int:
    raw = (ROOT / "src" / "report.html").read_text(encoding="utf-8")
    m = MAP_RE.search(raw)
    if not m:
        print("!! anon-map block not found in src/report.html", file=sys.stderr)
        return 1
    name_map = json.loads(m.group(1))
    real_html = MAP_RE.sub("", raw, count=1)  # full report, map stripped
    anon_html = anonymize(real_html, name_map)  # default (privacy-on) view

    # sanity: the anonymized view must leak none of the mapped originals
    leaked = sorted({frm for frm, _ in name_map if frm in anon_html})
    if leaked:
        print("!! anonymized view still contains:", leaked, file=sys.stderr)
        return 2

    salt = os.urandom(16)
    aes_main = AESGCM(derive_key(PASSWORD, salt))
    aes_reveal = AESGCM(derive_key(PASSWORD2, salt))

    payload = {
        "v": 2,
        "kdf": "PBKDF2-SHA256",
        "iter": ITERATIONS,
        "salt": b64(salt),
        # tier 1 (main password): anonymized report
        "verifier": b64(seal(aes_main, b"shoraka-report-ok")),
        "content": b64(seal(aes_main, anon_html.encode("utf-8"))),
        # tier 2 (second password): full report
        "rverifier": b64(seal(aes_reveal, b"shoraka-reveal-ok")),
        "full": b64(seal(aes_reveal, real_html.encode("utf-8"))),
    }
    (ROOT / "data").mkdir(exist_ok=True)
    (ROOT / "data" / "payload.js").write_text(
        "window.PAYLOAD = " + json.dumps(payload) + ";\n", encoding="utf-8"
    )
    print(
        f"data/payload.js  (anon {len(anon_html)} B / full {len(real_html)} B)"
    )

    # PDFs -> encrypted with the SECOND password (download requires reveal)
    for person, src_name, out_name in PDFS:
        src = ROOT / "files" / person / src_name
        if not src.exists():
            print(f"!! missing {src} — skipped", file=sys.stderr)
            continue
        blob = seal(aes_reveal, src.read_bytes())
        out = ROOT / "data" / "files" / person / out_name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
        print(f"data/files/{person}/{out_name}  ({src.stat().st_size} B)")

    print("\nDone. Anonymized view = main password; full + PDFs = second password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
