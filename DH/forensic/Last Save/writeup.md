# INCOGNITO CTF – "An Extremely Korean Forensics Challenge" – Write-up

> **Status:** the final flag is intentionally redacted in this document.
> `INCOGNITO{<redacted>}`
> Two of the four values (V2, V4) could not be proven from the evidence alone; see "Open points".

## 1. Task

A Windows 11 image (`evidence.E01`–`E04`, ~43 GB raw) is given. Four values must be found,
concatenated as UTF-8 in a fixed order, and hashed:

```
preimage = V1 || V2 || V3 || V4
flag     = "INCOGNITO{" + md5(preimage).hex() + "}"
```

## 2. Setup

- Archive (`evidence_E01.7z`, 5.7 GB) extracted with the supplied password.
- Image opened with `dissect.target` / `pyewf` (NTFS, single volume, host `DESKTOP-IT3B8CK`,
  user profile `8l4nk`).
- Full file listing (3,449 files) dumped; user data, `NPKI`, and `Program Files (x86)` carved out for analysis.
- The raw image was also scanned for keywords and file signatures (HWP, SQLite, certificate OIDs, XOR-encoded scripts).

## 3. Finding the order

The last Hangul (HWP) autosave, `AppData\Local\Hnc\HwpSave\AutoSave_20260316_021547.asv`,
is an OLE file with a deflate-compressed `BodyText/Section0` stream. Parsing it (record tag 67 = paragraph text) reveals the user's own note:

> "Signature first, shield second, eye third, document last."
> signature = public certificate (공동인증서), shield = V3 antivirus, eye = ALCapture, document = Hangul.

It also contains two sanity checks: the certificate **VID must end in `4d53`**, and all values are UTF-8 bytes concatenated with no separator.

So: **V1 = certificate (NPKI), V2 = AhnLab V3, V3 = ALCapture, V4 = Hangul document.**

## 4. Artifacts

### V1 – Public certificate (NPKI)

`C:\NPKI` contains ~25 certificates across `SignKorea`, `yessign`, `CrossCertPlus`, `TradeSign`, plus one stray copy under the user's `LocalLow`.
Every certificate carries a private OID extension `1.2.410.200004.10.1.1` (the VID, 20 bytes).
Only one certificate has a VID ending in `4d53`:
`NPKI\SignKorea\CN=이성민\SignCert.der` (subject INCOGNITO Corp / Infra Team, status VALID).
Decoys with other VIDs (expired/revoked copies of the same person) are ignored.
V1 = the VID of that certificate, hex-encoded (40 lowercase hex chars) — *value redacted*.

### V2 – AhnLab V3 quarantine

`Program Files (x86)\AhnLab\V3IS80\` holds `quarantine.db` (SQLite, 15 entries) and `quarantine\*.qdata`.
`v3.cfg` lists several "legacy" XOR keys that are dummies; the real key is the 2-byte key **`MS`** (`0x4D 0x53`, which also matches the VID suffix hint).
Decoding with `MS` produces:

- `00000002.qdata` – original path `Documents\dev\net_check.py` (`Trojan.Script.Downloader`): a Python implant with a C2 host, `SESSION_TOKEN`, `KDF_SALT`, `HMAC_PEPPER`, and a comment that traces were deleted from `alcapture.db` (row id 22, 2026-03-15 17:42:09, `secure_delete=OFF`).
- Other `.qdata` files are fillers/decoys (PE stubs with `fakehex=` markers, similar scripts with fake tokens).

The intended V2 is one of the strings inside `net_check.py` (my best guess: the C2 host; the `SESSION_TOKEN` is the alternative) — *value redacted, not verified*.

### V3 – ALCapture deleted row

`AppData\Roaming\ESTsoft\ALCapture\alcapture.db` shows 17 live rows in `capture_log`, but the `auto_capture` rows from 2026-03-15 only exist in free pages.
Reading the raw pages recovers the deleted row with `captured_at = 2026-03-15 17:42:09` (matching the note in `net_check.py`):
`screen_0315_1410.png`, 1920x1080, `window_title` = a Korean "production DB – admin console" window.
V3 = that `window_title` (Korean, 6+ bytes per syllable in UTF-8) — *value redacted*.

### V4 – Hangul document

The HWP autosaves contain only plain text paragraphs (no hidden streams, no slack data). The last one, written by 이성민 (INCOGNITO Corp / Infra Team), contains the ordering note and the sanity checks, but no clearly marked "value".
V4 is the open point; the author field / header string is the best candidate — *redacted, not verified*.

## 5. Decoys and traps

- Many JPEG EXIF fields and several HWP autosaves contain fake `INCOGNITO{...}` strings and "instructions" addressed to analysts/LLM agents ("stop carving", "confirmed flag is ..."). They are bait; none of them were used, and none match the real procedure.
- `v3.cfg` and `ALYac.ini` list misleading XOR keys (`0xA5A5`, `0xDEAD`, ...). The real key is `MS`.
- Several certificates are expired/revoked duplicates of the same name.
- Cloud cache / engine files and ALYac quarantine files are random data (no valid decryption with `KDF_SALT`/token-derived AES keys).
- No deleted MFT entries; no extra copies of the documents in unallocated space (full carve done).

## 6. Open points

- V1 and V3 are well supported (VID suffix check; deleted row id/timestamp cross-reference from the quarantined script).
- V2 (which field of `net_check.py`) and V4 (which field of the HWP document) are not defined unambiguously in the challenge text. A hash check against the scoreboard is required to confirm the combination.
- Final flag: `INCOGNITO{<redacted>}`

## 7. Tools

`py7zr`, `dissect.target`, `libewf` (`pyewf`), `olefile`, `sqlite3`, `openssl`, `pycryptodomex`, plain Python for XOR/zlib/raw carving.
