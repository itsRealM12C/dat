# gd-save-extractor

Decode Geometry Dash save files (`CCGameManager.dat`, `CCGameManager2.dat`,
`CCLocalLevels.dat`, `CCLocalLevels2.dat`) into readable plist XML, and flag
(and where possible, decode) credential-looking fields — entirely locally,
no network requests.

Two equivalent implementations are included:

- **`gd-save-extractor.html`** — a self-contained browser tool. Open it in
  any browser, drop a `.dat` file in, done.
- **`gd_extractor.py`** — the same logic as a stdlib-only CLI.

## The format

Geometry Dash's save files aren't encrypted in any cryptographically
meaningful sense — they're reversible obfuscation, no secret key required:

```
raw file bytes
  --XOR every byte with 11-->
  base64 text (url-safe variant)
  --base64 decode-->
  gzip-compressed bytes
  --gzip inflate-->
  plist XML
```

Some save variants differ slightly (no XOR, standard base64, zlib/raw-deflate
instead of gzip) — both tools try every combination and report which one
worked.

### About the password field

- **`GJP`** (legacy field): reversible. `base64 decode -> XOR each byte with
  37` gets you the plaintext password back.
- **`GJP2`** (current field): a one-way **bcrypt hash**. This cannot be
  reversed by this tool or any tool — that's the point of a hash. Don't
  expect it to "decrypt."

Both tools scan for a broad set of credential-looking key names
(`pass|pwd|usn|user|login|gjp|udid|account|token|secret|email`) — this will
catch some false positives (GD's own achievement system uses keys like
`secret01` for unrelated unlock flags), so sanity-check what's actually
printed rather than assuming every hit is sensitive.

## Usage

```
python3 gd_extractor.py CCGameManager2.dat
python3 gd_extractor.py CCGameManager2.dat -o decoded.xml
python3 gd_extractor.py CCGameManager2.dat --no-scan-base64
```

Or just open `gd-save-extractor.html` in a browser.

## Credits

The underlying obfuscation scheme (XOR‑11 outer layer, XOR‑37 on the legacy
`GJP` field) is publicly documented by the Geometry Dash community/modding
scene — this repo doesn't claim to have discovered it, just packages a clean,
dependency-light implementation of it.

## License

MIT — see [LICENSE](LICENSE).
