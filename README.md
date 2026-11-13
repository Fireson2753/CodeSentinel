# CodeSentinel V2.3.3 — Language Detection

Static, read-only Python/Lua/Luau/JS source scanner. **Never executes inspected code.**

## Run

```bash
pip install -r requirements.txt
python main.py
```

Use **Open file** for individual scripts or **Scan folder** for a read-only, multi-file scan. Export JSON works for either mode.

## V2.3

- `LUA006`: GUI installation into `PlayerGui` (contextual, medium)
- `LUA007`: object renaming during installation (low)
- `LUA008`: installation callback on `Players.PlayerAdded` (low)
- `CROSS001`: GUI installation and command-style UI coexist in a scanned folder. **Co-occurrence only**: does not establish that one script invokes another.
- Maximum 100 source files, 2 MiB/file, 8 MiB total. Skips binaries, invalid UTF-8, and symbolic links.
- All prior V2.2 rules retained. Source file is not executed.

**Limitations:** This is a heuristic scanner, not a full Luau parser or antivirus. It does not reconstruct Roblox Instance trees, inspect attributes stored in `.rbxl` files, prove malicious intent, or follow remote dependencies. `0 findings` is not a safety certificate.

Run tests with `python -m unittest discover -s tests -v`.

## V2.3.3

Conservative language detection for pasted or opened code. If the selected language conflicts with strong Python, Lua/Luau, or JavaScript syntax indicators, the app shows **Possibly the wrong language selected.** with Selected and Detected languages and offers to switch and reanalyze. Hints and mismatch are included in JSON exports. Ambiguous snippets do not trigger warnings. The detector is heuristic and can be wrong; no target code is executed.

## V2.3.3 — Reliability fixes
- Clears stale results when code/language changes or a scan starts/fails.
- High-confidence language mismatch pauses security rules and prompts to switch. Declining keeps a diagnostic report with zero *evaluated* findings, not a clean bill of health.
- Python parse errors and skipped/unverified project files are marked incomplete, including reasons in JSON.
- No findings never implies safety. Detection remains heuristic; run tests before public beta.

## V2.3.3 correlation fix
`CROSS001` now also recognizes a weaker combination: an installer in one file and attribute-built UI with input interception in another. The correlation is LOW severity for this weaker signal and explicitly means **co-occurrence only**, not a proven link or malware verdict.
