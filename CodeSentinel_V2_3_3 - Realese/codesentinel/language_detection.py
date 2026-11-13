"""Conservative, non-executing language mismatch hints."""
import re
from pathlib import Path

EXTENSION_LANGUAGE = {'.py': 'Python', '.lua': 'Lua', '.luau': 'Lua', '.js': 'JavaScript'}

# Distinctive syntax only. Generic print(), if, comments, etc. are insufficient.
SIGNALS = {
    'Lua': [
        (r'\blocal\s+[A-Za-z_]\w*\s*=', 3, 'local variable declaration'),
        (r'\bgame\s*:\s*GetService\s*\(', 5, 'Roblox GetService call'),
        (r'\b(?:then|elseif)\b', 2, 'Lua conditional syntax'),
        (r'\bfunction\s+[A-Za-z_]\w*\s*\(', 2, 'Lua function declaration'),
        (r'\b(?:ipairs|pairs)\s*\(', 1, 'Lua iterator'),
        (r'\b(?:task\.spawn|Instance\.new|Enum\.[A-Za-z]+)\b', 2, 'Roblox API'),
    ],
    'Python': [
        (r'(?m)^\s*(?:def|async\s+def)\s+[A-Za-z_]\w*\s*\([^\n]*\)\s*(?:->[^:\n]+)?\s*:', 5, 'Python function definition'),
        (r'(?m)^\s*(?:from\s+\w[\w.]*\s+import|import\s+\w[\w.]*)\b', 3, 'Python import'),
        (r'(?m)^\s*(?:class\s+\w+[^\n]*:|if\s+__name__\s*==)', 4, 'Python class or entry point'),
        (r'(?m)^\s*(?:with|except|elif)\b[^\n]*:', 3, 'Python block syntax'),
    ],
    'JavaScript': [
        (r'\b(?:const|let)\s+[A-Za-z_$][\w$]*\s*=', 4, 'JavaScript variable declaration'),
        (r'\b(?:function\s+[A-Za-z_$][\w$]*\s*\(|=>)', 3, 'JavaScript function syntax'),
        (r'\b(?:document\.querySelector|console\.log|require\s*\(\s*[\"\'])', 3, 'JavaScript API'),
    ],
}

def detect_language(source: str, filename: str = '') -> dict:
    # Remove obvious single-line comments to reduce accidental matches.
    lines = []
    for line in source.splitlines():
        if line.lstrip().startswith(('--', '#', '//')):
            continue
        lines.append(line)
    sample = '\n'.join(lines[:5000])
    scores, evidence = {}, {}
    for lang, patterns in SIGNALS.items():
        scores[lang] = 0
        evidence[lang] = []
        for pattern, weight, reason in patterns:
            if re.search(pattern, sample):
                scores[lang] += weight
                evidence[lang].append(reason)
    ranked = sorted(scores, key=lambda name: scores[name], reverse=True)
    best, second = ranked[0], ranked[1]
    # Require strong and distinctive evidence, with a clear lead.
    detected = best if scores[best] >= 5 and scores[best] - scores[second] >= 3 else None
    ext = EXTENSION_LANGUAGE.get(Path(filename).suffix.lower())
    return {'detected': detected, 'confidence': 'high' if detected and scores[best] >= 8 and scores[best] - scores[second] >= 5 else ('moderate' if detected else 'insufficient'),
            'evidence': evidence[detected] if detected else [], 'scores': scores, 'extension_hint': ext}

def mismatch(source: str, selected: str, filename: str = '') -> dict | None:
    result = detect_language(source, filename)
    detected = result['detected']
    if detected and selected in SIGNALS and detected != selected:
        return {'selected': selected, 'detected': detected, 'confidence': result['confidence'],
                'evidence': result['evidence'], 'message': 'Possibly the wrong language selected.'}
    return None
