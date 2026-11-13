"""Conservative static pattern scanner. Never imports or executes target code."""
import hashlib
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from .think_engine import inspect_python
from .lua_engine import inspect_lua
from .language_detection import detect_language, mismatch

MAX_BYTES = 2 * 1024 * 1024
EXTENSIONS = {'.py': 'Python', '.lua': 'Lua', '.luau': 'Lua', '.js': 'JavaScript', '.txt': 'Text'}

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    explanation: str
    pattern: str
    languages: tuple[str, ...]

RULES = [
    Rule('PY001','Dynamic code execution','high','exec/eval can execute constructed code; inspect the input source.',r'\b(?:exec|eval)\s*\(',('Python',)),
    Rule('PY002','Shell command invocation','medium','Shell or subprocess calls can start external processes.',r'\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output|check_call))\s*\(',('Python',)),
    Rule('PY003','Encoded payload decoding','medium','Base64 decoding may be legitimate or used to hide payloads.',r'\b(?:base64\.b64decode|b64decode)\s*\(',('Python',)),
    Rule('PY004','Deserialization with pickle','high','Loading untrusted pickle data can execute code.',r'\b(?:pickle|dill)\.loads?\s*\(',('Python',)),
    Rule('PY005','Remote download','low','Network access may fetch external content; verify its purpose.',r'\b(?:requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(',('Python',)),
    Rule('LUA001','Remote module loading','high','Dynamic require with a numeric or computed argument merits review.',r'\brequire\s*\(\s*(?:\d{5,}|tonumber\s*\(|[A-Za-z_]\w*\s*\))',('Lua',)),
    Rule('LUA002','Remote HTTP retrieval','medium','External HTTP requests can load unexpected content.',r'\b(?:GetAsync|PostAsync|HttpGet)\s*\(',('Lua',)),
    Rule('LUA003','Dynamic Lua execution','high','loadstring can execute dynamically constructed code.',r'\bloadstring\s*\(',('Lua',)),
    Rule('JS001','Dynamic JavaScript execution','high','eval and Function can execute dynamically constructed code.',r'\b(?:eval|Function)\s*\(',('JavaScript',)),
    Rule('JS002','Process execution','medium','Child process APIs can execute local commands.',r'\b(?:exec|execSync|spawn|spawnSync)\s*\(',('JavaScript',)),
]

COMPILED = [(rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in RULES]

def analyze(source: str, filename: str = 'pasted.py', language: str | None = None) -> dict:
    if len(source.encode('utf-8')) > MAX_BYTES:
        raise ValueError('Code exceeds 2 MiB size limit.')
    lang = language or EXTENSIONS.get(Path(filename).suffix.lower(), 'Text')
    language_hint = detect_language(source, filename)
    language_mismatch = mismatch(source, lang, filename)
    # Strong mismatch: do not run rules for the wrong language.
    # Report the mismatch as a diagnostic, not a security finding.
    if language_mismatch and language_mismatch['confidence'] == 'high':
        return {'file': Path(filename).name, 'language': lang,
            'sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
            'line_count': len(source.splitlines()), 'findings': [], 'finding_count': 0,
            'status': 'Possibly the wrong language selected — analysis paused',
            'analysis_complete': False, 'analysis_state': 'paused_language_mismatch',
            'incomplete_reason': f"Selected {lang}; detected {language_mismatch['detected']} (high confidence).",
            'engine': {'parser': 'Not run', 'parse_error': None},
            'language_detection': language_hint, 'language_mismatch': language_mismatch,
            'disclaimer': 'No security scan performed. Language mismatch must be resolved before trusting results.'}
    lines = source.splitlines()
    findings = []
    metadata = {"parser": "Regex", "parse_error": None}
    if lang == "Python":
        findings, metadata = inspect_python(source)
    if lang == "Lua":
        findings, metadata = inspect_lua(source)
    for number, line in enumerate(lines, 1):
        # Simple heuristic, not a parser: comments and strings may cause false positives.
        for rule, compiled in COMPILED:
            if lang == "JavaScript" and lang in rule.languages and compiled.search(line):
                findings.append({'rule_id':rule.id,'title':rule.title,'severity':rule.severity,
                    'explanation':rule.explanation,'line':number,'snippet':line.strip()[:180]})
    parse_error = metadata.get('parse_error')
    return {'file':Path(filename).name,'language':lang,'sha256':hashlib.sha256(source.encode('utf-8')).hexdigest(),
        'line_count':len(lines),'findings':findings,'finding_count':len(findings),
        'status': ('Analysis incomplete — parse error' if parse_error else ('Possible language mismatch — results unverified' if language_mismatch else ('Review recommended' if findings else 'No matched rules — safety not established'))),
        'analysis_complete': not bool(parse_error or language_mismatch),
        'analysis_state': 'partial_parse_error' if parse_error else ('unverified_language' if language_mismatch else 'complete'),
        'incomplete_reason': str(parse_error) if parse_error else ('Possible language mismatch; verify the language before trusting findings.' if language_mismatch else None),
        'engine': metadata, 'language_detection': language_hint, 'language_mismatch': language_mismatch,
        'disclaimer':'Static heuristic analysis only. No findings does not mean safe. Lua uses lexical masking and contextual heuristics, not a full parser; JavaScript regex may flag strings/comments.'}

def analyze_file(path: str) -> dict:
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError('File exceeds 2 MiB size limit.')
    data = p.read_bytes()
    if b'\x00' in data:
        raise ValueError('Binary files are not supported.')
    source = data.decode('utf-8-sig', errors='replace')
    result = analyze(source, p.name)
    result['sha256'] = hashlib.sha256(data).hexdigest()
    return result
