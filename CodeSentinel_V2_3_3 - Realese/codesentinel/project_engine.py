"""Read-only multi-file correlation. Never executes inspected source."""
from pathlib import Path
from .analyzer import analyze, MAX_BYTES

MAX_FILES = 100
MAX_TOTAL = 8 * 1024 * 1024
ALLOWED = {'.lua', '.luau', '.py', '.js'}

def analyze_project(folder: str) -> dict:
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError('Choose an existing directory.')
    reports = []
    skipped = []
    total = 0
    # No symlinks: avoid following files outside the chosen folder.
    candidates = sorted(p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in ALLOWED and not p.is_symlink() and not any(parent.is_symlink() for parent in p.parents if parent != root and root in parent.parents))
    if len(candidates) > MAX_FILES:
        raise ValueError(f'Project contains more than {MAX_FILES} supported files.')
    for path in candidates:
        rel = str(path.relative_to(root))
        size = path.stat().st_size
        if size > MAX_BYTES or total + size > MAX_TOTAL:
            skipped.append({'file': rel, 'reason': 'Size limit exceeded'})
            continue
        data = path.read_bytes()
        total += len(data)
        if b'\x00' in data:
            skipped.append({'file': rel, 'reason': 'Binary content'})
            continue
        try:
            content = data.decode('utf-8-sig')
        except UnicodeDecodeError:
            skipped.append({'file': rel, 'reason': 'Not UTF-8'})
            continue
        report = analyze(content, rel)
        report['file'] = rel
        reports.append(report)
    correlations = []
    installers = [(r, f) for r in reports for f in r['findings'] if f['rule_id'] == 'LUA006']
    # SOC002/SOC004 are strong command-UI evidence; SOC001 with LUA004
    # is a weaker but useful pairing for reduced WindowDriver samples.
    ui_reports = []
    for r in reports:
        ids = {f['rule_id'] for f in r['findings']}
        if ids & {'SOC002', 'SOC004'}:
            ui_reports.append((r, 'command-ui'))
        elif {'SOC001', 'LUA004'} <= ids:
            ui_reports.append((r, 'attribute-ui-with-input-interception'))
    # Only correlate across different files. Co-location does not prove
    # one script installed or invoked another.
    pairs = [(installer, ui, kind) for installer, _ in installers
             for ui, kind in ui_reports if installer['file'] != ui['file']]
    if pairs:
        involved = sorted({r['file'] for installer, ui, _ in pairs for r in (installer, ui)})
        weaker = not any(kind == 'command-ui' for _, _, kind in pairs)
        correlations.append({
            'rule_id': 'CROSS001', 'severity': 'low' if weaker else 'medium',
            'title': 'GUI installer and interactive UI indicators coexist',
            'explanation': ('Separate files contain GUI installation and attribute-driven UI with input interception. '
                            if weaker else 'Separate files contain GUI installation and a command-oriented UI. ')
                           + 'This is project-level co-occurrence only; verify the Roblox object hierarchy and actual GUI text.',
            'files': involved,
            'confidence': 'co-occurrence only',
        })
    return {
        'project': root.name, 'files_scanned': len(reports),
        'files_skipped': skipped, 'reports': reports,
        'correlations': correlations,
        'finding_count': sum(r['finding_count'] for r in reports) + len(correlations),
        'status': ('Analysis incomplete — some files skipped or unverified' if skipped or any(not r.get('analysis_complete', True) for r in reports) else ('Review recommended' if correlations or any(r['findings'] for r in reports) else 'No matched rules — safety not established')),
        'analysis_complete': not skipped and all(r.get('analysis_complete', True) for r in reports),
        'incomplete_files': [{'file': r['file'], 'reason': r.get('incomplete_reason')} for r in reports if not r.get('analysis_complete', True)] + skipped,
        'disclaimer': 'Static heuristics only. Cross-file co-occurrence is not proof of malicious intent or direct execution. No target code is executed.'
    }
