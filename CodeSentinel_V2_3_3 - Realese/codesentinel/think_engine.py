"""Bounded, conservative Python AST reasoning. Never executes inspected source."""
import ast

SOURCES = {'input', 'requests.get', 'requests.post', 'httpx.get', 'httpx.post',
           'urllib.request.urlopen', 'urlopen'}
DECODERS = {'base64.b64decode', 'b64decode', 'base64.urlsafe_b64decode'}
EXECUTORS = {'exec', 'eval', 'builtins.exec', 'builtins.eval'}
SHELLS = {'os.system', 'subprocess.run', 'subprocess.Popen', 'subprocess.call',
          'subprocess.check_output', 'subprocess.check_call'}
PICKLES = {'pickle.load', 'pickle.loads', 'dill.load', 'dill.loads'}


def inspect_python(source):
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [], {'parser': 'AST', 'parse_error': f'Line {exc.lineno}: {exc.msg}'}
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                if a.name != '*':
                    aliases[a.asname or a.name] = f'{node.module}.{a.name}'

    def resolve(node):
        if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute): return resolve(node.value) + '.' + node.attr
        return ''

    # A deliberately local approximation: assignments in a scope are collected
    # in source order, but branches, reassignments and interprocedural flows
    # are not modeled precisely. Never treat these results as proof.
    findings, values = [], {}
    lines = source.splitlines()

    def trace(expr, depth=0):
        if depth > 12: return set()
        if isinstance(expr, ast.Name): return set(values.get(expr.id, ()))
        if isinstance(expr, ast.Call):
            name = resolve(expr.func)
            tags = set()
            if name in SOURCES: tags.add('external input')
            if name in DECODERS: tags.add('decoded data')
            for a in [expr.func, *expr.args, *(kw.value for kw in expr.keywords)]: tags |= trace(a, depth+1)
            return tags
        tags = set()
        for child in ast.iter_child_nodes(expr): tags |= trace(child, depth+1)
        return tags

    def add(node, rule_id, title, severity, explanation):
        line = getattr(node, 'lineno', 1)
        findings.append({'rule_id': rule_id, 'title': title, 'severity': severity,
                         'explanation': explanation, 'line': line,
                         'snippet': lines[line-1].strip()[:180] if line <= len(lines) else ''})

    class Walker(ast.NodeVisitor):
        def visit_Assign(self, node):
            self.visit(node.value)
            tags = trace(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name): values[target.id] = tags
        def visit_AnnAssign(self, node):
            if node.value:
                self.visit(node.value)
                if isinstance(node.target, ast.Name): values[node.target.id] = trace(node.value)
        def visit_Call(self, node):
            name = resolve(node.func)
            tags = set()
            for a in [*node.args, *(kw.value for kw in node.keywords)]: tags |= trace(a)
            if name in EXECUTORS:
                severity = 'critical' if 'external input' in tags else 'high'
                reason = ('External input reaches dynamic execution; potential arbitrary code execution.'
                          if 'external input' in tags else 'Dynamic code execution requires review.')
                add(node, 'THINK001', 'Dynamic code execution', severity, reason)
            elif name in SHELLS:
                severity = 'high' if 'external input' in tags else 'medium'
                add(node, 'THINK002', 'Process or shell invocation', severity,
                    'External input reaches a process call.' if 'external input' in tags
                    else 'External process invocation; inspect arguments and purpose.')
            elif name in PICKLES:
                add(node, 'THINK003', 'Unsafe deserialization API',
                    'critical' if 'external input' in tags else 'high',
                    'Deserializing untrusted data may execute code.')
            elif name in DECODERS:
                # Decoding by itself is informational, not a malware indicator.
                pass
            elif name in SOURCES and name != 'input':
                add(node, 'THINK004', 'External data retrieval', 'low',
                    'External data is fetched; verify the source and downstream use.')
            self.generic_visit(node)
    Walker().visit(tree)
    findings.sort(key=lambda f: (f['line'], f['rule_id']))
    return findings, {'parser': 'AST', 'parse_error': None,
                      'limitations': 'Local approximate data flow only; no interprocedural, branch-sensitive or full alias analysis.'}
