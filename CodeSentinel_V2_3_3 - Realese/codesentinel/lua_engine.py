"""Conservative Luau/Lua lexical and behavioral scanner. Never runs target code."""
import re


def mask_noncode(source: str) -> str:
    """Mask comments and string literals, preserving offsets and newlines.

    Handles quoted strings, -- comments and Lua long brackets with any = depth.
    """
    out = list(source)
    i, n = 0, len(source)
    def blank(a, b):
        for j in range(a, b):
            if source[j] not in "\r\n": out[j] = " "
    while i < n:
        if source.startswith("--", i):
            start = i
            m = re.match(r"\[(=*)\[", source[i+2:])
            if m:
                close = "]" + m.group(1) + "]"
                pos = source.find(close, i+2+m.end())
                i = n if pos < 0 else pos+len(close)
            else:
                pos = source.find("\n", i)
                i = n if pos < 0 else pos
            blank(start, i)
        elif source[i] in "\"'":
            start, quote = i, source[i]
            i += 1
            while i < n:
                if source[i] == "\\": i += 2
                elif source[i] == quote:
                    i += 1; break
                else: i += 1
            i = min(i, n)
            blank(start, i)
        elif source[i] == "[" and (m := re.match(r"\[(=*)\[", source[i:])):
            start = i
            close = "]" + m.group(1) + "]"
            pos = source.find(close, i+m.end())
            i = n if pos < 0 else pos+len(close)
            blank(start, i)
        else:
            i += 1
    return "".join(out)


def inspect_lua(source: str):
    code = mask_noncode(source)
    lines = source.splitlines()
    code_lines = code.splitlines()
    findings = []
    def add(rule, title, severity, explanation, pos):
        line = source.count("\n", 0, pos) + 1
        findings.append(dict(rule_id=rule,title=title,severity=severity,
            explanation=explanation,line=line,snippet=lines[line-1].strip()[:180]))
    rules = [
        ("LUA001", "Dynamic module loading", "high", r"\brequire\s*\(\s*(?:\d{5,}|tonumber\s*\(|[A-Za-z_]\w*\s*\))", "Dynamic require may load a module; inspect its source."),
        ("LUA002", "HTTP retrieval", "medium", r"\b(?:GetAsync|PostAsync|HttpGet)\s*\(", "Network retrieval deserves review when combined with dynamic execution."),
        ("LUA003", "Dynamic Lua execution", "high", r"\bloadstring\s*\(", "Dynamic Lua execution can run constructed source."),
        ("LUA004", "Player input interception", "medium", r"\b(?:BindActionAtPriority|BindAction)\s*\(", "Input interception can be legitimate; inspect user-facing purpose."),
        ("LUA005", "Player movement restriction", "medium", r"\b(?:WalkSpeed|JumpPower|JumpHeight)\s*=\s*0(?=\D|$)|\bAnchored\s*=\s*true\b", "Movement restriction can be legitimate but may accompany coercive UI."),
    ]
    for rule,title,severity,pattern,explanation in rules:
        for m in re.finditer(pattern,code,re.I): add(rule,title,severity,explanation,m.start())
    # Contextual indicators: no claims of malicious intent from isolated UI APIs.
    has_rows = bool(re.search(r"GetAttributes\s*\(|GetAttribute\s*\(",code)) and bool(re.search(r"\brows\s*\[|\browsJoin\s*\(",code))
    has_copy = bool(re.search(r"\b(?:SelectionStart|selectAll|Clipboard|CopyShortcut)\b",code))
    has_command = bool(re.search(r"\b(?:CommandBar|CodeViewport|Command)\b",source))
    has_activity = bool(re.search(r"\b(?:InputBegan|InputChanged)\b",code)) and bool(re.search(r"\b(?:activity|operatorPresent)\b",code))
    has_gui = bool(re.search(r"\b(?:gui\.Enabled|frame\.Visible)\b",code))
    def marker(pattern):
        m=re.search(pattern,code)
        return m.start() if m else 0
    if has_rows:
        add("SOC001","GUI text assembled from attributes","low","UI content is assembled from instance attributes; inspect the attribute values separately.",marker(r"GetAttributes\s*\("))
    if has_copy and has_command:
        add("SOC002","Selectable command presentation","medium","A command-style UI has selection/copy affordances. Check the displayed instructions.",marker(r"SelectionStart|selectAll"))
    if has_activity and has_gui:
        add("SOC003","Activity-gated UI presentation","low","UI behavior is linked to user input activity; inspect intent and user consent.",marker(r"InputChanged|InputBegan"))
    if has_rows and has_copy and has_command and (has_activity or any(f["rule_id"] in ("LUA004","LUA005") for f in findings)):
        add("SOC004","Combined social-engineering indicators","medium","Multiple UI behaviors co-occur; manual review of the GUI attributes and displayed command is recommended.",marker(r"GetAttributes\s*\("))
    # Installation signals are informational alone; they need correlation.
    installer_rules = [
        ("LUA006", "GUI/template cloned into PlayerGui", "medium",
         r"\b(?:copy|clone|gui|template)\s*\.Parent\s*=\s*playerGui\b",
         "A cloned object is installed in a player's GUI. Review the cloned descendants; this is common in legitimate games."),
        ("LUA007", "Runtime object renamed during installation", "low",
         r"\b(?:copy|context|toggleContext|toggleAction)\s*\.Name\s*=\s*(?:LIVE_\w+|[A-Za-z_]\w*)",
         "An object is renamed during installation; not inherently malicious."),
        ("LUA008", "GUI installation for player sessions", "low",
         r"\bPlayers\s*\.PlayerAdded\s*:\s*Connect\s*\(\s*install\b",
         "The install callback is registered for new players; inspect the installed template."),
    ]
    for rule, title, severity, pattern, explanation in installer_rules:
        for m in re.finditer(pattern, code, re.I):
            add(rule, title, severity, explanation, m.start())
    findings.sort(key=lambda f:(f["line"],f["rule_id"]))
    return findings, {"parser":"Lua lexical masking + contextual heuristics","parse_error":None,
        "limitations":"Not a full Luau parser. GUI attributes and external assets are not included in pasted script."}
