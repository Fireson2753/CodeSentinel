import tempfile
import unittest
from pathlib import Path
from codesentinel.analyzer import analyze
from codesentinel.project_engine import analyze_project

RUNTIME = """local copy = folderTemplate:Clone()
copy.Name = LIVE_FOLDER
copy.Parent = playerGui
Players.PlayerAdded:Connect(install)
"""
WINDOW = """local rows = {}
for n,v in pairs(gui:GetAttributes()) do rows[n]=v end
local CommandBar = gui.CommandBar
box.SelectionStart = 1
"""

class ProjectTests(unittest.TestCase):
    def test_runtime_indicators(self):
        ids = {f['rule_id'] for f in analyze(RUNTIME, 'Runtime.lua')['findings']}
        self.assertTrue({'LUA006','LUA007','LUA008'} <= ids, ids)
    def test_project_correlation(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'Runtime.lua').write_text(RUNTIME)
            Path(d, 'WindowDriver.lua').write_text(WINDOW)
            result = analyze_project(d)
            self.assertIn('CROSS001', [x['rule_id'] for x in result['correlations']])
    def test_reduced_windowdriver_correlation(self):
        window = """local rows = {}
for name, value in pairs(gui:GetAttributes()) do
    rows[name] = value
end
local ContextActionService = game:GetService("ContextActionService")
ContextActionService:BindActionAtPriority("InputBlockAction", function()
    return Enum.ContextActionResult.Sink
end, false, 3100, Enum.PlayerActions.CharacterForward)
"""
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'Runtime.lua').write_text(RUNTIME)
            Path(d, 'WindowDriver.lua').write_text(window)
            result = analyze_project(d)
            self.assertIn('CROSS001', [c['rule_id'] for c in result['correlations']])
            self.assertEqual(result['correlations'][0]['confidence'], 'co-occurrence only')
    def test_no_correlation_without_installer(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'WindowDriver.lua').write_text(WINDOW)
            self.assertEqual(analyze_project(d)['correlations'], [])
    def test_no_false_link_on_unrelated_source(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'a.lua').write_text('print("hello")')
            self.assertEqual(analyze_project(d)['correlations'], [])
    def test_comments_ignored(self):
        self.assertEqual(analyze('-- copy.Parent = playerGui\n', 'x.lua')['finding_count'],0)

if __name__=='__main__': unittest.main()
