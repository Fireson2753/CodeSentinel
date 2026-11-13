import unittest
from codesentinel.analyzer import analyze

LUA = 'local Players = game:GetService("Players")\nlocal x = 1\nif x then task.spawn(function() print(x) end) end'

class ReliabilityTests(unittest.TestCase):
    def test_high_confidence_mismatch_pauses(self):
        r = analyze(LUA, 'test.txt', 'JavaScript')
        self.assertEqual(r['analysis_state'], 'paused_language_mismatch')
        self.assertFalse(r['analysis_complete'])
        self.assertEqual(r['findings'], [])
        self.assertEqual(r['finding_count'], 0)
    def test_correct_language_is_scanned(self):
        r = analyze(LUA, 'test.lua', 'Lua')
        self.assertTrue(r['analysis_complete'])
    def test_python_syntax_error_is_partial(self):
        r = analyze('def broken(:\n  pass', 'bad.py', 'Python')
        self.assertFalse(r['analysis_complete'])
        self.assertIn('incomplete', r['status'].lower())
    def test_ambiguous_does_not_pause(self):
        r = analyze('print("hello")', 'a.py', 'Python')
        self.assertTrue(r['analysis_complete'])
    def test_no_findings_not_safe(self):
        r = analyze('x = 1', 'a.py', 'Python')
        self.assertIn('safety not established', r['status'])

if __name__ == '__main__': unittest.main()
