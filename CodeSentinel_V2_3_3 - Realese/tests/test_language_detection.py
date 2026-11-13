import unittest
from codesentinel.language_detection import detect_language, mismatch
from codesentinel.analyzer import analyze

class LanguageDetectionTests(unittest.TestCase):
    def test_luau_mismatch(self):
        code = 'local Players = game:GetService("Players")\nlocal x = 1\nif x then print(x) end'
        self.assertEqual(mismatch(code, 'Python')['detected'], 'Lua')
        result = analyze(code, 'sample.txt', 'Python')
        self.assertIn('wrong language', result['status'])
        self.assertEqual(result['language_mismatch']['selected'], 'Python')
    def test_python_mismatch(self):
        code = 'import os\ndef hello():\n    print(os.getcwd())'
        self.assertEqual(mismatch(code, 'Lua')['detected'], 'Python')
    def test_js_mismatch(self):
        self.assertEqual(mismatch('const a = 1;\nconsole.log(a);', 'Python')['detected'], 'JavaScript')
    def test_ambiguous(self):
        self.assertIsNone(detect_language('print("Hello")')['detected'])
        self.assertIsNone(mismatch('print("Hello")', 'Python'))
    def test_same_language(self):
        self.assertIsNone(mismatch('local Players = game:GetService("Players")', 'Lua'))
    def test_comments_only(self):
        self.assertIsNone(detect_language('-- local Players = game:GetService("Players")')['detected'])
    def test_json_has_hint(self):
        self.assertIn('language_detection', analyze('print("hi")', 'a.py', 'Python'))
    def test_filename_not_only_signal(self):
        self.assertIsNone(detect_language('print("hi")', 'test.lua')['detected'])

if __name__ == '__main__': unittest.main()
