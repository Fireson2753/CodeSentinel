import unittest
from codesentinel.analyzer import analyze
class TestAnalyzer(unittest.TestCase):
    def test_exec(self):
        r=analyze('exec(user_input)',language='Python')
        self.assertIn('THINK001',[f['rule_id'] for f in r['findings']])
    def test_safe(self):
        self.assertEqual(analyze('print("hello")',language='Python')['finding_count'],0)
    def test_lua(self):
        r=analyze('require(tonumber(id))',language='Lua')
        self.assertIn('LUA001',[f['rule_id'] for f in r['findings']])
    def test_size(self):
        with self.assertRaises(ValueError):analyze('x'*(2*1024*1024+1))
if __name__=='__main__':unittest.main()
