import unittest
from codesentinel.analyzer import analyze
from codesentinel.lua_engine import mask_noncode

class LuaTests(unittest.TestCase):
    def test_strings_and_comments_are_ignored(self):
        s = "-- require(123456)\nlocal x = [[loadstring(1) GetAsync(2)]]\nlocal y = \"HttpGet(1)\""
        self.assertEqual(analyze(s, "x.lua")["finding_count"], 0)
    def test_real_dynamic_require(self):
        self.assertIn("LUA001", [x["rule_id"] for x in analyze("require(tonumber(id))", "x.lua")["findings"]])
    def test_long_brackets(self):
        self.assertNotIn("loadstring", mask_noncode("--[=[ loadstring(x) ]=]"))
    def test_social_ui(self):
        s = "local rows={}\nfor n,v in pairs(gui:GetAttributes()) do rows[n]=v end\nlocal CommandBar = x\nbox.SelectionStart = 1\nUserInputService.InputBegan:Connect(function() activity += 1 end)\ngui.Enabled=true"
        ids={f["rule_id"] for f in analyze(s,"x.luau")["findings"]}
        self.assertTrue({"SOC001","SOC002","SOC003","SOC004"}.issubset(ids),ids)
    def test_movement(self):
        ids={f["rule_id"] for f in analyze("humanoid.WalkSpeed = 0", "x.lua")["findings"]}
        self.assertIn("LUA005", ids)

if __name__ == "__main__": unittest.main()
