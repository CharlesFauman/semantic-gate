#!/usr/bin/env python3
from __future__ import annotations

import unittest

from semantic_gate.recipe_plugin import Recipe, RecipePlugin, RecipePluginError


class RecipePluginTests(unittest.TestCase):
    def test_reviewed_recipe_uses_fixed_executable_without_shell(self):
        calls=[]
        def runner(argv, **kwargs):
            calls.append((argv,kwargs))
            return type("Result",(),{"returncode":0,"stdout":"done\n","stderr":""})()
        plugin=RecipePlugin(
            plugin_id="example.local",node_id="mac",
            recipes={"mac.application.open":Recipe(argv=("/usr/bin/open","-a","{application}"),parameters={"application":("Preview","Calculator")})},
            runner=runner,
        )
        self.assertTrue(plugin.precheck("mac.application.open",{"application":"Preview"})["eligible"])
        result=plugin.execute("mac.application.open",{"application":"Preview"})
        self.assertEqual("done",result["stdout"])
        self.assertEqual(["/usr/bin/open","-a","Preview"],calls[0][0])
        self.assertNotIn("shell",calls[0][1])
        self.assertEqual({"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"},calls[0][1]["env"])

    def test_unknown_extra_or_unallowlisted_values_cannot_become_commands(self):
        plugin=RecipePlugin(plugin_id="example.local",node_id="mac",recipes={"mac.application.open":Recipe(argv=("/usr/bin/open","-a","{application}"),parameters={"application":("Preview",)})})
        for action,params in [
            ("system.shell.execute",{"application":"Preview"}),
            ("mac.application.open",{"application":"Terminal"}),
            ("mac.application.open",{"application":"Preview","args":"; rm -rf /"}),
        ]:
            with self.subTest(action=action,params=params), self.assertRaises(RecipePluginError):
                plugin.execute(action,params)


if __name__=="__main__": unittest.main()
