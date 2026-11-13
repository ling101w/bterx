import unittest

from installer import replace_collaboration
from prompts import BLOCK_BEGIN, BLOCK_END, PLANNER_COLLABORATION


class PromptPriorityTests(unittest.TestCase):
    def test_owned_experience_rule_keeps_its_position_and_preserves_body(self):
        body = "Persona and task rules.\n\n" + BLOCK_BEGIN + "\nold instruction\n" + BLOCK_END + "\n\nExisting constraints."
        updated = replace_collaboration(body, "planner")
        self.assertTrue(updated.startswith("Persona and task rules."))
        self.assertLess(updated.index("Persona"), updated.index(BLOCK_BEGIN))
        self.assertIn(PLANNER_COLLABORATION, updated)
        self.assertIn("Persona and task rules.", updated)
        self.assertIn("Existing constraints.", updated)
        self.assertNotIn("old instruction", updated)
        self.assertEqual(updated.count(BLOCK_BEGIN), 1)
        self.assertEqual(updated.count(BLOCK_END), 1)


if __name__ == "__main__":
    unittest.main()
