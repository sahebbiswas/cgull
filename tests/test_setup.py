import unittest
from pathlib import Path


class TestProjectMetadata(unittest.TestCase):
    @staticmethod
    def _project_toml() -> str:
        project_path = Path(__file__).parent.parent / "pyproject.toml"
        return project_path.read_text(encoding="utf-8")

    def test_development_status_classifier(self):
        content = self._project_toml()

        self.assertIn("Development Status :: 4 - Beta", content)
        self.assertNotIn("Development Status :: 5 - Production/Stable", content)

    def test_flake8_not_in_dev_extras(self):
        content = self._project_toml()

        self.assertIn('[project.optional-dependencies]', content)
        self.assertNotIn("flake8", content)

    def test_dependabot_config(self):
        dependabot_path = Path(__file__).parent.parent / ".github" / "dependabot.yml"
        self.assertTrue(dependabot_path.exists(), "dependabot.yml should exist")
        content = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("version: 2", content)
        self.assertIn("package-ecosystem: \"pip\"", content)
        self.assertIn("package-ecosystem: \"github-actions\"", content)
        self.assertIn("interval: \"weekly\"", content)

    def test_pre_commit_hooks_config(self):
        hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
        self.assertTrue(hooks_path.exists(), ".pre-commit-hooks.yaml should exist")
        content = hooks_path.read_text(encoding="utf-8")
        self.assertIn("id: cgull", content)
        self.assertIn("entry: cgull scan --fail-on high", content)
        self.assertIn("language: python", content)
        self.assertIn("types_or: [c, c++]", content)
        self.assertIn(r"files: \.(c|h|hpp)$", content)

if __name__ == "__main__":
    unittest.main()
