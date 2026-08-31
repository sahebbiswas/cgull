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

if __name__ == "__main__":
    unittest.main()
