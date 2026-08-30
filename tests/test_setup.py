import unittest
import os

class TestSetupMetadata(unittest.TestCase):
    def test_development_status_classifier(self):
        setup_path = os.path.join(os.path.dirname(__file__), "..", "setup.py")
        with open(setup_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("Development Status :: 4 - Beta", content)
        self.assertNotIn("Development Status :: 5 - Production/Stable", content)

    def test_flake8_not_in_dev_extras(self):
        setup_path = os.path.join(os.path.dirname(__file__), "..", "setup.py")
        with open(setup_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("flake8", content)

if __name__ == "__main__":
    unittest.main()
