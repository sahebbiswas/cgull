"""
Tests for Translation-Unit (TU) mode CLI, config, and engine integration.
"""

import os
import tempfile
import unittest
from cgull.models import ScanConfig, ScanMode
from cgull.config import load_config
from cgull.engine import CGullScanner
from cgull.cli import main, build_parser, handle_scan


class TestTUMode(unittest.TestCase):
    def test_scan_config_mode_default_and_serialization(self):
        cfg = ScanConfig.create()
        self.assertEqual(cfg.mode, ScanMode.FILE)

        cfg_tu = ScanConfig.create(mode="tu")
        self.assertEqual(cfg_tu.mode, ScanMode.TU)

        d = cfg_tu.to_dict()
        self.assertEqual(d["mode"], "tu")

        restored = ScanConfig.from_dict(d)
        self.assertEqual(restored.mode, ScanMode.TU)

    def test_config_toml_mode_parsing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, ".cgull.toml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write('mode = "tu"\n')

            cfg = load_config(config_path=cfg_path)
            self.assertEqual(cfg.mode, ScanMode.TU)

            # Test [scan] section
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write('[scan]\nmode = "tu"\n')

            cfg2 = load_config(config_path=cfg_path)
            self.assertEqual(cfg2.mode, ScanMode.TU)

    def test_cli_mode_argument(self):
        parser = build_parser()
        args = parser.parse_args(["scan", ".", "--mode", "tu"])
        self.assertEqual(args.mode, "tu")

    def test_engine_tu_mode_roots_and_orphan_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            foo_h = os.path.join(tmpdir, "foo.h")
            with open(foo_h, "w", encoding="utf-8") as f:
                f.write("void foo(void);\n")

            main_c = os.path.join(tmpdir, "main.c")
            with open(main_c, "w", encoding="utf-8") as f:
                f.write('#include "foo.h"\nint main(void) { return 0; }\n')

            orphan_h = os.path.join(tmpdir, "orphan.h")
            with open(orphan_h, "w", encoding="utf-8") as f:
                f.write("void orphan(void);\n")

            # File mode (default): scans main.c, foo.h, orphan.h (3 files analyzed)
            scanner_file = CGullScanner(config=ScanConfig.create(mode=ScanMode.FILE))
            res_file = scanner_file.scan_path(tmpdir, quiet=True)
            self.assertEqual(res_file.scanned_files_count, 3)

            # TU mode: scans main.c (includes foo.h) and orphan.h (2 files analyzed)
            scanner_tu = CGullScanner(config=ScanConfig.create(mode=ScanMode.TU))
            res_tu = scanner_tu.scan_path(tmpdir, quiet=True)
            self.assertEqual(res_tu.scanned_files_count, 2)
            scanned_names = {os.path.basename(fs.file_path) for fs in res_tu.file_summaries}
            self.assertIn("main.c", scanned_names)
            self.assertIn("orphan.h", scanned_names)
            self.assertNotIn("foo.h", scanned_names)


if __name__ == "__main__":
    unittest.main()
