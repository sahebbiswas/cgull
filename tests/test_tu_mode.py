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

    def test_tu_flag_collection_in_included_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            header_h = os.path.join(tmpdir, "header.h")
            with open(header_h, "w", encoding="utf-8") as f:
                f.write("#ifdef HEADER_FLAG\nint h_var;\n#endif\n")

            main_c = os.path.join(tmpdir, "main.c")
            with open(main_c, "w", encoding="utf-8") as f:
                f.write('#include "header.h"\nint main(void) { return 0; }\n')

            scanner = CGullScanner(config=ScanConfig.create(mode=ScanMode.TU, config_strategy="one-at-a-time"))
            res = scanner.scan_path(tmpdir, quiet=True)
            # Presence flag HEADER_FLAG inside header.h must be collected even in TU mode
            # Profiles generated: baseline and +HEADER_FLAG
            self.assertGreaterEqual(len(res.file_summaries), 1)

    def test_multi_profile_tu_header_inclusion(self):
        from cgull.models import ConfigProfile
        with tempfile.TemporaryDirectory() as tmpdir:
            opt_h = os.path.join(tmpdir, "opt.h")
            with open(opt_h, "w", encoding="utf-8") as f:
                f.write("void opt(void);\n")

            main_c = os.path.join(tmpdir, "main.c")
            with open(main_c, "w", encoding="utf-8") as f:
                f.write("#ifdef USE_OPT\n#include \"opt.h\"\n#endif\nint main(void) { return 0; }\n")

            prof1 = ConfigProfile(name="no_opt", flags={})
            prof2 = ConfigProfile(name="with_opt", flags={"USE_OPT": None})

            scanner = CGullScanner(config=ScanConfig.create(mode=ScanMode.TU))
            res = scanner.scan_path(tmpdir, profiles=[prof1, prof2], quiet=True)
            scanned_names = {os.path.basename(fs.file_path) for fs in res.file_summaries}
            # Since opt.h is included under prof2, it is NOT an orphan header across all profiles
            self.assertNotIn("opt.h", scanned_names)

    def test_header_caching_and_invalidation(self):
        from cgull.includes import HEADER_CACHE, IncludeResolver, TUIncludeExpander

        with tempfile.TemporaryDirectory() as tmpdir:
            common_h = os.path.realpath(os.path.join(tmpdir, "common.h"))
            with open(common_h, "w", encoding="utf-8") as f:
                f.write("void common_func(char *b) { gets(b); }\n")

            sources = []
            for i in range(10):
                src = os.path.join(tmpdir, f"src_{i}.c")
                with open(src, "w", encoding="utf-8") as f:
                    f.write(f'#include "common.h"\nint foo_{i}(void) {{ return 0; }}\n')
                sources.append(src)

            HEADER_CACHE.clear()
            scanner = CGullScanner(config=ScanConfig.create(mode=ScanMode.TU))
            res = scanner.scan_path(tmpdir, quiet=True)

            self.assertEqual(res.scanned_files_count, 10)
            gets_issues = [i for i in res.issues if i.rule_id == "CGULL-001"]
            self.assertEqual(len(gets_issues), 1)
            self.assertTrue(gets_issues[0].file_path.endswith("common.h"))
            self.assertEqual(len(gets_issues[0].related_tus), 10)

            # Verify that HEADER_CACHE was populated with common.h
            self.assertGreaterEqual(len(HEADER_CACHE._expansion_cache), 1)

            # Invalidation test: modify common.h content
            with open(common_h, "w", encoding="utf-8") as f:
                f.write("void common_func_v2(char *b) { gets(b); }\n")

            res2 = scanner.scan_path(tmpdir, quiet=True)
            gets_issues2 = [i for i in res2.issues if i.rule_id == "CGULL-001"]
            self.assertEqual(len(gets_issues2), 1)
            self.assertEqual(len(gets_issues2[0].related_tus), 10)


if __name__ == "__main__":
    unittest.main()
