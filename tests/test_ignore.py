"""
Tests for cgull.ignore.CGullIgnoreFilter: glob-to-regex conversion,
negation, directory-only rules, and file loading.
"""

import os
import tempfile
import shutil
import unittest

from cgull.ignore import CGullIgnoreFilter


class TestDefaultIgnores(unittest.TestCase):
    def setUp(self):
        self.filter = CGullIgnoreFilter(base_dir="/tmp/nonexistent_cgull_test_root")

    def test_git_directory_ignored(self):
        self.assertTrue(self.filter.should_ignore("/tmp/nonexistent_cgull_test_root/.git", is_dir=True))

    def test_object_files_ignored(self):
        self.assertTrue(self.filter.should_ignore("/tmp/nonexistent_cgull_test_root/foo.o"))

    def test_regular_c_file_not_ignored(self):
        self.assertFalse(self.filter.should_ignore("/tmp/nonexistent_cgull_test_root/src/main.c"))

    def test_base_dir_itself_not_ignored(self):
        self.assertFalse(self.filter.should_ignore("/tmp/nonexistent_cgull_test_root"))


class TestDirectoryOnlyRules(unittest.TestCase):
    """
    Regression tests for a bug found while adding coverage: a directory-only
    pattern like "build/" used to also incorrectly match a plain FILE
    literally named "build" (the dir_only flag was computed but never
    actually enforced).
    """

    def setUp(self):
        self.filter = CGullIgnoreFilter(base_dir="/tmp/cgull_dir_only_test")

    def test_directory_matching_pattern_is_ignored(self):
        self.assertTrue(self.filter.should_ignore("/tmp/cgull_dir_only_test/build", is_dir=True))

    def test_file_with_same_name_as_dir_pattern_is_not_ignored(self):
        self.assertFalse(self.filter.should_ignore("/tmp/cgull_dir_only_test/build", is_dir=False))

    def test_file_nested_inside_matching_directory_is_still_ignored(self):
        self.assertTrue(self.filter.should_ignore("/tmp/cgull_dir_only_test/build/output.o", is_dir=False))

    def test_file_with_prefix_of_dir_pattern_name_is_not_ignored(self):
        # "build.c" should not match a "build/" directory-only rule.
        self.assertFalse(self.filter.should_ignore("/tmp/cgull_dir_only_test/build.c"))


class TestGlobPatterns(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.filter = CGullIgnoreFilter(base_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _p(self, rel):
        return os.path.join(self.temp_dir, rel)

    def test_single_star_matches_within_segment_only(self):
        self.filter.load_from_text("*.tmp")
        self.assertTrue(self.filter.should_ignore(self._p("a.tmp")))
        self.assertTrue(self.filter.should_ignore(self._p("nested/dir/a.tmp")))

    def test_question_mark_matches_single_char(self):
        self.filter.load_from_text("file?.c")
        self.assertTrue(self.filter.should_ignore(self._p("file1.c")))
        self.assertFalse(self.filter.should_ignore(self._p("file12.c")))

    def test_double_star_matches_any_depth(self):
        self.filter.load_from_text("**/generated/*.c")
        self.assertTrue(self.filter.should_ignore(self._p("a/b/c/generated/x.c")))
        self.assertTrue(self.filter.should_ignore(self._p("generated/x.c")))

    def test_root_anchored_pattern_only_matches_at_root(self):
        self.filter.load_from_text("/config.c")
        self.assertTrue(self.filter.should_ignore(self._p("config.c")))
        self.assertFalse(self.filter.should_ignore(self._p("src/config.c")))

    def test_negation_reincludes_previously_excluded_path(self):
        self.filter.load_from_text("vendor/\n!vendor/important.c")
        self.assertTrue(self.filter.should_ignore(self._p("vendor/lib.c")))
        self.assertFalse(self.filter.should_ignore(self._p("vendor/important.c")))

    def test_rule_order_matters_last_match_wins(self):
        # A later rule overrides an earlier one for the same path, matching
        # standard .gitignore semantics.
        self.filter.load_from_text("*.c\n!important.c")
        self.assertTrue(self.filter.should_ignore(self._p("regular.c")))
        self.assertFalse(self.filter.should_ignore(self._p("important.c")))

    def test_comment_lines_are_ignored(self):
        self.filter.load_from_text("# this is a comment\n*.tmp")
        self.assertEqual(len([p for p in self.filter.raw_patterns if p.startswith("#")]), 0)

    def test_blank_lines_produce_no_rule(self):
        before = len(self.filter.rules)
        self.filter.load_from_text("\n\n   \n")
        self.assertEqual(len(self.filter.rules), before)


class TestFileLoading(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_from_file_reads_patterns(self):
        ignore_path = os.path.join(self.temp_dir, ".cgullignore")
        with open(ignore_path, "w") as f:
            f.write("*.log\n")
        f = CGullIgnoreFilter(base_dir=self.temp_dir)
        self.assertTrue(f.should_ignore(os.path.join(self.temp_dir, "debug.log")))

    def test_load_from_file_missing_file_is_a_noop(self):
        f = CGullIgnoreFilter(base_dir=self.temp_dir)
        before = len(f.rules)
        f.load_from_file(os.path.join(self.temp_dir, "does_not_exist.ignore"))
        self.assertEqual(len(f.rules), before)

    def test_custom_patterns_applied_at_construction(self):
        f = CGullIgnoreFilter(base_dir=self.temp_dir, custom_patterns=["*.bak"])
        self.assertTrue(f.should_ignore(os.path.join(self.temp_dir, "old.bak")))


class TestFilterPaths(unittest.TestCase):
    def test_filter_paths_excludes_ignored_entries(self):
        temp_dir = tempfile.mkdtemp()
        try:
            f = CGullIgnoreFilter(base_dir=temp_dir, custom_patterns=["*.o"])
            paths = [
                os.path.join(temp_dir, "main.c"),
                os.path.join(temp_dir, "main.o"),
            ]
            kept = f.filter_paths(paths)
            self.assertIn(paths[0], kept)
            self.assertNotIn(paths[1], kept)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
