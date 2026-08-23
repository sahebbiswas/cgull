import unittest
from pycparser import c_parser
from cgull.cfg import (
    build_cfg, find_function_def,
    Nullness, Initialization, Allocation,
    BasicBlock, StructuredCFG
)


def _parse_and_build_cfg(code_str, func_name="f"):
    prelude = """
    typedef unsigned long size_t;
    void *malloc(size_t);
    void free(void *);
    """
    parser = c_parser.CParser()
    ast = parser.parse(prelude + code_str)
    fdef = find_function_def(ast, func_name)
    cfg = build_cfg(fdef)
    cfg.analyze_dataflow()
    return cfg


class TestCFGBasicBlocksAndDataflow(unittest.TestCase):

    def test_basic_blocks_construction_and_connections(self):
        code = """
        void f(int cond) {
            int x = 1;
            if (cond) {
                x = 2;
            } else {
                x = 3;
            }
            int y = x;
        }
        """
        cfg = _parse_and_build_cfg(code)
        self.assertGreaterEqual(len(cfg.blocks), 4)
        entry_block = cfg.blocks[cfg.node_to_block[cfg.entry]]
        self.assertGreaterEqual(len(entry_block.successors), 2)

    def test_nullness_fact_propagation_across_branches_and_joins(self):
        code = """
        void f(int cond, char *p) {
            if (p != NULL) {
                p[0] = 'a';
            } else {
                p = malloc(16);
            }
            p[0] = 'b';
        }
        """
        cfg = _parse_and_build_cfg(code)
        join_nodes = [n for n in cfg.nodes.values() if "p[0] = 'b'" in n.expr_str]
        self.assertEqual(len(join_nodes), 1)
        join_node_id = join_nodes[0].node_id
        p_null = cfg.query_nullness('p', join_node_id)
        self.assertIn(p_null, (Nullness.MAYBE_NULL, Nullness.NON_NULL))

    def test_initialization_fact_propagation_and_reassignment(self):
        code = """
        void f(int cond) {
            int status;
            if (cond) {
                status = 1;
            } else {
                status = 0;
            }
            int r = status;
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "r = status" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        status_init = cfg.query_initialization('status', use_node_id)
        self.assertEqual(status_init, Initialization.INITIALIZED)

    def test_uninitialized_fact_when_only_one_branch_assigned(self):
        code = """
        void f(int cond) {
            int status;
            if (cond) {
                status = 1;
            }
            int r = status;
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "r = status" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        status_init = cfg.query_initialization('status', use_node_id)
        self.assertEqual(status_init, Initialization.MAYBE_INITIALIZED)

    def test_allocation_lifetime_and_reassignment(self):
        code = """
        void f(char *p) {
            free(p);
            p = malloc(32);
            p[0] = 'x';
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "p[0] = 'x'" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        p_alloc = cfg.query_allocation('p', use_node_id)
        self.assertEqual(p_alloc, Allocation.ALLOCATED)

    def test_allocation_branch_join_maybe_allocated(self):
        code = """
        void f(int cond) {
            int *p;
            if (cond) {
                p = malloc(sizeof(*p));
            }
            *p = 1;
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "*p = 1" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        p_alloc = cfg.query_allocation('p', use_node_id)
        self.assertEqual(p_alloc, Allocation.MAYBE_ALLOCATED)

    def test_branch_join_free_and_use_rules(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import (
            UncheckedDynamicAllocationsRule,
            UseAfterFreeRule,
            DoubleFreeRule,
        )

        code = """
        void *malloc(size_t);
        void free(void *);

        void test_maybe_alloc(int cond) {
            int *p;
            if (cond) {
                p = malloc(sizeof(int));
            }
            *p = 1;
        }

        void test_maybe_free(int cond, char *p) {
            if (cond) {
                free(p);
            }
            free(p);
        }

        void test_uaf_maybe_free(int cond, char *p) {
            if (cond) {
                free(p);
            }
            *p = 'a';
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)
        self.assertIsNotNone(ast_ctx.pycparser_ast)

        rule_alloc = UncheckedDynamicAllocationsRule()
        issues_alloc = rule_alloc.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_alloc), 1)
        self.assertIn("p", issues_alloc[0].message)

        rule_df = DoubleFreeRule()
        issues_df = rule_df.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_df), 1)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_uaf), 1)

    def test_query_facts_at_program_location(self):
        code = """
        void f(char *ptr) {
            if (ptr == NULL) return;
            ptr[0] = 'z';
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "ptr[0] = 'z'" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        facts = cfg.get_facts_at_node(use_node_id)
        self.assertIn('ptr', facts)
        self.assertEqual(facts['ptr'].nullness, Nullness.NON_NULL)


class TestCFGGotoAndLabeledControlFlow(unittest.TestCase):

    def test_goto_forward_null_check_and_bypass(self):
        code = """
        void f() {
            char *p = malloc(16);
            if (p == NULL)
                goto out;
            *p = 'a';
        out:
            free(p);
        }
        """
        cfg = _parse_and_build_cfg(code)

        # Labels are represented as CFG targets
        label_nodes = [n for n in cfg.nodes.values() if n.kind == "label" and n.expr_str == "out"]
        self.assertEqual(len(label_nodes), 1)
        label_node = label_nodes[0]

        # goto label creates an edge to the corresponding label
        goto_nodes = [n for n in cfg.nodes.values() if n.kind == "goto" and "out" in n.expr_str]
        self.assertEqual(len(goto_nodes), 1)
        goto_node = goto_nodes[0]
        self.assertIn(label_node.node_id, goto_node.successors)

        # Forward gotos bypass intervening statements correctly (*p = 'a')
        use_nodes = [n for n in cfg.nodes.values() if "*p = 'a'" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id

        # At *p = 'a', p is known to be NON_NULL because the NULL path jumped to out
        p_null = cfg.query_nullness('p', use_node_id)
        self.assertEqual(p_null, Nullness.NON_NULL)

    def test_goto_backward_creates_cycle(self):
        code = """
        void f() {
            char *p;
        again:
            p = malloc(16);
            if (p == NULL)
                goto again;
            *p = 'b';
        }
        """
        cfg = _parse_and_build_cfg(code)

        label_nodes = [n for n in cfg.nodes.values() if n.kind == "label" and n.expr_str == "again"]
        self.assertEqual(len(label_nodes), 1)
        label_node = label_nodes[0]

        goto_nodes = [n for n in cfg.nodes.values() if n.kind == "goto" and "again" in n.expr_str]
        self.assertEqual(len(goto_nodes), 1)
        goto_node = goto_nodes[0]
        self.assertIn(label_node.node_id, goto_node.successors)

        # Verify reachability/cycle: goto again -> again label -> malloc -> if_cond -> goto again
        use_nodes = [n for n in cfg.nodes.values() if "*p = 'b'" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id
        self.assertEqual(cfg.query_nullness('p', use_node_id), Nullness.NON_NULL)

    def test_uaf_and_allocation_propagation_across_goto_paths(self):
        code = """
        void f(char *p, int flag) {
            if (flag)
                goto skip_free;
            free(p);
        skip_free:
            *p = 'c';
        }
        """
        cfg = _parse_and_build_cfg(code)

        use_nodes = [n for n in cfg.nodes.values() if "*p = 'c'" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id

        # On flag path, p is NOT freed; on !flag path, p IS freed -> meet result is MAYBE_FREED
        p_alloc = cfg.query_allocation('p', use_node_id)
        self.assertEqual(p_alloc, Allocation.MAYBE_FREED)

    def test_initialization_propagation_across_goto_paths(self):
        code = """
        void f(int cond) {
            int x;
            if (cond)
                goto init_path;
            goto out;
        init_path:
            x = 42;
        out:
            use(x);
        }
        """
        cfg = _parse_and_build_cfg(code)

        use_nodes = [n for n in cfg.nodes.values() if "use(x)" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        use_node_id = use_nodes[0].node_id

        # One path initializes x, the other skips initialization -> MAYBE_INITIALIZED
        x_init = cfg.query_initialization('x', use_node_id)
        self.assertEqual(x_init, Initialization.MAYBE_INITIALIZED)

    def test_rules_ast_scan_with_goto_cleanup_pattern(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import (
            UncheckedDynamicAllocationsRule,
            MissingNullCheckOnFunctionParametersRule,
            UseAfterFreeRule,
            DoubleFreeRule,
            UninitializedMemoryUseRule
        )

        code = """
        void *malloc(size_t);
        void free(void *);

        int process(int *param) {
            if (param == NULL)
                goto err;
            *param = 100; // Safe: checked by goto above

            char *buf = (char *)malloc(32);
            if (buf == NULL)
                goto err;
            buf[0] = 'X'; // Safe: checked by goto above

            free(buf);
            goto out;

        err:
            return -1;
        out:
            return 0;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)
        self.assertIsNotNone(ast_ctx.pycparser_ast)

        rule_alloc = UncheckedDynamicAllocationsRule()
        issues_alloc = rule_alloc.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_alloc), 0, "No unchecked dynamic allocation should be reported")

        rule_param = MissingNullCheckOnFunctionParametersRule()
        issues_param = rule_param.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_param), 0, "No missing null check on param should be reported")

    def test_unreachable_statements_after_goto_do_not_degrade_facts(self):
        code = """
        void f() {
            int x = 42;
            char *p = malloc(16);
            goto out;
            x = 0;
            free(p);
        out:
            use(x);
            use(p);
        }
        """
        cfg = _parse_and_build_cfg(code)

        use_x_nodes = [n for n in cfg.nodes.values() if "use(x)" in n.expr_str]
        self.assertEqual(len(use_x_nodes), 1)
        x_init = cfg.query_initialization('x', use_x_nodes[0].node_id)
        self.assertEqual(x_init, Initialization.INITIALIZED)

        use_p_nodes = [n for n in cfg.nodes.values() if "use(p)" in n.expr_str]
        self.assertEqual(len(use_p_nodes), 1)
        p_alloc = cfg.query_allocation('p', use_p_nodes[0].node_id)
        self.assertEqual(p_alloc, Allocation.ALLOCATED)


class TestExpressionControlFlow(unittest.TestCase):

    def test_ternary_expression_path_sensitive_nullness(self):
        code = """
        void f(int *p) {
            int val = p ? *p : -1;
        }
        """
        cfg = _parse_and_build_cfg(code)
        deref_nodes = [n for n in cfg.nodes.values() if "*p" in n.expr_str]
        self.assertEqual(len(deref_nodes), 1)
        deref_node_id = deref_nodes[0].node_id
        self.assertEqual(cfg.query_nullness('p', deref_node_id), Nullness.NON_NULL)

    def test_short_circuit_and_expression_path_sensitive_nullness(self):
        code = """
        void f(int *p) {
            if (p != NULL && *p == 1) {
                use(*p);
            }
            return;
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "use(*p)" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        self.assertEqual(cfg.query_nullness('p', use_nodes[0].node_id), Nullness.NON_NULL)

    def test_short_circuit_or_guard_clause(self):
        code = """
        void f(int *p) {
            if (p == NULL || *p == 0) {
                return;
            }
            use(*p);
        }
        """
        cfg = _parse_and_build_cfg(code)
        use_nodes = [n for n in cfg.nodes.values() if "use(*p)" in n.expr_str]
        self.assertEqual(len(use_nodes), 1)
        self.assertEqual(cfg.query_nullness('p', use_nodes[0].node_id), Nullness.NON_NULL)

    def test_juliet_style_ternary_free_and_alloc(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import MissingNullCheckOnFunctionParametersRule, UseAfterFreeRule, UncheckedDynamicAllocationsRule

        code = """
        void *malloc(size_t);
        void free(void *);

        void juliet_cwe476_ternary_good(int *p) {
            int x = p ? *p : 0;
        }

        void juliet_cwe415_ternary_good(char *p, int flag) {
            if (p == (char *)0) return;
            flag ? free(p) : (void)0;
        }

        void juliet_cwe252_ternary_alloc_good(int flag) {
            char *buf = (char *)malloc(10);
            if (buf == (void *)0) return;
            buf[0] = 'x';
            free(buf);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_null = MissingNullCheckOnFunctionParametersRule()
        issues_null = rule_null.scan_ast("juliet_test.c", ast_ctx)
        self.assertEqual(len(issues_null), 0, "Ternary pointer check should prevent missing NULL check finding")

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("juliet_test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 0, "Ternary free should not trigger false positive UAF on un-freed branch")

        rule_alloc = UncheckedDynamicAllocationsRule()
        issues_alloc = rule_alloc.scan_ast("juliet_test.c", ast_ctx)
        self.assertEqual(len(issues_alloc), 0, "Ternary allocation checked for NULL should not be flagged as unchecked")


class TestAliasLifetimeTracking(unittest.TestCase):

    def test_uaf_and_double_free_through_direct_alias(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule, DoubleFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_uaf_alias() {
            int *p = (int *)malloc(sizeof(*p));
            int *q = p;
            free(p);
            *q = 1;
        }

        void test_double_free_alias() {
            int *p = (int *)malloc(sizeof(*p));
            int *q = p;
            free(p);
            free(q);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 1)
        self.assertIn("q", issues_uaf[0].message)

        rule_df = DoubleFreeRule()
        issues_df = rule_df.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_df), 1)
        self.assertIn("q", issues_df[0].message)

    def test_alias_reassignment_before_free_or_use(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule, DoubleFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_reassign_q() {
            int *p = (int *)malloc(sizeof(*p));
            int *q = p;
            q = (int *)malloc(sizeof(*q));
            free(p);
            *q = 1;
            free(q);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 0)

        rule_df = DoubleFreeRule()
        issues_df = rule_df.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_df), 0)

    def test_original_ptr_reassigned_after_alias(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule, DoubleFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_reassign_p() {
            int *p = (int *)malloc(sizeof(*p));
            int *q = p;
            p = (int *)malloc(sizeof(*p));
            free(q);
            *p = 1;
            free(p);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 0)

        rule_df = DoubleFreeRule()
        issues_df = rule_df.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_df), 0)

    def test_transitive_aliases(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule, DoubleFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_transitive() {
            int *p = (int *)malloc(sizeof(*p));
            int *q = p;
            int *r = q;
            free(p);
            *r = 1;
            free(r);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 1)
        self.assertIn("r", issues_uaf[0].message)

        rule_df = DoubleFreeRule()
        issues_df = rule_df.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_df), 1)
        self.assertIn("r", issues_df[0].message)

    def test_loop_allocation_does_not_resurrect_retained_freed_alias(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_loop(int count) {
            int *q = 0;
            for (int i = 0; i < count; i++) {
                int *p = (int *)malloc(sizeof(int));
                if (!p) return;
                if (i > 0) {
                    *q = 1;
                }
                q = p;
                free(p);
            }
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_uaf), 1)
        self.assertIn("q", issues_uaf[0].message)

    def test_compound_assignment_does_not_alias(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_compound_op() {
            int *p = (int *)malloc(10 * sizeof(int));
            int *q = (int *)malloc(10 * sizeof(int));
            if (!p || !q) return;
            q += 1;
            free(p);
            *q = 123;
            free(q - 1);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 0)

    def test_realloc_invalidates_input_alias_locations(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void *realloc(void *, size_t);
        void free(void *);

        void test_realloc_alias() {
            int *p = (int *)malloc(10 * sizeof(int));
            if (!p) return;
            int *q = p;
            int *new_p = (int *)realloc(p, 20 * sizeof(int));
            if (!new_p) {
                free(p);
                return;
            }
            *q = 42;
            free(new_p);
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_uaf), 1)
        self.assertIn("q", issues_uaf[0].message)

    def test_uaf_attribution_multiple_frees(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void test_attribution() {
            int *p = (int *)malloc(sizeof(int));
            int *q = (int *)malloc(sizeof(int));
            if (!p || !q) return;
            free(p);
            free(q);
            *q = 1;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 1)
        self.assertIn("q", issues_uaf[0].message)
        # Check that the reported free line corresponds to free(q) (line 11), not free(p) (line 10)
        self.assertIn("was freed at line 11", issues_uaf[0].message)


class TestInterproceduralCFGSummaries(unittest.TestCase):

    def test_interprocedural_release_uaf(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void free(void *);

        void release(int *p) {
            free(p);
        }

        void f(int *p) {
            release(p);
            *p = 1;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 1)
        self.assertIn("p", issues_uaf[0].message)

    def test_interprocedural_get_buffer_null_deref(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import MissingNullCheckOnFunctionParametersRule, UncheckedDynamicAllocationsRule

        code = """
        typedef unsigned long size_t;

        int *get_buffer(void) {
            return 0;
        }

        void f(void) {
            int *p = get_buffer();
            *p = 1;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_null = MissingNullCheckOnFunctionParametersRule()
        issues_null = rule_null.scan_ast("test.c", ast_ctx)
        self.assertGreaterEqual(len(issues_null), 1)
        self.assertIn("p", issues_null[0].message)

    def test_interprocedural_transitive_wrapper(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void free(void *);

        void raw_free(int *ptr) {
            free(ptr);
        }

        void wrapper_release(int *p) {
            raw_free(p);
        }

        void f(int *p) {
            wrapper_release(p);
            *p = 42;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        self.assertEqual(len(issues_uaf), 1)
        self.assertIn("p", issues_uaf[0].message)

    def test_interprocedural_unknown_callee_conservative(self):
        from cgull.ast_analyzer import CASTParser
        from cgull.rules.memory_management import UseAfterFreeRule

        code = """
        typedef unsigned long size_t;
        void free(void *);
        void external_log(int *p);

        void f(int *p) {
            external_log(p);
            *p = 1;
        }
        """
        parser = CASTParser()
        ast_ctx = parser.parse(code)
        self.assertTrue(ast_ctx.has_pycparser)

        rule_uaf = UseAfterFreeRule()
        issues_uaf = rule_uaf.scan_ast("test.c", ast_ctx)
        # Unknown callee external_log is conservative: NOT assumed to free p unless proven or built-in
        self.assertEqual(len(issues_uaf), 0)


if __name__ == "__main__":
    unittest.main()
