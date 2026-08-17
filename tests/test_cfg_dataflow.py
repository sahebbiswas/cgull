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


if __name__ == "__main__":
    unittest.main()
