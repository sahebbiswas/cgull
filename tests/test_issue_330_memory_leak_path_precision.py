from types import SimpleNamespace

from cgull.cfg import NodeOwnershipEffects, filter_leak_exits_for_ownership
from cgull.engine import CGullScanner
from cgull.models import AnalysisEngine
from cgull.rules.memory_management import MemoryLeakRule


class _FakeCFG:
    def __init__(self):
        self.nodes = {
            1: SimpleNamespace(node_id=1, successors=[2], kind="assignment", reads=set(), writes={"p"}, alias_writes={}, expr_str="p = malloc(16)", freed=set()),
            2: SimpleNamespace(node_id=2, successors=[3], kind="funccall", reads={"q"}, writes=set(), alias_writes={}, expr_str="release(q)", freed=set()),
            3: SimpleNamespace(node_id=3, successors=[], kind="return", reads=set(), writes=set(), alias_writes={}, expr_str="return", freed=set()),
        }
        self._locations = {
            1: {"p": {"alloc_1_p"}},
            2: {"p": {"alloc_1_p"}, "q": {"alloc_1_p"}},
            3: {"p": {"alloc_1_p"}, "q": {"alloc_1_p"}},
        }

    def get_loc_map_at_node(self, node_id):
        return self._locations[node_id]


def _scan(source: str):
    return CGullScanner(
        rules=[MemoryLeakRule()],
        engine_mode=AnalysisEngine.HYBRID,
    ).scan_text(source, "issue_330.c").issues


def test_definite_consumption_through_untracked_alias_drops_leak_exit():
    cfg = _FakeCFG()
    effects = {
        2: NodeOwnershipEffects(freed=frozenset({"q"})),
    }

    leak_exits = filter_leak_exits_for_ownership(
        cfg,
        1,
        "p",
        [cfg.nodes[3]],
        effects,
    )

    assert leak_exits == []


def test_possible_consumption_through_alias_remains_conservative():
    cfg = _FakeCFG()
    effects = {
        2: NodeOwnershipEffects(maybe_freed=frozenset({"q"})),
    }

    leak_exits = filter_leak_exits_for_ownership(
        cfg,
        1,
        "p",
        [cfg.nodes[3]],
        effects,
    )

    assert leak_exits == [cfg.nodes[3]]


def test_returned_alias_cleanup_is_not_reported_as_memory_leak():
    source = r"""
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        static char *alias_of(char *ptr) {
            return ptr;
        }

        void good(void) {
            char *data = (char *)malloc(32);
            if (data == 0) {
                return;
            }
            char *cleanup_ptr = alias_of(data);
            free(cleanup_ptr);
        }
    """

    assert _scan(source) == []


def test_cleanup_label_with_definite_free_is_safe_but_bypass_still_reports():
    source = r"""
        typedef unsigned long size_t;
        void *malloc(size_t);
        void free(void *);

        void good(int fail) {
            char *data = (char *)malloc(32);
            if (data == 0) {
                return;
            }
            if (fail) {
                goto cleanup;
            }
            data[0] = 'x';
        cleanup:
            free(data);
        }

        void bad(int bypass) {
            char *data = (char *)malloc(32);
            if (data == 0) {
                return;
            }
            if (bypass) {
                return;
            }
            free(data);
        }
    """

    issues = _scan(source)
    assert len(issues) == 1
    assert "data" in issues[0].message
