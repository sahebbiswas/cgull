from cgull.ast_analyzer import CASTParser
from cgull.rules.memory_management import UseAfterFreeRule


PRELUDE = """
typedef unsigned long size_t;
void *malloc(size_t);
void free(void *);
"""


def _scan(body: str):
    ctx = CASTParser().parse(PRELUDE + body)
    assert ctx.has_pycparser
    return UseAfterFreeRule().scan_ast("test.c", ctx)


def test_branch_free_then_null_does_not_reappear_at_join():
    issues = _scan(
        """
        void *f(int cond) {
            void *p = malloc(8);
            if (cond) {
                free(p);
                p = 0;
            }
            return p;
        }
        """
    )

    assert issues == []


def test_branch_free_then_fresh_allocation_does_not_reappear_at_join():
    issues = _scan(
        """
        void *f(int cond) {
            void *p = malloc(8);
            if (cond) {
                free(p);
                p = malloc(8);
            }
            return p;
        }
        """
    )

    assert issues == []


def test_branch_free_without_rebinding_still_reports():
    issues = _scan(
        """
        void *f(int cond) {
            void *p = malloc(8);
            if (cond) {
                free(p);
            }
            return p;
        }
        """
    )

    assert len(issues) == 1
    assert "pointer 'p'" in issues[0].message


def test_straight_line_free_then_null_remains_clean():
    issues = _scan(
        """
        void *f(void) {
            void *p = malloc(8);
            free(p);
            p = 0;
            return p;
        }
        """
    )

    assert issues == []


def test_clearing_original_pointer_does_not_hide_live_freed_alias():
    issues = _scan(
        """
        void *f(int cond) {
            void *p = malloc(8);
            void *alias = p;
            if (cond) {
                free(p);
                p = 0;
            }
            return alias;
        }
        """
    )

    assert len(issues) == 1
    assert "pointer 'alias'" in issues[0].message


def test_clearing_used_alias_is_clean_even_if_another_alias_remains():
    issues = _scan(
        """
        void *f(int cond) {
            void *p = malloc(8);
            void *alias = p;
            if (cond) {
                free(p);
                alias = 0;
            }
            return alias;
        }
        """
    )

    assert issues == []


def test_os_create_thread_control_flow_shape_is_clean():
    issues = _scan(
        """
        typedef int pthread_t;
        typedef int pthread_attr_t;
        int pthread_create(pthread_t *, pthread_attr_t *, void *, void *);

        pthread_t *OSCreateThread(
            pthread_attr_t *threadAttr,
            void *startRoutine,
            void *args
        ) {
            pthread_t *threadObject = malloc(sizeof(*threadObject));
            if (threadObject == 0)
                return 0;

            if (pthread_create(threadObject, threadAttr, startRoutine, args)) {
                free(threadObject);
                threadObject = 0;
            }

            return threadObject;
        }
        """
    )

    assert issues == []
