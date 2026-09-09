"""Compatible, scan-local project summaries attached to a parsed TU."""


def imported_summaries(ast_context, domain):
    return getattr(ast_context, "project_summaries", {}).get(domain, {})
