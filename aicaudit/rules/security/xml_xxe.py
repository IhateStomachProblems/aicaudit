"""Detect XML External Entity processing (CWE-611)."""
import ast

from aicaudit.rules.base import Finding, Rule, Severity, register

# Known safe parser patterns
_SAFE_PATTERNS = ("defusedxml",)


def _is_unsafe_xml(func):
    """Check if a function name looks like an unsafe XML parser."""
    lower = func.lower()
    if "etree" in lower and "parse" in lower:
        return True
    if "lxml" in lower and ("parse" in lower or "fromstring" in lower):
        return True
    if "sax" in lower and "parse" in lower:
        return True
    if "minidom" in lower and "parse" in lower:
        return True
    if "xml.dom" in lower and "parse" in lower:
        return True
    # Handle common import aliases
    return func in ("ET.parse", "etree.parse", "ET.fromstring", "ElementTree.parse")


def _is_safe_parser(node):
    """Check if the call uses a safe XML parser (defusedxml or resolve_entities=False)."""
    # Check keyword arguments for resolve_entities=False
    for kw in node.keywords:
        if (
            kw.arg == "resolve_entities"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
        ):
            return True
    # Check if any argument references a defusedxml parser
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        if _references_defusedxml(arg):
            return True
    return False


def _references_defusedxml(node):
    """Recursively check if a node references defusedxml."""
    if isinstance(node, ast.Name):
        return "defusedxml" in node.id.lower()
    if isinstance(node, ast.Attribute):
        if "defusedxml" in node.attr.lower():
            return True
        return _references_defusedxml(node.value)
    if isinstance(node, ast.Call):
        return _references_defusedxml(node.func)
    return False


@register
class XXE(Rule):
    id = "S007"
    name = "xxe"
    severity = Severity.ERROR
    description = "Detect XXE: XML parsing without entity resolution disabled"
    description_zh = "检测XXE：未禁用实体解析的XML解析"

    def check(self, tree, context):
        from aicaudit.taint.imports import ImportTable, dotted_name

        findings = []
        module_table = ImportTable.from_module(tree)

        # scope-aware defusedxml resolution: `from defusedxml import
        # ElementTree` inside one function must not whitelist the same name
        # used by other functions in the file.
        def scope_safe(node) -> bool:
            table = module_table
            owner = _enclosing_function(tree, node)
            if owner is not None:
                table = ImportTable.from_scope(owner, base=module_table)
            canonical = dotted_name(node.func, table) or ""
            return "defusedxml" in canonical

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = _func_name(node.func)
            if not _is_unsafe_xml(func):
                continue
            if scope_safe(node):
                continue
            if _is_safe_parser(node):
                continue
            findings.append(self._make(node, func, context))
        return findings

    def _make(self, node, func, ctx):
        return Finding(rule_id=self.id,
                       message="XXE risk: XML parser without entity resolution disabled",
                       message_zh="XXE风险：未禁用实体解析的XML解析器",
                       file=str(ctx.file_path), line=node.lineno or 0,
                       severity=self.severity,
                       fix="Disable external entities: XMLParser(resolve_entities=False)",
                       cwe="CWE-611")


def _enclosing_function(tree: ast.Module, node: ast.Call):
    """Return the innermost function containing this call node (or None)."""
    best = None
    best_size: int | None = None
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = func.end_lineno or func.lineno
        if func.lineno <= node.lineno <= end:
            size = end - func.lineno
            if best is None or size < (best_size or 0):
                best, best_size = func, size
    return best


def _func_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
