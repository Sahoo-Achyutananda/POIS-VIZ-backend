import ast
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple


class CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        name = self._extract_name(node.func)
        if name:
            self.calls.add(name)
        self.generic_visit(node)

    def _extract_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._extract_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        return None


def _module_name(py_file: Path, backend_root: Path) -> str:
    rel = py_file.relative_to(backend_root).with_suffix("")
    return ".".join(rel.parts)


def _collect_functions(py_file: Path, module: str) -> List[Dict[str, object]]:
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source)

    functions: List[Dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        collector = CallCollector()
        collector.visit(node)

        fn_id = f"{module}.{node.name}"
        functions.append(
            {
                "id": fn_id,
                "name": node.name,
                "module": module,
                "line": node.lineno,
                "calls": sorted(collector.calls),
            }
        )

    return functions


def build_backend_callgraph() -> Dict[str, object]:
    backend_root = Path(__file__).resolve().parents[1]
    scan_roots = [backend_root / "crypto", backend_root / "routes", backend_root / "analysis"]

    all_functions: List[Dict[str, object]] = []
    for root in scan_roots:
        if not root.exists():
            continue
        for py_file in sorted(root.rglob("*.py")):
            if "__pycache__" in py_file.parts:
                continue
            module = _module_name(py_file, backend_root)
            all_functions.extend(_collect_functions(py_file, module))

    by_name: Dict[str, List[str]] = defaultdict(list)
    by_module_and_name: Dict[Tuple[str, str], str] = {}
    for fn in all_functions:
        by_name[fn["name"]].append(fn["id"])
        by_module_and_name[(fn["module"], fn["name"])] = fn["id"]

    nodes = [
        {
            "id": fn["id"],
            "label": fn["name"],
            "module": fn["module"],
            "line": fn["line"],
        }
        for fn in all_functions
    ]

    edges = []
    seen_edges: Set[Tuple[str, str]] = set()

    for fn in all_functions:
        source_id = fn["id"]
        source_module = fn["module"]

        for raw_call in fn["calls"]:
            simple_name = raw_call.split(".")[-1]

            # Prefer same-module resolution first.
            target_id = by_module_and_name.get((source_module, simple_name))

            # Otherwise use unique global match by function name.
            if target_id is None and len(by_name.get(simple_name, [])) == 1:
                target_id = by_name[simple_name][0]

            if target_id is None:
                continue

            edge_key = (source_id, target_id)
            if edge_key in seen_edges:
                continue

            seen_edges.add(edge_key)
            edges.append(
                {
                    "id": f"{source_id}->{target_id}",
                    "source": source_id,
                    "target": target_id,
                    "is_recursive": source_id == target_id,
                    "call": raw_call,
                }
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "scanned_roots": [str(path.relative_to(backend_root)) for path in scan_roots if path.exists()],
            "function_count": len(nodes),
            "edge_count": len(edges),
            "recursive_edges": sum(1 for edge in edges if edge["is_recursive"]),
        },
    }
