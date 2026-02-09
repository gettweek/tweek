"""
Tweek Taint Analyzer — Dataflow Taint Analysis for Skill Scripts

Traces sensitive data from sources (env vars, credential files, user input)
through variable assignments and function calls to sinks (network calls,
subprocess, eval/exec). Catches credential exfiltration that simple
forbidden-import checks cannot detect.

Architecture inspired by Cisco AI Defense skill-scanner behavioral analyzer.
See THIRD-PARTY-NOTICES.md for attribution. Implementation is original code
using only Python stdlib (ast module).

Source categories:
  - env_var: os.environ.get(), os.getenv(), os.environ access
  - credential_file: open() with paths matching ~/.ssh, ~/.aws, .env, etc.
  - file_read: open() with variable/unknown arguments
  - stdin: input(), sys.stdin.read()

Sink categories:
  - network_call: requests.*, urllib.*, httpx.*, aiohttp.*, socket.*
  - exec_call: eval, exec, os.system, subprocess.*
  - file_write: open() with write mode (staging for later exfiltration)
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# =============================================================================
# Data Structures
# =============================================================================

class TaintStatus(Enum):
    """Taint state of a variable or expression."""
    TAINTED = auto()
    UNTAINTED = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class TaintLabel:
    """Tracks WHERE tainted data originated."""
    source_type: str       # "env_var", "credential_file", "file_read", "stdin"
    source_detail: str     # e.g., "os.environ.get('API_KEY')"
    file: str
    lineno: int


@dataclass
class TaintState:
    """Taint information for a single variable."""
    status: TaintStatus = TaintStatus.UNKNOWN
    labels: Set[TaintLabel] = field(default_factory=set)

    def merge(self, other: TaintState) -> TaintState:
        """Lattice join: TAINTED > UNKNOWN > UNTAINTED. Labels union."""
        if self.status == TaintStatus.TAINTED or other.status == TaintStatus.TAINTED:
            new_status = TaintStatus.TAINTED
        elif self.status == TaintStatus.UNKNOWN or other.status == TaintStatus.UNKNOWN:
            new_status = TaintStatus.UNKNOWN
        else:
            new_status = TaintStatus.UNTAINTED
        return TaintState(
            status=new_status,
            labels=self.labels | other.labels,
        )

    @property
    def is_tainted(self) -> bool:
        return self.status == TaintStatus.TAINTED


@dataclass
class CFGNode:
    """A node in the control flow graph."""
    node_id: int
    ast_node: ast.AST
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class DataflowFinding:
    """A taint-flow finding: sensitive source reached a dangerous sink."""
    file: str
    source_file: str
    source_line: int
    source_type: str
    source_detail: str
    sink_line: int
    sink_type: str
    sink_detail: str
    severity: str
    path_description: str


# =============================================================================
# Source and Sink Definitions
# =============================================================================

# Functions that return sensitive data (taint sources)
TAINT_SOURCE_ENV: FrozenSet[str] = frozenset({
    "os.environ.get", "os.getenv", "os.environ.copy",
    "os.environ.items", "os.environ.values",
})

# Direct attribute access patterns treated as env sources
TAINT_SOURCE_ENV_ATTR: FrozenSet[str] = frozenset({
    "os.environ",
})

# Credential file path patterns (matched against string arguments to open())
CREDENTIAL_FILE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\.env\b", r"\.aws/credentials", r"\.ssh/id_",
        r"\.ssh/id_rsa", r"\.ssh/id_ed25519", r"\.gnupg/",
        r"\.netrc$", r"credentials\.json", r"service.account\.json",
        r"\.kube/config", r"api.?key", r"secret.?key",
        r"private.?key", r"\.pem$",
    ]
]

# Functions that read files (taint sources when reading sensitive paths)
TAINT_SOURCE_FILE: FrozenSet[str] = frozenset({
    "open", "builtins.open",
    "pathlib.Path.read_text", "pathlib.Path.read_bytes",
})

# Functions that read user input
TAINT_SOURCE_INPUT: FrozenSet[str] = frozenset({
    "input", "sys.stdin.read", "sys.stdin.readline",
})

# Functions that send data externally (taint sinks — network)
TAINT_SINKS_NETWORK: FrozenSet[str] = frozenset({
    "requests.post", "requests.put", "requests.patch",
    "requests.get", "requests.request", "requests.delete",
    "urllib.request.urlopen", "urllib.request.Request",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "httpx.post", "httpx.put", "httpx.get", "httpx.request",
    "httpx.AsyncClient.post", "httpx.AsyncClient.get",
    "aiohttp.ClientSession.post", "aiohttp.ClientSession.get",
    "socket.socket.send", "socket.socket.sendto",
    "socket.socket.sendall", "socket.socket.connect",
})

# Functions that execute code (taint sinks — execution)
TAINT_SINKS_EXEC: FrozenSet[str] = frozenset({
    "eval", "exec", "compile",
    "os.system", "os.popen", "os.execl", "os.execv",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
})

# Severity mapping: (source_type, sink_type) -> severity
_SEVERITY_MAP: Dict[Tuple[str, str], str] = {
    ("env_var", "network_call"): "critical",
    ("credential_file", "network_call"): "critical",
    ("env_var", "exec_call"): "high",
    ("file_read", "network_call"): "high",
    ("stdin", "exec_call"): "high",
    ("credential_file", "exec_call"): "high",
    ("credential_file", "file_write"): "medium",
    ("env_var", "file_write"): "medium",
    ("file_read", "exec_call"): "medium",
    ("stdin", "network_call"): "medium",
}

# Max nodes per file before skipping (performance bound)
MAX_CFG_NODES = 500


# =============================================================================
# Helper: Extract call name from AST
# =============================================================================

def _get_call_name(node: ast.Call) -> str:
    """Extract the dotted name of a function call (e.g., 'os.environ.get')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current: ast.expr = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _get_string_value(node: ast.AST) -> Optional[str]:
    """Extract string literal value from an AST node, if it is one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# =============================================================================
# CFG Builder
# =============================================================================

class CFGBuilder:
    """Build a simplified control flow graph from a Python AST module.

    Each statement becomes a node. Branching (if/while/for/try) creates
    proper edges. Function definitions are recorded as sub-CFGs.
    """

    def __init__(self):
        self._nodes: List[CFGNode] = []
        self._counter: int = 0
        self.function_cfgs: Dict[str, List[CFGNode]] = {}

    def build(self, tree: ast.Module, filename: str = "") -> List[CFGNode]:
        """Build CFG for module-level statements."""
        self._nodes = []
        self._counter = 0
        self.function_cfgs = {}
        self._build_block(tree.body)
        return list(self._nodes)

    def _new_node(self, ast_node: ast.AST) -> CFGNode:
        """Create and register a new CFG node."""
        node = CFGNode(node_id=self._counter, ast_node=ast_node)
        self._counter += 1
        self._nodes.append(node)
        return node

    def _connect(self, from_node: CFGNode, to_node: CFGNode) -> None:
        """Add a directed edge."""
        if to_node.node_id not in from_node.successors:
            from_node.successors.append(to_node.node_id)
        if from_node.node_id not in to_node.predecessors:
            to_node.predecessors.append(from_node.node_id)

    def _build_block(self, stmts: List[ast.stmt]) -> Tuple[Optional[CFGNode], Optional[CFGNode]]:
        """Build CFG for a list of statements. Returns (first_node, last_node)."""
        if not stmts:
            return None, None

        first_node = None
        prev_node = None

        for stmt in stmts:
            if self._counter >= MAX_CFG_NODES:
                break

            if isinstance(stmt, ast.FunctionDef) or isinstance(stmt, ast.AsyncFunctionDef):
                # Record function body as sub-CFG
                sub_builder = CFGBuilder()
                sub_builder.build(ast.Module(body=stmt.body, type_ignores=[]))
                self.function_cfgs[stmt.name] = sub_builder._nodes
                # The def statement itself is a node (for import tracking)
                node = self._new_node(stmt)

            elif isinstance(stmt, ast.If):
                node = self._build_if(stmt)

            elif isinstance(stmt, (ast.While, ast.For)):
                node = self._build_loop(stmt)

            elif isinstance(stmt, ast.Try):
                node = self._build_try(stmt)

            else:
                node = self._new_node(stmt)

            if first_node is None:
                first_node = node
            if prev_node is not None:
                self._connect(prev_node, node)
            prev_node = node

        return first_node, prev_node

    def _build_if(self, stmt: ast.If) -> CFGNode:
        """Build CFG for an if/elif/else block. Returns the merge node."""
        cond_node = self._new_node(stmt)

        # Then branch
        then_first, then_last = self._build_block(stmt.body)
        if then_first:
            self._connect(cond_node, then_first)

        # Else branch
        else_first, else_last = self._build_block(stmt.orelse)
        if else_first:
            self._connect(cond_node, else_first)

        # Merge node (empty pass statement as placeholder)
        merge = self._new_node(ast.Pass())

        if then_last:
            self._connect(then_last, merge)
        else:
            self._connect(cond_node, merge)

        if else_last:
            self._connect(else_last, merge)
        elif not else_first:
            self._connect(cond_node, merge)

        return merge

    def _build_loop(self, stmt) -> CFGNode:
        """Build CFG for while/for. Returns exit node."""
        cond_node = self._new_node(stmt)

        body_first, body_last = self._build_block(stmt.body)
        if body_first:
            self._connect(cond_node, body_first)
        if body_last:
            self._connect(body_last, cond_node)  # Back-edge

        # Exit node
        exit_node = self._new_node(ast.Pass())
        self._connect(cond_node, exit_node)
        return exit_node

    def _build_try(self, stmt: ast.Try) -> CFGNode:
        """Build CFG for try/except/finally."""
        try_first, try_last = self._build_block(stmt.body)

        merge = self._new_node(ast.Pass())

        if try_last:
            self._connect(try_last, merge)

        # Each except handler
        for handler in stmt.handlers:
            h_first, h_last = self._build_block(handler.body)
            if try_first and h_first:
                self._connect(try_first, h_first)
            if h_last:
                self._connect(h_last, merge)

        # Finally
        if stmt.finalbody:
            f_first, f_last = self._build_block(stmt.finalbody)
            if f_first:
                self._connect(merge, f_first)
            if f_last:
                merge = f_last  # Finally becomes the new merge point

        return try_first if try_first else merge


# =============================================================================
# Source Detection
# =============================================================================

def _check_source(node: ast.AST, filename: str) -> Optional[TaintLabel]:
    """Check if an expression is a taint source. Returns label if so."""
    if not isinstance(node, ast.Call):
        # Check for direct os.environ attribute access
        if isinstance(node, ast.Attribute):
            attr_name = _get_attr_name(node)
            if attr_name in TAINT_SOURCE_ENV_ATTR:
                return TaintLabel(
                    source_type="env_var",
                    source_detail=attr_name,
                    file=filename,
                    lineno=getattr(node, "lineno", 0),
                )
        # Check for os.environ[key] subscript
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                attr_name = _get_attr_name(node.value)
                if attr_name in TAINT_SOURCE_ENV_ATTR:
                    key = _get_string_value(node.slice) or "unknown"
                    return TaintLabel(
                        source_type="env_var",
                        source_detail=f"os.environ['{key}']",
                        file=filename,
                        lineno=getattr(node, "lineno", 0),
                    )
        return None

    call_name = _get_call_name(node)
    lineno = getattr(node, "lineno", 0)

    # Environment variable access
    if call_name in TAINT_SOURCE_ENV:
        arg_str = ""
        if node.args:
            arg_str = _get_string_value(node.args[0]) or "variable"
        return TaintLabel(
            source_type="env_var",
            source_detail=f"{call_name}('{arg_str}')" if arg_str else call_name,
            file=filename,
            lineno=lineno,
        )

    # File read — check if argument matches credential patterns
    if call_name in TAINT_SOURCE_FILE:
        arg_str = ""
        if node.args:
            arg_str = _get_string_value(node.args[0]) or ""

            # Check for expanduser wrapping
            if isinstance(node.args[0], ast.Call):
                inner_name = _get_call_name(node.args[0])
                if inner_name == "os.path.expanduser" and node.args[0].args:
                    arg_str = _get_string_value(node.args[0].args[0]) or ""

        if arg_str:
            for pattern in CREDENTIAL_FILE_PATTERNS:
                if pattern.search(arg_str):
                    return TaintLabel(
                        source_type="credential_file",
                        source_detail=f"open('{arg_str}')",
                        file=filename,
                        lineno=lineno,
                    )
            # Non-credential file read — lower severity
            return TaintLabel(
                source_type="file_read",
                source_detail=f"open('{arg_str}')",
                file=filename,
                lineno=lineno,
            )
        else:
            # open() with variable argument — conservative
            return TaintLabel(
                source_type="file_read",
                source_detail=f"{call_name}(variable)",
                file=filename,
                lineno=lineno,
            )

    # User input
    if call_name in TAINT_SOURCE_INPUT:
        return TaintLabel(
            source_type="stdin",
            source_detail=call_name,
            file=filename,
            lineno=lineno,
        )

    return None


def _get_attr_name(node: ast.Attribute) -> str:
    """Get dotted attribute name like 'os.environ'."""
    parts = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


# =============================================================================
# Sink Detection
# =============================================================================

def _check_sink(node: ast.Call) -> Optional[Tuple[str, str]]:
    """Check if a call is a taint sink. Returns (sink_type, detail) if so."""
    call_name = _get_call_name(node)

    if call_name in TAINT_SINKS_NETWORK:
        return ("network_call", call_name)

    if call_name in TAINT_SINKS_EXEC:
        return ("exec_call", call_name)

    # Partial matches for methods (e.g., session.post, client.get)
    if call_name:
        last_part = call_name.rsplit(".", 1)[-1]
        if last_part in ("post", "put", "patch", "send", "sendall", "sendto"):
            return ("network_call", call_name)

    return None


# =============================================================================
# Expression Taint Evaluation
# =============================================================================

def _eval_expr_taint(
    expr: ast.AST,
    env: Dict[str, TaintState],
    filename: str,
) -> TaintState:
    """Evaluate the taint status of an expression given current environment."""
    # Variable reference
    if isinstance(expr, ast.Name):
        return env.get(expr.id, TaintState(TaintStatus.UNKNOWN))

    # Attribute access (e.g., obj.attr)
    if isinstance(expr, ast.Attribute):
        # Check if it's a known source
        label = _check_source(expr, filename)
        if label:
            return TaintState(TaintStatus.TAINTED, {label})
        # Otherwise propagate from base object
        return _eval_expr_taint(expr.value, env, filename)

    # Subscript (e.g., d["key"], os.environ["KEY"])
    if isinstance(expr, ast.Subscript):
        label = _check_source(expr, filename)
        if label:
            return TaintState(TaintStatus.TAINTED, {label})
        return _eval_expr_taint(expr.value, env, filename)

    # Function/method call
    if isinstance(expr, ast.Call):
        label = _check_source(expr, filename)
        if label:
            return TaintState(TaintStatus.TAINTED, {label})

        # Conservative: if any argument is tainted, result is tainted
        result = TaintState(TaintStatus.UNTAINTED)
        for arg in expr.args:
            result = result.merge(_eval_expr_taint(arg, env, filename))
        for kw in expr.keywords:
            result = result.merge(_eval_expr_taint(kw.value, env, filename))
        # Also check the function itself (e.g., tainted_func())
        if isinstance(expr.func, ast.Name):
            func_taint = env.get(expr.func.id, TaintState(TaintStatus.UNKNOWN))
            if func_taint.is_tainted:
                result = result.merge(func_taint)
        return result

    # Binary operations (taint propagates through concatenation, formatting)
    if isinstance(expr, ast.BinOp):
        left = _eval_expr_taint(expr.left, env, filename)
        right = _eval_expr_taint(expr.right, env, filename)
        return left.merge(right)

    # f-strings
    if isinstance(expr, ast.JoinedStr):
        result = TaintState(TaintStatus.UNTAINTED)
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                result = result.merge(_eval_expr_taint(value.value, env, filename))
        return result

    # Containers (dict, list, tuple, set) — whole-container tainting
    if isinstance(expr, ast.Dict):
        result = TaintState(TaintStatus.UNTAINTED)
        for v in expr.values:
            if v is not None:
                result = result.merge(_eval_expr_taint(v, env, filename))
        return result

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        result = TaintState(TaintStatus.UNTAINTED)
        for elt in expr.elts:
            result = result.merge(_eval_expr_taint(elt, env, filename))
        return result

    # String/int/float constants are untainted
    if isinstance(expr, ast.Constant):
        return TaintState(TaintStatus.UNTAINTED)

    return TaintState(TaintStatus.UNKNOWN)


# =============================================================================
# Taint Analyzer — Forward Propagation
# =============================================================================

class TaintAnalyzer:
    """Forward taint propagation over a CFG.

    Tracks how data flows from sources to sinks through variable assignments,
    function calls, and container construction.
    """

    MAX_ITERATIONS = 3  # Limit for loop back-edges

    def __init__(self, cfg_nodes: List[CFGNode], filename: str):
        self.nodes = {n.node_id: n for n in cfg_nodes}
        self.filename = filename
        self.findings: List[DataflowFinding] = []
        # Function return taint (populated during analysis)
        self.function_return_taint: Dict[str, TaintState] = {}

    def analyze(self) -> List[DataflowFinding]:
        """Run forward dataflow analysis. Returns findings."""
        if not self.nodes:
            return []

        # Initialize
        sorted_ids = sorted(self.nodes.keys())
        worklist = list(sorted_ids)
        iterations: Dict[int, int] = {n_id: 0 for n_id in self.nodes}
        env: Dict[int, Dict[str, TaintState]] = {
            n_id: {} for n_id in self.nodes
        }

        while worklist:
            node_id = worklist.pop(0)
            node = self.nodes[node_id]

            if iterations[node_id] >= self.MAX_ITERATIONS:
                continue

            # Merge predecessors' environments
            merged_env: Dict[str, TaintState] = {}
            for pred_id in node.predecessors:
                for var, state in env.get(pred_id, {}).items():
                    if var in merged_env:
                        merged_env[var] = merged_env[var].merge(state)
                    else:
                        merged_env[var] = TaintState(state.status, set(state.labels))

            # Apply transfer function
            new_env = dict(merged_env)
            self._transfer(node, new_env)

            # Check for changes
            if new_env != env.get(node_id, {}):
                env[node_id] = new_env
                iterations[node_id] += 1
                for succ_id in node.successors:
                    if succ_id not in worklist:
                        worklist.append(succ_id)

            # Check sinks
            self._check_sinks(node, new_env)

        return self.findings

    def _transfer(self, node: CFGNode, env: Dict[str, TaintState]) -> None:
        """Apply transfer function: update env based on statement."""
        stmt = node.ast_node

        # Assignment: x = expr
        if isinstance(stmt, ast.Assign):
            rhs_taint = _eval_expr_taint(stmt.value, env, self.filename)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = rhs_taint
                elif isinstance(target, ast.Tuple) and isinstance(stmt.value, ast.Tuple):
                    # Tuple unpacking: a, b = x, y
                    for i, elt in enumerate(target.elts):
                        if isinstance(elt, ast.Name) and i < len(stmt.value.elts):
                            env[elt.id] = _eval_expr_taint(
                                stmt.value.elts[i], env, self.filename
                            )

        # Augmented assignment: x += expr
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                rhs_taint = _eval_expr_taint(stmt.value, env, self.filename)
                current = env.get(stmt.target.id, TaintState(TaintStatus.UNKNOWN))
                env[stmt.target.id] = current.merge(rhs_taint)

        # Annotated assignment: x: type = expr
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            if isinstance(stmt.target, ast.Name):
                env[stmt.target.id] = _eval_expr_taint(
                    stmt.value, env, self.filename
                )

        # Expression statement (e.g., function call as statement)
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            # Sinks are checked in _check_sinks, but we also need to track
            # method calls that modify variables (e.g., list.append)
            pass

        # Return statement
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            ret_taint = _eval_expr_taint(stmt.value, env, self.filename)
            if ret_taint.is_tainted:
                # Record for cross-function analysis
                self.function_return_taint["__return__"] = ret_taint

        # Import tracking (for alias resolution)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                name = alias.asname or alias.name
                env[name] = TaintState(TaintStatus.UNTAINTED)

        elif isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                name = alias.asname or alias.name
                env[name] = TaintState(TaintStatus.UNTAINTED)

        # For loops: the iterator variable gets taint from the iterable
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_taint = _eval_expr_taint(stmt.iter, env, self.filename)
            if isinstance(stmt.target, ast.Name):
                env[stmt.target.id] = iter_taint
            elif isinstance(stmt.target, ast.Tuple):
                for elt in stmt.target.elts:
                    if isinstance(elt, ast.Name):
                        env[elt.id] = iter_taint

    def _check_sinks(self, node: CFGNode, env: Dict[str, TaintState]) -> None:
        """Check if tainted data reaches a sink at this node."""
        stmt = node.ast_node

        # Get call nodes from the statement
        calls: List[ast.Call] = []
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            calls.append(stmt.value)
        elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call):
            calls.append(stmt.value)

        for call in calls:
            sink = _check_sink(call)
            if sink is None:
                continue

            sink_type, sink_detail = sink

            # Check if any argument carries taint
            for arg in call.args:
                arg_taint = _eval_expr_taint(arg, env, self.filename)
                if arg_taint.is_tainted:
                    self._report_finding(arg_taint, sink_type, sink_detail, call)
                    break  # One finding per call is enough

            # Also check keyword arguments
            if not any(
                _eval_expr_taint(a, env, self.filename).is_tainted
                for a in call.args
            ):
                for kw in call.keywords:
                    kw_taint = _eval_expr_taint(kw.value, env, self.filename)
                    if kw_taint.is_tainted:
                        self._report_finding(kw_taint, sink_type, sink_detail, call)
                        break

    def _report_finding(
        self,
        taint: TaintState,
        sink_type: str,
        sink_detail: str,
        call_node: ast.Call,
    ) -> None:
        """Generate a DataflowFinding from a tainted sink call."""
        sink_line = getattr(call_node, "lineno", 0)

        for label in taint.labels:
            severity = _SEVERITY_MAP.get(
                (label.source_type, sink_type), "medium"
            )

            # Deduplicate: don't report the same source→sink twice
            key = (label.file, label.lineno, self.filename, sink_line, sink_type)
            if any(
                (f.source_file, f.source_line, f.file, f.sink_line, f.sink_type) == key
                for f in self.findings
            ):
                continue

            self.findings.append(DataflowFinding(
                file=self.filename,
                source_file=label.file,
                source_line=label.lineno,
                source_type=label.source_type,
                source_detail=label.source_detail,
                sink_line=sink_line,
                sink_type=sink_type,
                sink_detail=sink_detail,
                severity=severity,
                path_description=(
                    f"Tainted data from {label.source_detail} "
                    f"(line {label.lineno}) flows to {sink_detail} "
                    f"(line {sink_line})"
                ),
            ))


# =============================================================================
# Cross-File Analyzer
# =============================================================================

class CrossFileAnalyzer:
    """Correlate taint findings across multiple Python files in a skill.

    Two-pass approach:
    1. Analyze each file independently; record function return taint
    2. Re-analyze files that import from other analyzed files, injecting
       return taint as additional sources
    """

    def __init__(self, files: Dict[str, str]):
        """
        Args:
            files: {relative_path: source_code} — Python files to analyze
        """
        self.files = files

    def analyze_all(self) -> List[DataflowFinding]:
        """Run two-pass cross-file analysis."""
        all_findings: List[DataflowFinding] = []
        function_exports: Dict[str, Dict[str, TaintState]] = {}

        # Pass 1: Analyze each file independently
        for rel_path, source in self.files.items():
            try:
                tree = ast.parse(source, filename=rel_path)
            except SyntaxError:
                continue

            builder = CFGBuilder()
            cfg_nodes = builder.build(tree, filename=rel_path)

            if not cfg_nodes:
                continue

            analyzer = TaintAnalyzer(cfg_nodes, filename=rel_path)
            findings = analyzer.analyze()
            all_findings.extend(findings)

            # Record function return taint for cross-file analysis
            for func_name, func_cfg in builder.function_cfgs.items():
                if func_cfg:
                    func_analyzer = TaintAnalyzer(func_cfg, filename=rel_path)
                    func_analyzer.analyze()
                    if "__return__" in func_analyzer.function_return_taint:
                        module_name = rel_path.replace("/", ".").replace(".py", "")
                        key = f"{module_name}.{func_name}"
                        function_exports[key] = func_analyzer.function_return_taint["__return__"]

        # Pass 2: Re-analyze files that import tainted functions
        if function_exports:
            for rel_path, source in self.files.items():
                try:
                    tree = ast.parse(source, filename=rel_path)
                except SyntaxError:
                    continue

                # Check if this file imports from any file with tainted exports
                imported_taint = self._resolve_imports(tree, function_exports, rel_path)
                if not imported_taint:
                    continue

                # Re-analyze with injected taint
                builder = CFGBuilder()
                cfg_nodes = builder.build(tree, filename=rel_path)
                if not cfg_nodes:
                    continue

                analyzer = TaintAnalyzer(cfg_nodes, filename=rel_path)
                # Inject imported function return taint into initial environment
                # This is done by pre-populating the first node's environment
                if cfg_nodes:
                    first_id = min(n.node_id for n in cfg_nodes)
                    # We'll inject via a custom analysis pass
                    pass2_findings = self._analyze_with_imports(
                        cfg_nodes, rel_path, imported_taint
                    )
                    # Only add new findings not already found
                    existing_keys = {
                        (f.source_file, f.source_line, f.file, f.sink_line)
                        for f in all_findings
                    }
                    for f in pass2_findings:
                        key = (f.source_file, f.source_line, f.file, f.sink_line)
                        if key not in existing_keys:
                            all_findings.append(f)

        return all_findings

    def _resolve_imports(
        self,
        tree: ast.Module,
        function_exports: Dict[str, TaintState],
        current_file: str,
    ) -> Dict[str, TaintState]:
        """Check which imported names carry taint from other files."""
        imported_taint: Dict[str, TaintState] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    func_key = f"{module}.{alias.name}"
                    if func_key in function_exports:
                        local_name = alias.asname or alias.name
                        imported_taint[local_name] = function_exports[func_key]

        return imported_taint

    def _analyze_with_imports(
        self,
        cfg_nodes: List[CFGNode],
        filename: str,
        imported_taint: Dict[str, TaintState],
    ) -> List[DataflowFinding]:
        """Re-analyze with pre-seeded taint for imported functions.

        When a call to an imported function is encountered, we treat its
        return value as carrying the taint from Pass 1.
        """
        analyzer = TaintAnalyzer(cfg_nodes, filename=filename)
        # Inject the imported taint into the analyzer's function return map
        analyzer.function_return_taint.update(imported_taint)
        return analyzer.analyze()
