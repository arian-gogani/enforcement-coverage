#!/usr/bin/env python3
"""
Enforcement Coverage — find API routes carrying weaker authorization than
their siblings.

    python3 enforcement_coverage.py /path/to/repo
    python3 enforcement_coverage.py /path/to/repo --density
    python3 enforcement_coverage.py /path/to/repo --json

Supports FastAPI. Python 3.10+, no dependencies.

Verdicts:
    MISSING    established control absent, and the route has no control at all
    MISMATCH   route uses a weaker value from an ordered control vocabulary
    PRESERVED  consistent with established precedent
    UNKNOWN    insufficient evidence — abstains, never reported

Design rules, each learned by running against real code:
  - authorization often lives in function bodies, not Depends()
  - a route can carry several control families at once; evaluate each
  - HTTP verb is not operation class; derive it from what the body calls
  - action vocabularies (create/delete/execute) are not strength scales
  - only weakening is reported; stricter than precedent is not a bug
  - validation helpers that raise 422 are not authorization
  - wrapper functions must be inlined to find the real control
  - never compare across modules; it destroys precision
  - MISSING requires the route to carry no authorization control at all
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass, field

# Parsing third-party source emits SyntaxWarning for things like invalid
# escape sequences in their code. Those are not our problem and they bury
# the actual output.
warnings.filterwarnings("ignore", category=SyntaxWarning)

# ---------------------------------------------------------------- constants

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_CHAIN_DEPTH = 3
MIN_PRECEDENTS = 3
PRECEDENT_THRESHOLD = 0.80

AUTH_TOKENS = (
    "has_access", "has_permission", "check_access", "check_permission",
    "require_permission", "authorize", "can_access", "verify_access",
    "ensure_", "_verify_", "require_", "_require_", "has_admin", "allows",
)
STRENGTH_KWARGS = ("permission", "action", "level", "scope", "access")
RESOURCE_KWARGS = ("resource_type", "resource", "type")

AUTHZ_CODES = ("401", "403", "UNAUTHORIZED", "FORBIDDEN")
VALIDATION_CODES = ("400", "404", "409", "422", "BAD_REQUEST", "NOT_FOUND",
                    "UNPROCESSABLE", "CONFLICT")

MUTATION_TOKENS = (
    "insert", "update", "delete", "create", "upsert", "set_", "add_",
    "remove_", "commit", "save", "toggle", "archive", "restore", "revoke",
    "grant", "assign", "reset", "clear", "rename", "move_", "sync",
)
READ_TOKENS = ("get_", "list_", "search", "count_", "find_", "fetch", "read_")

NOISE_CALLS = {"debug", "info", "warning", "error", "exception",
               "model_dump", "model_validate", "dumps", "loads", "json"}

# Known permission level orderings, weakest first.
LEVEL_SCALES = [
    ["none", "read", "write", "admin", "owner"],
    ["read", "readwrite", "write"],
    ["view", "edit", "manage", "admin"],
    ["viewer", "editor", "admin", "owner"],
]
ACTION_TOKENS = {
    "create", "delete", "update", "execute", "run", "invoke", "list",
    "export", "import", "share", "duplicate", "archive", "restore",
    "publish", "deploy", "configure", "retry", "cancel",
}
PERMISSION_CLASS_ACTIONS = (
    "view", "read", "edit", "write", "create", "delete", "update",
    "manage", "admin", "owner", "execute", "list",
)

# ------------------------------------------------------------------- model


@dataclass
class Control:
    name: str
    factory: str | None = None
    args: list[str] = field(default_factory=list)
    source: str = "signature"
    resource_type: str | None = None

    @property
    def family(self) -> str:
        base = self.factory or self.name
        if self.resource_type and self.resource_type not in base.lower():
            return f"{base}:{self.resource_type}"
        return base

    @property
    def value(self) -> str | None:
        return self.args[0] if self.args else None


@dataclass
class Route:
    method: str
    path: str
    handler: str
    module: str
    lineno: int
    router_var: str | None = None
    path_params: list[str] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)

    @property
    def resource(self) -> str:
        for c in self.controls:
            if c.resource_type:
                return c.resource_type
        if self.path_params:
            return self.path_params[-1]
        segs = [s for s in self.path.split("/") if s and not s.startswith("{")]
        return segs[-1] if segs else ""

    @property
    def op_class(self) -> str:
        r = self.resource
        if _scoped(self.mutations, r):
            return "WRITE"
        if _scoped(self.reads, r):
            return "READ"
        return "READ" if self.method in READ_METHODS else "WRITE"

    @property
    def sibling_key(self) -> tuple:
        return (self.resource, self.module, self.op_class)

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


def _scoped(evidence: list[str], resource: str) -> list[str]:
    """Keep only DAO calls whose owner plausibly matches the resource."""
    if not resource:
        return evidence
    r = resource.rstrip("s").lower()
    sidecar = ("accessgrant", "permission", "share", "acl")
    out = []
    for e in evidence:
        owner = e.split(".")[0].rstrip("s").lower()
        tail = e.split(".")[-1].lower()
        if owner == r or r in owner or r in tail or any(s in owner for s in sidecar):
            out.append(e)
    return out


# --------------------------------------------------------------- ast helpers


def _literal(node):
    return str(node.value) if isinstance(node, ast.Constant) else None


def _name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _split_permission_class(name: str) -> tuple[str | None, str | None]:
    """CaseEditPermission -> ('case', 'edit')"""
    if not name.endswith("Permission"):
        return None, None
    parts = re.findall(r"[A-Z][a-z0-9]*", name[: -len("Permission")])
    low = [p.lower() for p in parts]
    for i, p in enumerate(low):
        if p in PERMISSION_CLASS_ACTIONS:
            return ("".join(low[:i]) or None), p
    return ("".join(low) or None), None


def _resource_from_guard(short: str) -> str | None:
    """ensure_flow_permission -> flow"""
    drop = {"ensure", "verify", "require", "check", "has", "is", "user", "can",
            "permission", "access", "auth", "authorize", "allows", "view",
            "admin", "for", "to", "the"}
    cand = [p for p in short.strip("_").split("_") if p and p not in drop]
    return cand[0] if cand else None


def parse_depends(node, source: str) -> Control | None:
    """Depends(x) / Security(x) / Depends(f('admin')) / PermissionsDependency([C])"""
    if not isinstance(node, ast.Call):
        return None
    if _name(node.func) not in ("Depends", "Security",
                                "fastapi.Depends", "fastapi.Security"):
        return None
    if not node.args:
        return None
    inner = node.args[0]

    if isinstance(inner, (ast.Name, ast.Attribute)):
        nm = _name(inner)
        return Control(nm, source=source) if nm else None

    if isinstance(inner, ast.Call):
        fac = _name(inner.func)
        if not fac:
            return None
        args = [a for a in (_literal(x) for x in inner.args) if a]
        for kw in inner.keywords:
            v = _literal(kw.value)
            if v:
                args.append(v)
        # permission-class list idiom
        if not args:
            for a in inner.args:
                if isinstance(a, ast.List):
                    for el in a.elts:
                        cn = _name(el)
                        if cn:
                            args.append(cn.split(".")[-1])
        return Control(fac, fac, args, source)
    return None


def parse_body_auth(node: ast.Call) -> Control | None:
    """An authorization call inside a handler body."""
    nm = _name(node.func)
    if not nm:
        return None
    short = nm.split(".")[-1].lower()
    if not any(t in short for t in AUTH_TOKENS):
        return None

    strength = resource = None
    for kw in node.keywords:
        v = _literal(kw.value)
        if not v:
            continue
        if kw.arg in STRENGTH_KWARGS and strength is None:
            strength = v
        if kw.arg in RESOURCE_KWARGS and resource is None:
            resource = v

    if strength is None:
        for a in node.args:
            lv = _literal(a)
            if lv and len(lv) < 24 and " " not in lv:
                strength = lv
                break
        if strength is None:
            for a in node.args:
                if isinstance(a, ast.Attribute):
                    strength = a.attr.lower()
                    break

    if resource is None:
        resource = _resource_from_guard(short)

    base = nm.split(".")[-1]
    return Control(base, base, [strength] if strength else [], "body", resource)


def body_controls(fn) -> list[Control]:
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            c = parse_body_auth(n)
            if c:
                out.append(c)
    return out


def classify_operation(fn) -> tuple[list[str], list[str]]:
    muts, reads = [], []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        nm = _name(n)
        if not nm or "." not in nm:
            continue
        short = nm.split(".")[-1].lower()
        if short in NOISE_CALLS or any(t in short for t in AUTH_TOKENS):
            continue
        if any(short.startswith(t) or f"_{t}" in short for t in MUTATION_TOKENS):
            muts.append(nm)
        elif any(short.startswith(t) for t in READ_TOKENS):
            reads.append(nm)
    return muts, reads


# ----------------------------------------------------------------- scanning


class ModuleScan(ast.NodeVisitor):
    def __init__(self, module: str):
        self.module = module
        self.routes: list[Route] = []
        self.router_controls: dict[str, list[Control]] = {}
        self.router_prefix: dict[str, str] = {}
        self.funcs: dict[str, ast.AST] = {}

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call) and _name(node.value.func) in (
            "APIRouter", "fastapi.APIRouter"
        ):
            if node.targets and isinstance(node.targets[0], ast.Name):
                var = node.targets[0].id
                ctrls, prefix = [], ""
                for kw in node.value.keywords:
                    if kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                        for el in kw.value.elts:
                            c = parse_depends(el, "router")
                            if c:
                                ctrls.append(c)
                    if kw.arg == "prefix":
                        prefix = _literal(kw.value) or ""
                self.router_controls[var] = ctrls
                self.router_prefix[var] = prefix
        self.generic_visit(node)

    def _handle(self, node):
        self.funcs[node.name] = node
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            target = _name(dec.func)
            if not target or "." not in target:
                continue
            router_var, method = target.rsplit(".", 1)
            if method not in HTTP_METHODS:
                continue

            path = (_literal(dec.args[0]) if dec.args else "") or ""
            controls = []
            for kw in dec.keywords:
                if kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                    for el in kw.value.elts:
                        c = parse_depends(el, "decorator")
                        if c:
                            controls.append(c)
            for d in list(node.args.defaults) + [
                x for x in node.args.kw_defaults if x
            ]:
                c = parse_depends(d, "signature")
                if c:
                    controls.append(c)

            muts, reads = classify_operation(node)
            self.routes.append(Route(
                method=method.upper(), path=path, handler=node.name,
                module=self.module, lineno=node.lineno, router_var=router_var,
                path_params=[s[1:-1].split(":")[0] for s in path.split("/")
                             if s.startswith("{") and s.endswith("}")],
                controls=controls + body_controls(node),
                mutations=muts[:6], reads=reads[:6],
            ))

    visit_FunctionDef = _handle
    visit_AsyncFunctionDef = _handle


def classify_guards(funcs: dict[str, ast.AST]) -> dict[str, str]:
    """AUTHZ vs VALIDATION by the HTTP status a guard raises."""
    direct, calls = {}, {}
    for name, fn in funcs.items():
        codes, called = set(), set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Raise):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Attribute) and sub.attr.startswith("HTTP_"):
                        codes.add(sub.attr)
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, int):
                        if 400 <= sub.value < 600:
                            codes.add(str(sub.value))
            if isinstance(node, ast.Call):
                nm = _name(node.func)
                if nm:
                    called.add(nm.split(".")[-1])
        calls[name] = called
        if any(any(t in c for t in AUTHZ_CODES) for c in codes):
            direct[name] = "AUTHZ"
        elif codes and all(any(t in c for t in VALIDATION_CODES) for c in codes):
            direct[name] = "VALIDATION"

    resolved = dict(direct)
    for name, called in calls.items():
        if name in resolved:
            continue
        kinds = {direct[c] for c in called if c in direct}
        if len(kinds) == 1:
            resolved[name] = kinds.pop()
    return resolved


def wrapper_controls(funcs: dict[str, ast.AST]) -> dict[str, list[Control]]:
    """Helpers that wrap an authorization call, e.g. _verify_x_write_access."""
    out = {}
    for name, fn in funcs.items():
        inner = [c for c in body_controls(fn) if c.name != name]
        if inner:
            out[name] = inner
    return out


def expand_permission_classes(ctrls: list[Control]) -> list[Control]:
    out = []
    for c in ctrls:
        handled = False
        for a in list(c.args):
            res, act = _split_permission_class(a)
            if act:
                out.append(Control(c.name, c.factory, [act], c.source, res))
                handled = True
        if not handled:
            out.append(c)
    return out


def scan(root: str) -> list[Route]:
    scans, funcs = [], {}
    skip = {".git", "node_modules", "venv", ".venv", "__pycache__",
            "site-packages", "tests", "test"}

    for dp, dn, fnames in os.walk(root):
        dn[:] = [d for d in dn if d not in skip]
        for fn in fnames:
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dp, fn)
            try:
                tree = ast.parse(open(full, encoding="utf-8", errors="replace").read())
            except (SyntaxError, ValueError):
                continue
            s = ModuleScan(os.path.relpath(full, root))
            s.visit(tree)
            scans.append(s)
            funcs.update(s.funcs)

    kinds = classify_guards(funcs)
    wrappers = wrapper_controls(funcs)
    routes = []

    for s in scans:
        for r in s.routes:
            if r.router_var in s.router_controls:
                r.controls.extend(s.router_controls[r.router_var])
            prefix = s.router_prefix.get(r.router_var or "", "")
            if prefix and not r.path.startswith(prefix):
                r.path = prefix + r.path
                r.path_params = [x[1:-1].split(":")[0] for x in r.path.split("/")
                                 if x.startswith("{") and x.endswith("}")]

            kept = [c for c in r.controls if kinds.get(c.name) != "VALIDATION"]
            seen = {(c.name, tuple(c.args)) for c in kept}
            for c in list(kept):
                for w in wrappers.get(c.name, []):
                    if kinds.get(w.name) == "VALIDATION":
                        continue
                    sig = (w.name, tuple(w.args))
                    if sig not in seen:
                        seen.add(sig)
                        kept.append(Control(w.name, w.factory, list(w.args),
                                            "inlined", w.resource_type))
            r.controls = expand_permission_classes(kept)
            routes.append(r)
    return routes


# ------------------------------------------------------------------ verdict


def classify_vocabulary(values: set[str]) -> str:
    """LEVEL (ordered) | ACTION (distinct operations) | SCOPE | SINGLETON"""
    vals = {v.lower() for v in values if v}
    if len(vals) <= 1:
        return "SINGLETON"
    if any("." in v or "_" in v for v in vals) and not (vals & ACTION_TOKENS):
        return "SCOPE"
    if vals & ACTION_TOKENS:
        return "ACTION"
    for scale in LEVEL_SCALES:
        if vals <= set(scale):
            return "LEVEL"
    return "SCOPE"


def level_rank(value: str) -> int | None:
    v = value.lower()
    for scale in LEVEL_SCALES:
        if v in scale:
            return scale.index(v)
    return None


def evaluate(changed: Route, others: list[Route]) -> dict:
    fams = defaultdict(list)
    for r in others:
        fams[r.sibling_key].append(r)

    precedents = [p for p in fams.get(changed.sibling_key, [])
                  if str(p) != str(changed)]

    out = {"route": str(changed), "handler": changed.handler,
           "module": changed.module, "resource": changed.resource,
           "op_class": changed.op_class, "precedents": len(precedents)}

    if len(precedents) < MIN_PRECEDENTS:
        out["verdict"] = "UNKNOWN"
        out["reason"] = f"only {len(precedents)} precedents, need {MIN_PRECEDENTS}"
        return out

    fam_count = Counter()
    fam_values = defaultdict(Counter)
    uncontrolled = 0
    for p in precedents:
        by_fam = defaultdict(list)
        for c in p.controls:
            by_fam[c.family].append(c)
        if not by_fam:
            uncontrolled += 1
            continue
        for f, cs in by_fam.items():
            fam_count[f] += 1
            for c in cs:
                if c.value:
                    fam_values[f][c.value] += 1

    if not fam_count:
        out["verdict"] = "UNKNOWN"
        out["reason"] = "no precedent carries a resolvable control"
        return out

    changed_fams = defaultdict(list)
    for c in changed.controls:
        changed_fams[c.family].append(c)

    established = {f: n for f, n in fam_count.items()
                   if n / len(precedents) >= PRECEDENT_THRESHOLD}
    if not established:
        top, n = fam_count.most_common(1)[0]
        out["verdict"] = "UNKNOWN"
        out["reason"] = (f"no family reaches {PRECEDENT_THRESHOLD:.0%}; "
                         f"top {top} at {n/len(precedents):.0%}")
        return out

    out["proof"] = [
        {"route": str(p),
         "controls": [{"family": c.family, "value": c.value} for c in p.controls]}
        for p in precedents
    ]

    findings = []
    for fam, n in sorted(established.items(), key=lambda kv: -kv[1]):
        sample = set(fam_values[fam])
        if fam in changed_fams and changed_fams[fam][0].value:
            sample.add(changed_fams[fam][0].value)
        vocab = classify_vocabulary(sample)

        if fam not in changed_fams:
            # A route carrying some other control is not missing one.
            # Claiming otherwise is a sufficiency judgment we cannot make.
            if uncontrolled or changed_fams:
                continue
            findings.append({
                "verdict": "MISSING", "family": fam, "vocabulary": vocab,
                "reason": (f"{n}/{len(precedents)} comparable "
                           f"{changed.op_class.lower()} operations on "
                           f"{changed.resource} use {fam}; this route has none"),
            })
            continue

        if vocab != "LEVEL":
            continue

        vals = fam_values[fam]
        if not vals:
            continue
        dom, dom_n = vals.most_common(1)[0]
        if dom_n / len(precedents) < PRECEDENT_THRESHOLD:
            continue

        cur = changed_fams[fam][0].value
        if not cur or cur == dom:
            continue

        dr, cr = level_rank(dom), level_rank(cur)
        if dr is None or cr is None or cr >= dr:
            continue  # direction filter: only weakening is reported

        findings.append({
            "verdict": "MISMATCH", "family": fam, "vocabulary": vocab,
            "reason": (f"{dom_n}/{len(precedents)} comparable "
                       f"{changed.op_class.lower()} operations on "
                       f"{changed.resource} require {fam}({dom}); "
                       f"this route requires only {fam}({cur})"),
        })

    if findings:
        findings.sort(key=lambda f: f["verdict"] != "MISSING")
        out.update(findings[0])
        return out

    out["verdict"] = "PRESERVED"
    out["reason"] = f"consistent with {len(established)} established control(s)"
    return out


# --------------------------------------------------------------------- cli


def analyze(routes: list[Route]) -> tuple[Counter, list[dict]]:
    counts, findings = Counter(), []
    for i, r in enumerate(routes):
        res = evaluate(r, [x for j, x in enumerate(routes) if j != i])
        counts[res["verdict"]] += 1
        if res["verdict"] in ("MISSING", "MISMATCH"):
            findings.append(res)
    return counts, findings


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    root = sys.argv[1]
    routes = scan(root)
    if not routes:
        print("No FastAPI routes found.")
        return 1

    controlled = [r for r in routes if r.controls]
    counts, findings = analyze(routes)

    if "--json" in sys.argv:
        print(json.dumps(findings, indent=2))
        return 0

    print(f"\n{root}")
    print(f"  routes                {len(routes)}")
    print(f"  with controls         {len(controlled)}  "
          f"({len(controlled)/len(routes):.1%})")

    if "--density" in sys.argv:
        fams = defaultdict(list)
        for r in routes:
            fams[r.sibling_key].append(r)
        dense = [k for k, v in fams.items() if len(v) >= MIN_PRECEDENTS]
        covered = sum(len(fams[k]) for k in dense)
        print(f"  sibling families      {len(fams)}  ({len(dense)} with "
              f">={MIN_PRECEDENTS} members)")
        print(f"  routes in families    {covered}  ({covered/len(routes):.1%})")

    print()
    for k in ("MISSING", "MISMATCH", "PRESERVED", "UNKNOWN"):
        print(f"  {k:<10} {counts[k]:5d}  {counts[k]/len(routes):6.1%}")

    if not findings:
        print("\nNo findings.")
        return 0

    print(f"\n{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  [{f['verdict']}] {f['route']}  ({f['module']}:{f['handler']})")
        print(f"    {f['reason']}\n")
        for p in f.get("proof", []):
            ctl = ", ".join(
                f"{c['family']}({c['value']})" if c["value"] else c["family"]
                for c in p["controls"]
            ) or "none"
            print(f"      {p['route']:<44} {ctl}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
