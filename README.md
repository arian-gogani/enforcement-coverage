# Enforcement Coverage

Finds API routes that carry a **weaker authorization control than their siblings**.

It found CVE-2026-45316 in Open WebUI from source alone, with no advisory knowledge:

```
[MISMATCH] POST /notes/{id}/pin  (notes.py:pin_note_by_id)
  3/3 comparable write operations on note require has_access(write);
  this route requires only has_access(read)

    POST   /notes/{id}/update          has_access(write)
    POST   /notes/{id}/access/update   has_access(write)
    DELETE /notes/{id}/delete          has_access(write)
```

Across **2,568 routes in five production codebases** it produced 4 findings.
Two were real. This README explains both numbers.

## The idea

A large class of authorization bugs is not a broken check. It is a missing or
weakened one, on a route whose siblings all got it right.

Portainer authorized four sibling template endpoints and not the fifth.
Signal K rate-limited HTTP login but not WebSocket login. Open WebUI's
note-pin route mutated a note while checking read permission, when every
other note mutation checked write.

Always the same shape:

```
✓ ✓ ✓ ✓ ✗
```

The repository already contains the rule. One route broke it. So reconstruct
the rule from the code and report the exception. No policy file, no config,
no annotations. The proof set is the sibling routes themselves.

## Run it

```bash
python3 enforcement_coverage.py /path/to/repo
python3 enforcement_coverage.py /path/to/repo --density
python3 enforcement_coverage.py /path/to/repo --json
```

Python 3.10+, no dependencies. FastAPI only.

Verdicts are `MISSING`, `MISMATCH`, `PRESERVED`, `UNKNOWN`. `UNKNOWN` abstains
and is never reported.

## What it does

**Extraction.** Resolves controls from signature `Depends()`, decorator
`dependencies=[]`, router-level dependencies, **function bodies**, wrapper
functions, and permission-class lists.

Body extraction is essential. In Open WebUI, 216 of 608 handlers carry the
decisive check inside the function:

```python
if user.role != 'admin' and not await AccessGrants.has_access(
    user_id=user.id, resource_type='note',
    resource_id=note.id, permission='write', db=db,
):
    raise HTTPException(status_code=403)
```

**Operation class** comes from what the handler does to the resource, not from
the HTTP verb. `POST /notes/{id}/chat` is a POST that reads a note.

**Vocabulary classification.** Two values in one control family do not
necessarily form a strength scale:

```
has_access             {read, write}                      LEVEL
ensure_flow_permission {create,delete,execute,read,write}  ACTION
has_permission         {features.notes, workspace.tools}   SCOPE
```

Only LEVEL vocabularies support strength comparison. Comparing
`FlowAction.CREATE` against a dominant `WRITE` produced six false positives in
Langflow before this was fixed.

**Direction filter.** Only deviations toward a *less* restrictive control are
reported. Stricter than precedent is not a vulnerability.

## What it found

| repo | routes | controlled | findings |
|---|---:|---:|---:|
| LiteLLM | 808 | 87.1% | 0 |
| Danswer / Onyx | 653 | 95.9% | 0 |
| Open WebUI | 529 | 97.2% | 2 |
| Netflix Dispatch | 291 | 36.1% | 1 |
| Langflow | 287 | 47.4% | 1 |

**Two true positives.**

`POST /notes/{id}/pin` in Open WebUI — CVE-2026-45316.

One further finding is a permission asymmetry in a currently maintained
project. It has been reported privately to the maintainers and details are
withheld until they have had a chance to respond.

**Two false positives.** `POST /tools/{id}/valves/user/update` writes the
user's *own* valve settings and legitimately needs only read on the tool — the
mutation target is a different entity than the authorization subject. And a
Langflow knowledge-base route where the sibling guard is not required.

## Why it mostly does not work

This is the useful part.

### Density does not predict findings

Danswer has 95.9% control coverage and produced zero findings with 80.7%
UNKNOWN. Its vocabulary is `require_permission('basic_access')`,
`('manage_connectors')` — a **capability namespace**, not a strength scale.
You cannot say `manage_connectors` is weaker than `read_connectors`.

What predicts findings is a **resource-scoped permission call with an ordered
strength argument**, like `has_access(resource, read|write)`. One codebase in
five had that.

### Every codebase needed different extraction

| repo | idiom |
|---|---|
| Open WebUI | `AccessGrants.has_access(resource_type=, permission=)` |
| Langflow | `ensure_<resource>_permission(user, Action.X)` |
| LiteLLM | role compare on `user_api_key_dict.user_role` |
| Netflix Dispatch | `Depends(PermissionsDependency([CaseEditPermission]))` |
| Danswer | `require_permission('basic_access')` |

Five idioms across five repositories. Each needed extractor work before the
analysis could run at all.

### UNKNOWN never dropped below 72%

In any repository, under any configuration. Most routes do not belong to a
sibling family of three or more with a consistent control.

## Defects found by running against real code

None of these were anticipated in advance.

1. authorization lives in function bodies, not `Depends()`
2. routes carry several control families at once
3. HTTP verb is not operation class
4. authorization idioms differ per repository
5. action vocabularies are not strength scales
6. stricter-than-precedent is not a vulnerability
7. vocabulary classified from precedents alone hides single-value families
8. validation helpers raising 422 are not authorization
9. wrapper functions hide the real control
10. permission-class-list idioms need name splitting
11. loosening sibling families raised findings 7.5x and dropped precision from 50% to 13%
12. a route with a *different* sufficient control is not missing one
13. **equivalent enforcement implemented inline rather than as a dependency** — unsolved

Defect 13 is the interesting one. Dispatch's tag-recommendation routes lack the
`CaseViewPermission` their siblings carry. But that permission returns True for
any non-restricted case, and the service already checks
`visibility == restricted` inline. The paths are equivalent. Detecting that
needs semantic equivalence analysis, not structure.

## Honest assessment

The mechanism works. It recovered a published CVE and one unreported
authorization gap from source, with auditable proof sets, using only
information available before the vulnerable commit merged.

The yield is roughly one finding per 1,000 routes, and it needs an architecture
that one of five substantial codebases had.

Useful as an audit tool for a codebase with a resource-scoped permission
vocabulary. Not, on this evidence, a general-purpose scanner.

## Prior art

Static detection of access-control vulnerabilities by inferring implicit
assumptions dates to USENIX Security 2011. ACMiner mined authorization checks
in Android middleware. Semgrep ships AI-powered detection targeting missing
authorization and reported 61% precision in one customer evaluation. OWASP
publishes an Authorization Regression Testing cheat sheet whose recommended
approach is maintaining an Actor × Resource × Action matrix by hand.

This is a narrow, deterministic take: recover only what sibling routes prove,
abstain otherwise.

MIT licensed.
