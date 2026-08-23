# Adding an idiom

The extractor is idiom-specific by necessity. Five codebases needed five
different extraction strategies.

To add support for a new authorization idiom:

1. Add its callable name pattern to `AUTH_TOKENS`.
2. If it carries a strength argument, check `STRENGTH_KWARGS` or the
   positional fallback picks it up.
3. Run with `--density`. If control coverage is near zero, the idiom is not
   being seen.
4. Run normally. Hand-check every finding against source before claiming
   precision.

Rules that exist for a reason:

- **UNKNOWN must abstain.** Never turn an uncertain case into a finding.
- **MISSING requires the route to carry no authorization control at all.**
  A route with a different sufficient control is not missing one.
- **Only report weakening.** Stricter than precedent is not a bug.
- **Do not compare across modules.** Loosening sibling families raised
  findings 7.5x and dropped precision from 50% to 13%.

If you add a heuristic, measure precision on a real codebase and put the
number in the PR. Findings without hand-verification are not findings.
