# Cool Techniques — Variant Analysis
<!-- Techniques are added by /security-research:capture-technique -->

### Re-Open "All Patched" Verdicts Each Time the Code Surfaces Again (learned 2026-05-02)
**When to apply**: Multi-pass audit where Run N's variant analysis verdicted a pattern as "all instances patched" or "fix complete", and Run N+M re-encounters the same code path through a different lens (new hint, new threat model, new module deep-dive).
**Technique**: Stale verdicts are persistent failure modes. When code reviewed before is back in scope, re-open the variant entry adversarially. Don't re-grep for the *pre-fix* pattern — that's how the original verdict was reached. Instead, re-trace the *bug's trigger condition* against the *post-fix* code: walk the iteration boundary, the multiplication overflow domain, the state-machine corner. "Patch landed" never means "patch is correct"; "fix complete" verdicts decay as audit context evolves.
**Example**: A filename-scanner CVE was patched by adding `(q-p) < sizeof(buf)` to the loop. Run 1 verdicted "all 5 instances patched". Six later runs re-grep'd for the unbounded pre-fix pattern, found nothing, moved on. The actual bug — an off-by-one in the new check itself — survived 9 runs and was only caught when the upstream advisory ID was supplied. A single iteration-boundary trace on Run 1 would have caught it.
