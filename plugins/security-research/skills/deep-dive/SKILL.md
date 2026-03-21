---
name: deep-dive
description: Exhaustive semantic analysis methodology for a single file or module. Read code deeply, understand every function, trace data flows, analyze state machines, reason about edge cases, and find vulnerabilities that pattern matching misses.
argument-hint: "<file_or_module_path>"
user-invokable: false
---

# Deep-Dive — Semantic Vulnerability Analysis

## Goal

Exhaustively analyze a single file or module for security vulnerabilities through **deep code understanding** — not pattern matching. This is the methodology that finds novel, complex vulnerabilities: use-after-free bugs found by understanding object lifecycles, logic flaws found by understanding algorithm invariants, injection bugs found by tracing data through 10 function calls.

**Quality bar**: Every finding must include the full reasoning chain demonstrating *why* the code is vulnerable. "It matches a pattern" is not sufficient — you must demonstrate understanding of the code's behavior.

## When to Use

- On high-priority modules identified in `attack-surface.md` Critical Module Ranking
- On files flagged by variant analysis or automated scan candidates
- On complex code that handles untrusted input, authentication, authorization, or sensitive operations
- When pattern-based detection found nothing but the module handles high-risk operations

## Procedure

### 1. Full Read

Read the **ENTIRE** file or module. Do not skim. For each function/method, understand:
- Purpose and intended behavior
- All inputs (parameters, globals, config, environment)
- All outputs (return values, mutations, side effects, I/O)
- Assumptions the code makes about its inputs
- Error handling paths — what happens on failure?

If the module imports from other project files, read those definitions too. Resolve every function call to understand what it actually does.

### 2. Trust Boundary Mapping

Identify every point where data crosses a trust boundary:
- **External input entry points**: HTTP parameters, headers, cookies, WebSocket messages, file uploads, CLI arguments, environment variables, database reads (if DB is shared), message queue payloads
- **Privilege boundaries**: Where does the code transition between privilege levels? Auth checks, role gates, permission decorators
- **Assumptions about input**: What does the code assume about data types, formats, lengths, character sets, encoding? Are these assumptions enforced or implicit?

Document each trust boundary with `file:line`.

### 3. Data Flow Tracing

For each entry point identified in Step 2:
1. **Follow the data forward** through every function call, transformation, and assignment
2. At each hop: Is the data validated? Transformed? Truncated? Encoded? Decoded?
3. **Map the complete chain**: input → [transformation₁] → [transformation₂] → ... → sink
4. **Note gaps**: Where does data pass through without any validation or transformation?
5. **Cross-function tracing**: If data passes into another function, follow it into that function's implementation. Do NOT assume the called function is safe — read it.

Pay special attention to:
- Data that passes through 3+ functions before reaching a sink
- Transformations that change encoding (URL decode, base64, HTML entities) — double-encoding bypasses
- Data stored in a database and later retrieved — second-order injection
- Data passed through message queues or caches — the consumer may trust it

### 4. State Machine Analysis

Map the states the code can be in and the transitions between them:
- What states are possible? (initialized, authenticated, authorized, processing, completed, error)
- What transitions are allowed? What guards exist on each transition?
- **Can any state be reached via an unexpected path?** (e.g., reaching "authorized" without going through "authenticated")
- **TOCTOU windows**: Is there a gap between checking a condition and acting on it? Can the condition change in that gap?
- **Concurrent access**: What happens if two requests hit this code simultaneously? Are shared resources protected?

### 5. Edge Case Reasoning

For each function that processes input, systematically consider:

| Edge Case | Question |
|---|---|
| **Empty** | What happens with empty string, empty array, null, undefined, None? |
| **Boundary** | Max integer, min integer, 0, -1, MAX_SIZE, MAX_SIZE+1? |
| **Type confusion** | String where int expected? Array where string expected? Object where primitive expected? |
| **Unicode** | Null bytes (`\x00`), overlong encodings, RTL characters, homoglyphs, combining characters? |
| **Encoding** | Double URL-encode, mixed encodings, invalid UTF-8 sequences? |
| **Length** | Extremely long input? Does truncation create a vulnerability? |
| **Concurrent** | Two simultaneous calls? Interleaved operations? |
| **Error path** | What state is left after an exception? Are resources cleaned up? Is partial work committed? |

### 6. Algorithm Understanding

If the code implements a non-trivial algorithm (compression, crypto, parsing, encoding, state machine, protocol handling):
1. **Understand the algorithm's invariants** — what must always be true for correctness?
2. **Identify boundary conditions** — where do counters wrap? Where do buffers fill?
3. **Check for off-by-one errors** — especially in loop bounds, buffer sizes, index calculations
4. **Verify mathematical assumptions** — integer overflow? Division by zero? Negative values in unsigned contexts?
5. **Protocol compliance** — does the implementation match the spec? What happens with malformed input that violates the spec?

### 7. Memory & Resource Lifecycle (C/C++/Rust/unsafe code)

For every dynamically allocated resource:
1. **Track the lifecycle**: allocation → use → free/close
2. **Error path cleanup**: If an error occurs between allocation and free, is the resource leaked?
3. **Use-after-free**: After a resource is freed, can any code path still reference it?
4. **Double free**: Can a resource be freed twice? (especially in error paths with goto/cleanup)
5. **Allocation size**: Is the size calculation correct? Can integer overflow produce a small allocation for large data?
6. **Ownership transfer**: When a pointer/handle is passed to another function, who owns it? Is this clear and consistent?

Skip this step if the target is a memory-safe language without unsafe blocks.

### 8. Cross-Reference & Self-Verification

For every potential finding from Steps 1-7:
1. **Check framework protections**: Does the web framework, ORM, or library automatically prevent this? Read `recon/architecture.md` Section 3 if available.
2. **Check for middleware**: Is there global middleware that sanitizes input or enforces auth before this code runs?
3. **Check for safe wrappers**: Does the project have utility functions that wrap dangerous operations safely? Are they used here?
4. **Adversarial check**: Actively try to prove the finding is NOT exploitable. What prevents exploitation? Document your reasoning either way.
5. **Exploitation feasibility**: Can an attacker actually reach this code path with controlled input? What preconditions must be met?

## Output

For each finding, document:
- **Location**: `file:line`
- **Vulnerability type**: CWE classification
- **Reasoning chain**: The complete chain of logic from input to impact — not just "matches pattern X"
- **Data flow**: source → [hops] → sink with file:line at each step
- **What prevents exploitation?**: Framework protections, middleware, type constraints — and why they're insufficient
- **Confidence**: HIGH / MEDIUM / LOW with justification
- **Exploitation scenario**: Concrete description of how an attacker would trigger this

If no vulnerabilities are found, document:
- What was analyzed (list functions/endpoints)
- Why the code is secure (specific protections observed)
- Any areas of concern that couldn't be fully resolved (e.g., "the custom sanitizer at `utils.py:45` appears correct but warrants fuzzing")
