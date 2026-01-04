# Security Review: sis-pdf

## Scope

This review focuses on hostile PDF inputs targeting the parsing, decoding, and analysis pipeline of `sis`/`sis-pdf`, plus adjacent entry points that ingest external data (JSONL, config, reports). The goal is to identify ways a malicious PDF could subvert analysis, exhaust resources, or break boundaries/sandboxing.

In-scope components:
- PDF parsing/graph construction in `crates/sis-pdf-pdf`.
- Stream decoding and object stream expansion (`decode_stream`, ObjStm expansion).
- Detector execution and JS sandbox feature in `crates/sis-pdf-detectors`.
- CLI output/reporting and extraction utilities in `crates/sis-pdf` and `crates/sis-pdf-core`.

Out of scope:
- OS-level sandboxing around `sis` (no external sandbox is enforced in code).
- Third-party dependencies beyond their usage patterns here.

## Threat Model

Attacker controls one or more PDFs supplied to `sis` and aims to:
- Escape intended output directories or write arbitrary files.
- Exhaust CPU/memory/storage to degrade analysis availability.
- Hide or confuse analysis with malformed structures, parser differentials, or payload tricks.
- Abuse the JS sandbox (if enabled) to execute expensive loops or interfere with analysis stability.

Secondary attacker-controlled inputs:
- JSONL for campaign correlation, report JSON for response generation, configuration files, and ML model files (these are user-supplied but may be attacker-provided in batch workflows).

## Findings

### High severity

1) Path traversal via embedded file extraction
- Impact: A malicious PDF can write files outside the intended output directory when using `sis extract embedded`, enabling overwrites of arbitrary files reachable by the process.
- Evidence: `crates/sis-pdf/src/main.rs` uses `embedded_filename` to return `/F` or `/UF` directly and passes it to `outdir.join(name)` without sanitization.
- Risk: PDF-embedded filenames like `../../.bashrc` or absolute paths can escape `outdir`.
- Recommendation: Sanitize embedded filenames to a safe basename, reject path separators, and verify `outdir.join(safe_name)` stays within `outdir` (canonicalize and check prefix).

2) JavaScript sandbox runs untrusted JS in-process without limits
- Impact: Hostile PDFs can execute JS that loops forever or triggers heavy allocations, causing CPU or memory exhaustion and effectively DoS-ing analysis.
- Evidence: `crates/sis-pdf-detectors/src/js_sandbox.rs` uses `boa_engine::Context::default()` with no instruction/time limits or memory guards; execution is in-process.
- Recommendation: Add instruction/time budgets, limit heap, and ideally run JS in an isolated process with kill/timeouts. Consider default-off and explicit warning when `js-sandbox` is enabled.

3) Object stream expansion and parsing can exceed memory/CPU before safety checks
- Impact: PDFs with many or large object streams can cause memory spikes or long parse times before `max_objects` is enforced, enabling resource exhaustion.
- Evidence: `crates/sis-pdf-pdf/src/graph.rs` and `crates/sis-pdf-pdf/src/objstm.rs` decode and expand ObjStm data without a global decoded-bytes budget or object-count cap; `max_objects` in `crates/sis-pdf-core/src/runner.rs` is checked only after parsing completes.
- Recommendation: Enforce hard limits during parsing and ObjStm expansion (total decoded bytes, total expanded objects, maximum ObjStm count). Abort early on overflow.

### Medium severity

4) Terminal/Markdown injection via unescaped report output
- Impact: Malicious payload data can inject terminal escape codes or rendering tricks into console output and markdown reports, potentially misleading operators or altering terminal state.
- Evidence: `crates/sis-pdf-core/src/report.rs` prints payload previews and metadata directly into markdown and console output without escaping control characters.
- Recommendation: Escape or strip control characters for terminal output and markdown; render payloads in a safe escaped form by default.

5) Cache/report deserialization trusts local files without size limits
- Impact: If cache directories are shared or attacker-controlled, oversized JSON can cause memory pressure or slow parsing.
- Evidence: `crates/sis-pdf-core/src/cache.rs` uses `serde_json::from_slice` without size checks.
- Recommendation: Add file size caps before deserialization, and document cache directory trust requirements.

### Low severity

6) Unsafe lifetime extension in ObjStm expansion relies on invariants
- Impact: The `unsafe` transmute in ObjStm expansion assumes decoded buffers are retained for the graph lifetime; mistakes could lead to use-after-free if invariants change.
- Evidence: `crates/sis-pdf-pdf/src/objstm.rs` uses `std::mem::transmute` to extend the lifetime of decoded bytes.
- Recommendation: Document invariants prominently and add tests to prevent refactoring from breaking safety assumptions; consider alternative designs that avoid unsafe.

7) Extraction commands can write large data to disk without user confirmation
- Impact: A large or numerous embedded streams could fill disk space during `extract embedded`.
- Evidence: `crates/sis-pdf/src/main.rs` decodes up to 32MB per stream and writes to disk without an overall cap.
- Recommendation: Add total extraction size limits and/or a `--max-extract-bytes` option.

## Recommended Mitigations

- Enforce parsing budgets early: object count, total decoded bytes, ObjStm count.
- Sanitize embedded filenames rigorously; reject any path traversal and enforce strict basename rules.
- Add resource limits to JS sandbox; consider external process isolation for untrusted JS.
- Escape control characters in report output and previews.
- Introduce size caps for cache/report deserialization.

## Suggested Security Tests

- Fuzz parse/objstm expansion with corpus of malformed PDFs and large ObjStm counts.
- Regression tests for path traversal in `extract embedded` (e.g., `../` and absolute paths).
- JS sandbox test cases for infinite loops and large allocations; verify timeouts.
- Report rendering tests that include control characters and escape sequences.

## Notes

This review assumes adversarial PDFs are the primary threat and prioritizes preventing analysis denial-of-service and boundary escape. If the application is intended to run in hostile or multi-tenant environments, additional OS-level sandboxing and resource isolation are strongly recommended.
