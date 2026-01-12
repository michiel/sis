# JS sandbox expansion plan

## Objective

Build a repeatable pipeline to extract JavaScript from large PDF corpora, run
the payloads in the SIS JavaScript sandbox, capture failures, and turn those
failures into sandbox extensions and regression tests. Add a CLI entry point
(`sis sandbox eval FILE --type js`) to run dynamic evaluation on demand.

## Scope

- Corpus-scale extraction and sandbox evaluation.
- Failure capture and triage.
- Sandbox extension workflow with regression tests.
- CLI support for dynamic evaluation.

## Non-goals (for now)

- Dynamic evaluation for non-JS assets (images, fonts, etc).
- Automatic sandbox remediation (manual triage first).
- Full UI or dashboard integration.

## Phase 1 — CLI support

- Add `sis sandbox eval FILE` command.
- Provide `--type js` flag (default to `js`).
- Output JSON summary containing:
  - execution status, runtime errors, call counts, and key signals.
- Keep output stable for later scripts to consume.

## Phase 2 — Corpus extraction + execution

- Create a corpus runner script that:
  - Scans a corpus directory with `sis extract js` to dump JS payloads.
  - Runs `sis sandbox eval --type js` on each extracted payload.
  - Records successes, failures, and runtime errors into JSONL.
  - Emits a top-N failure summary (error messages + counts).
- Use parallel execution with a configurable worker count.
- Store logs under a predictable `out/` directory for repeatability.

## Phase 3 — Failure capture and sandbox extensions

- For each unique failure signature:
  - Save the minimal JS payload to a fixture file.
  - Add a regression test in `crates/js-analysis/tests/` (dynamic sandbox).
  - Extend the sandbox stub surface to handle the missing API or behaviour.
- Track fixes with a `failures.json` manifest to avoid duplicate effort.

## Phase 4 — Future extensions (placeholder)

- Extend `sis sandbox eval` to support other asset types.
- Add asset-specific evaluators under `crates/*` and update CLI dispatcher.

## Deliverables

- `sis sandbox eval` CLI command with `--type js`.
- Corpus runner script for extraction + evaluation.
- Failure manifest and fixture generation workflow.
- Tests covering fixed failures.

## Open questions

- JSON output schema for `sis sandbox eval` (minimal vs. verbose).
- Where to store corpus run artefacts (default `out/` path).
