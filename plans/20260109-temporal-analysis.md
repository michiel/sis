# Temporal Analysis for Incremental Updates - Technical Plan

**Date**: 2026-01-09  
**Status**: ✅ Implemented (Phase 1-5)  
**Owner**: ML explainability / inference pipeline  

## Purpose

Add temporal analysis for PDFs with incremental updates so ML inference and explainability can report how risk evolves across revisions. The goal is to identify when suspicious behaviour first appears, how it escalates, and which findings and signals changed between versions.

## Scope

In scope:
- Parse incremental update boundaries and expose versioned views.
- Per-version scanning with detectors and extended feature extraction.
- Temporal ML inference with versioned scores and `TemporalSnapshot` series.
- Report integration and JSON/JSONL output.
- Tests and fixtures for incremental updates.
- Revision-driven, non-ML temporal signals for triage and reporting.

Out of scope (for this plan):
- UI visualisation beyond textual report/JSON.
- Training temporal models (this is inference-only).
- Cross-document temporal correlation.

## Architecture Overview

High level components:
1. **Versioned Parsing**: identify PDF update revisions and expose per-revision `ObjectGraph`.
2. **Versioned Scan**: run detectors per revision and record findings.
3. **Versioned Features & ML**: extract extended features per revision and run inference.
4. **Temporal Aggregation**: build `TemporalSnapshot` series and explain changes.
5. **Output**: add report and JSON/JSONL output for temporal analysis.

## Data Model

### New/Extended Structures

`crates/sis-pdf-core/src/explainability.rs` already defines:
- `TemporalSnapshot`
- `TemporalExplanation`

Extend with a minimal metadata container:
```rust
pub struct TemporalContext {
    pub update_index: usize,
    pub startxref_offset: u64,
    pub object_count: usize,
    pub trailer_count: usize,
}
```

`TemporalSnapshot` should carry:
- `version_label`: `v1`, `v2`, `v3` (or based on incremental offset)
- `score`: ML calibrated score
- `high_severity_count`: count of high/critical findings
- `finding_count`: total findings
- Optional: `context: TemporalContext`

### Report / Output

Add to `ComprehensiveExplanation`:
- `temporal_analysis: Option<TemporalExplanation>`

Add to `Report`:
- `ml_inference.temporal_analysis` already supported via `ComprehensiveExplanation`.

Add JSON/JSONL payload:
- JSON: nested under `report.ml_inference.explanation.temporal_analysis`
- JSONL: emit a record type `ml_temporal_snapshot` per version if enabled.

### Non-ML Temporal Signals

Add a non-ML section to capture revision-driven deltas that do not require ML inference:
```rust
pub struct TemporalSignalSummary {
    pub revisions: usize,
    pub new_high_severity: usize,
    pub new_attack_surfaces: Vec<String>,
    pub removed_findings: Vec<String>,
    pub new_findings: Vec<String>,
    pub structural_deltas: Vec<String>,
}
```

Guidance:
- `new_high_severity`: count of findings with `High/Critical` that appear for the first time in later revisions.
- `new_attack_surfaces`: list of surfaces introduced in later revisions.
- `removed_findings`: findings present earlier but absent later (potential evasion).
- `structural_deltas`: object count jumps, new object streams, or decoder anomalies.

## Implementation Phases

### Phase 1: Versioned Parsing (2-3 days)

**Goal**: Expose per-update object graphs with clear boundaries.

Tasks:
- Extend `sis_pdf_pdf` parsing to expose incremental update sections:
  - Extract `startxref` chain and previous xref offsets.
  - Build a list of update boundaries with offsets and trailer info.
- Add a helper in `sis-pdf-core`:
  - `fn build_versioned_graphs(bytes: &[u8], opts: ParseOptions) -> Vec<ObjectGraph>`
  - Ensure strict handling when xref chain is broken: emit best-effort with a warning.
- Add `TemporalContext` metadata for each version (offsets, counts).

Files:
- `crates/sis-pdf-pdf/src/*` (likely xref parsing utilities)
- `crates/sis-pdf-core/src/scan.rs` (helper to build versioned contexts)

Acceptance:
- Unit tests that detect at least two update boundaries in a fixture PDF.
- `build_versioned_graphs` returns correct number of versions.

### Phase 2: Versioned Scan Pipeline (3-4 days)

**Goal**: Run detectors per revision and record findings.

Tasks:
- Add `ScanContext::new_versioned(...)` for a given `ObjectGraph`.
- Implement `run_scan_versioned(...)`:
  - For each version, run detectors and produce a `Report`-like subset:
    - Findings only (no chains/intent needed for temporal snapshot).
  - Capture counts for `TemporalSnapshot`.
- Compute non-ML temporal signal deltas:
  - First/last appearance of finding kinds.
  - Added/removed attack surfaces across revisions.
  - Structural deltas from summaries (object counts, trailers, objstm).
- Add a command-level flag to enable versioned scans:
  - `--ml-temporal` for `sis scan` and `sis report`.
  - If a PDF has no incremental updates, emit a single snapshot.

Files:
- `crates/sis-pdf-core/src/runner.rs`
- `crates/sis-pdf/src/main.rs`

Acceptance:
- Tests for versioned run create snapshots with non-zero counts.

### Phase 3: Versioned Feature Extraction and ML (3-4 days)

**Goal**: Compute ML score per version.

Tasks:
- Reuse `extract_extended_features` for each revision with findings.
- Run `run_ml_inference` per revision (extended features only).
- Store versioned scores and labels in `TemporalSnapshot`.
- Add aggregation helper:
  - `analyse_temporal_risk(samples)` already exists; ensure it is called when `--ml-temporal`.

Files:
- `crates/sis-pdf-core/src/ml_inference.rs`
- `crates/sis-pdf-core/src/explainability.rs`

Acceptance:
- Snapshot series includes scores and a computed `TemporalExplanation`.

### Phase 4: Output Integration (2-3 days)

**Goal**: Report and JSON/JSONL output for temporal analysis.

Tasks:
- `report::format_ml_explanation_for_report`:
  - Add a “Temporal analysis” section with trend, score delta, and notable changes.
- JSONL output:
  - Emit `ml_temporal_snapshot` record for each version when `--ml-temporal` is set.
  - Emit an `ml_temporal_summary` record for the aggregated explanation.
- Non-ML temporal signals:
  - Add a “Temporal signals” section in the report even when ML is disabled.
  - Add JSON/JSONL records for `temporal_signal_summary`.
- JSON output is already nested in `Report` (no extra work if `ml_inference` is attached).

Files:
- `crates/sis-pdf-core/src/report.rs`
- `crates/sis-pdf/src/main.rs` (flag handling)

Acceptance:
- Markdown report includes temporal section when enabled.
- JSONL contains temporal records.

### Phase 5: Fixtures and Tests (2-3 days)

**Goal**: Validate correctness and stability.

Tasks:
- Add fixtures with incremental updates to `crates/sis-pdf-core/tests/fixtures/`.
  - Two versions: benign -> malicious content introduction.
- Add integration tests:
  - `tests/temporal.rs` to validate:
    - Snapshot count matches number of updates.
    - Trend direction matches known modification.
    - Notable changes include increased high-severity findings.

Acceptance:
- `cargo test -p sis-pdf-core` passes with new temporal tests.

## CLI/Usage

Add:
```
sis scan suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-temporal --ml-baseline models/benign_baseline.json
sis report suspicious.pdf --ml-model-dir models/ --ml-extended-features --ml-explain --ml-temporal --ml-baseline models/benign_baseline.json
```

Rules:
- `--ml-temporal` requires `--ml-explain` and a baseline.
- If versioning fails, fall back to a single snapshot and warn.

Add:
```
sis scan suspicious.pdf --temporal-signals --json
sis report suspicious.pdf --temporal-signals
```

Rules:
- `--temporal-signals` does not require ML or a baseline.
- Can run alongside `--ml-temporal`.

## Risks and Mitigations

- **Broken xref chains**: fall back to best-effort; warn and keep single snapshot.
- **Performance**: versioned scans are multiplicative. Add a cap (e.g., max 5 revisions) and a flag to increase.
- **Inconsistent findings**: enforce stable sorting for per-version comparisons.
- **Feature drift**: use the same feature schema across versions.
- **False deltas**: ensure detector output is stable; normalise ordering and use stable IDs for comparisons.

## Delivery Checklist

- [x] Versioned graph extraction implemented
- [x] Versioned scanning and ML inference
- [x] Temporal aggregation and explanations
- [x] CLI flags `--ml-temporal` and `--temporal-signals`
- [x] Report/JSONL outputs
- [x] Non-ML temporal signals and output
- [x] Fixtures and tests
- [ ] Update `USAGE.md`

## Implementation Notes

- Versioned scans are generated by slicing the input PDF based on `startxref` offsets.
- Temporal signals compute new/removed findings and attack surface deltas per revision.
- ML temporal snapshots reuse ML inference per revision with a single model/baseline.

## Estimated Timeline

Total: 2–3 weeks
- Phase 1: 2-3 days
- Phase 2: 3-4 days
- Phase 3: 3-4 days
- Phase 4: 2-3 days
- Phase 5: 2-3 days
