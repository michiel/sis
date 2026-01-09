# ML Signals and Explainability - Progress Review

**Date**: 2026-01-09
**Reviewed Plan**: `plans/20260109-ml-signals-and-explainability.md`
**Scope**: Review of plan intent, implementation progress, delivered work, and planned phases.

## Progress Snapshot

- **Completed**: Phase 1.1-1.3 and Phase 1.6 as described, focused on feature expansion, explainability primitives, and unit tests.
- **In Progress**: Documentation and integration examples (Phase 1.4-1.5, 1.7).
- **Not Started**: Phases 2-6 and optional Phase 7.

## Implemented Work Review

### Strengths

- The feature expansion is comprehensive and maps onto the detector surface area.
- Feature extraction is mostly modular and testable.
- Explainability structures (attribution, evidence chains, baselines) are in place with reasonable unit coverage.

### Critical Issues and Gaps

1. **Feature count inconsistencies and misleading documentation**  
   The code and tests expect 333 features, while comments and struct documentation describe 320/321 with 70 finding flags (it is 71). This will confuse downstream tooling and training pipelines.  
   References: `crates/sis-pdf-core/src/features_extended.rs:1`, `crates/sis-pdf-core/src/features_extended.rs:65`, `crates/sis-pdf-core/src/features_extended.rs:2054`.

2. **Evidence chain linking for `finding.*` features is broken**  
   `find_contributing_findings` strips `_count` and `_present` from the wrong string, causing most `finding.*` features to never match actual finding kinds. This undermines evidence linking and explanation quality.  
   References: `crates/sis-pdf-core/src/explainability.rs:398`.

3. **URI feature extraction uses metadata keys that do not exist**  
   The extraction expects keys like `uri.is_ip_address`, `uri.obfuscated`, `uri.automatic_trigger`, and `uri.js_triggered`, which do not match current detector output (`uri.is_ip`, `uri.obfuscation`, `uri.automatic`, `uri.js_involved`). This will keep several URI features at zero regardless of actual content.  
   References: `crates/sis-pdf-core/src/features_extended.rs:1463`, `crates/sis-pdf-detectors/src/uri_classification.rs:635`.

4. **JS feature extraction relies on metadata that is not emitted**  
   Fields such as `js.obfuscation_score`, `js.eval_count`, `js.string_concat_layers`, and `js.unescape_layers` are not currently produced by detectors. Features depending on these keys will be systematically zero.  
   References: `crates/sis-pdf-core/src/features_extended.rs:1288`, `crates/js-analysis/src/static_analysis.rs:18`.

5. **Supply chain feature extraction is over-broad**  
   `finding.kind.contains("chain")` and other substring checks will misclassify unrelated findings (e.g., `annotation_action_chain`) as supply chain signals, inflating these features and weakening precision.  
   References: `crates/sis-pdf-core/src/features_extended.rs:1672`.

6. **URI aggregation counts include non-URI action findings**  
   URI feature totals are calculated from any finding on the `Actions` surface, even if no URI is present. This inflates counts and distorts risk profiles.  
   References: `crates/sis-pdf-core/src/features_extended.rs:1463`.

7. **Baseline score in explanations is not meaningful**  
   `create_ml_explanation` uses the average of benign feature means as a baseline score. This is not equivalent to a model baseline prediction and is likely misleading in reports.  
   References: `crates/sis-pdf-core/src/explainability.rs:838`.

8. **Integration gap: extended features and explainability are unused**  
   The new feature vector and explainability utilities are not wired into ML inference, CLI, or reports. The plan assumes these hooks, but they are absent.  
   References: `crates/sis-pdf-core/src/lib.rs:1`, `crates/sis-pdf-core/src/features_extended.rs:963`.

## Planned Work Review

### Phase 2-3 (IR/ORG semantic annotations and graph paths)

- These phases assume a stable schema for findings and object metadata. Given the current metadata mismatches, IR/ORG enrichment risks encoding empty or incorrect semantics.  
- Recommendation: lock a canonical metadata contract and update detectors before building IR/ORG annotations.

### Phase 4 (Risk profiles, calibration, comparative analysis)

- Calibration is listed as a later phase, but explainability text already makes confidence recommendations. This can lead to overconfident guidance without calibration.  
- Recommendation: move a minimal calibration pass earlier or add clear disclaimers in explanations until calibration is available.

### Phase 5 (Training pipeline)

- Feature schema drift is a major risk. With 333 features and weak metadata alignment, training could overfit or rely on zeros.  
- Recommendation: establish a feature schema file and a validation step that flags missing or unused features in training data.

### Phase 6 (Inference integration)

- Inference integration is currently blocked by the missing wiring and baseline model pipeline. This is the highest-leverage next step once metadata alignment is addressed.

### Phase 7 (Optional advanced explainability)

- Advanced features (counterfactuals, interactions) depend on stable model behaviour and faithful attribution. The current attribution method is closer to single-feature occlusion than permutation SHAP.  
- Recommendation: document the method precisely and evaluate stability before adding advanced explainability.

## Recommendations

### Immediate (next 1-2 sprints)

- Correct feature counts and documentation to match the actual vector size.
- Fix `find_contributing_findings` to strip suffixes from the correct string.
- Align URI and JS metadata keys with detector output; add or adjust detector metadata where necessary.
- Tighten supply chain extraction criteria (prefer explicit finding kinds or dedicated metadata).
- Adjust URI feature extraction to only include actual URI-related findings, not all action findings.

### Near-Term (Phase 2 prerequisites)

- Introduce a formal feature schema (names, types, source, intended range).
- Add a validation test that loads a real detector output and asserts non-zero coverage across key features.
- Decide on baseline score semantics and update explanation text accordingly.

### Medium-Term (Phases 2-6)

- Integrate extended feature extraction into ML inference and reporting.
- Implement a baseline computation workflow with real benign samples.
- Add calibration support before enabling “recommendation” language in explanations.

## Conclusion

The plan is ambitious and well-structured, and Phase 1 delivers a broad feature set and scaffolding for explainability. The main risk is that several feature groups are currently disconnected from real detector metadata, which undermines signal quality and explanations. Addressing metadata alignment, evidence linking correctness, and integration wiring should be prioritised before moving into IR/ORG enrichment and training pipeline work.
