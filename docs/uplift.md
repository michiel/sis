# Uplift Plan: State-of-the-Art Alignment (by Layer)

This plan targets the PARTIAL findings from `docs/pdf-state-of-the-art.md` and
positions the project for a stronger default posture. It also adds a robust,
default polyglot detection capability and a placeholder for semantic IR-style
object graph analysis.

## Formal Matrix (Current vs. Uplift)

| Layer | Structural Weakness (SoTA) | Current Coverage | Uplift Plan | Notes |
| --- | --- | --- | --- | --- |
| Syntactic | Header offset tolerance, malformed syntax, polyglots | Strict header check; recovery parsing | Add robust polyglot detection (default), header offset variance checks, mixed-magic detection | Make detection default; report as structural finding |
| Structural | Xref complexity, ObjStm concealment | Xref chain parsing, ObjStm expansion, density detection | Add explicit shadow-object mismatch checks, deep enumeration summaries, and diff-based structural reconciliation | Surface hidden objects with stronger evidence mapping |
| Interactive | /OpenAction, /AA, JavaScript | Action and JS detectors | Add action chain expansion across embedded sources; stronger cross-ref of triggers | Improve chain synthesis for multi-stage |
| External | /URI, /GoToR, /Launch, /SubmitForm | Action detectors | Add context scoring: external action + obfuscation + embedded origin | Prioritize risky combinations |
| Resource | Stream decoding risks, embedded files, binary payloads | Decode ratio metrics; embedded files | Add nested filter recursion, stream budget analytics in report, and resource anomaly normalization | Report resource risk in consistent format |
| Semantic IR | Object reference graph analysis | Not implemented | Placeholder for IR-style graph analysis and visitor framework | Details pending |

## Layer-by-Layer Plan (Implement PARTIAL Findings)

### 1) Syntactic Layer (Polyglot + Header Robustness)
- Default polyglot detection:
  - Scan first 4 KB and tail for multiple magic headers (PDF + common formats: PNG, JPG, GIF, ZIP, HTML/HTA markers).
  - Detect non-PDF magic at offset 0 with PDF header later in file; flag as polyglot risk.
  - Detect PDF header at offset 0 with secondary magic signatures embedded in body or tail.
  - Emit a new structural finding: `polyglot_signature_conflict`.
- Header offset and strictness:
  - Record header offset and EOF offset; flag unusual offsets beyond a configured threshold.
  - Elevate strict deviations when paired with action triggers.
- Reporting:
  - Add summary line: "polyglot risk: yes/no, format candidates".

### 2) Structural Layer (Hidden Objects + ObjStm Depth)
- Shadow object reconciliation:
  - Compare recovered xref objects vs. linear parse objects; report deltas.
  - Add finding: `object_shadow_mismatch` with evidence spans and counts.
- ObjStm deep enumeration improvements:
  - Ensure embedded object visitor findings include container refs and decoded offsets.
  - Add summary finding for embedded object count and anomalies per ObjStm.
- Structural diff report:
  - Add a "structural reconciliation" section that lists xref chain count, recovered vs. declared object totals, and ObjStm expansion totals.

### 3) Interactive Layer (Action Chains)
- Action chain expansion:
  - Trace /OpenAction and /AA into embedded objects (ObjStm, name trees, annotations).
  - Include chain rendering in report output and JSON.
- Action-to-payload correlation:
  - If JS present, link to decoded JS evidence and annotate action graph nodes.

### 4) External Layer (Risk Scoring + Context)
- Contextual risk scoring:
  - Combine external actions with obfuscation markers (multi-filter, hex-encoded names).
  - Emit a composite finding: `external_action_risk_context`.
- Report details:
  - Provide the target URI/filename and its evidence span.

### 5) Resource Layer (Stream/Embedded Risks)
- Nested filter recursion:
  - Detect deep filter chains and flag beyond a threshold.
  - Report per-stream decode ratio and filter chain length.
- Embedded payload normalization:
  - Normalize embedded files into a consistent "resource risk" group (filespec, embedded files, rich media).
- Evidence clarity:
  - Ensure raw and decoded evidence spans are included where safe to map.

## Polyglot Detection (Robust Default Capability)

### Requirements
- Enabled by default in `sis scan` and `sis report`.
- Must operate without deep decoding; use fast prefix/suffix scans and magic matching.
- Emit a single, stable finding ID with evidence and candidate formats.

### Detection Heuristics (Initial Set)
- Conflicting magic signatures (e.g., PNG, GIF, ZIP, HTML/HTA, PE) within header/tail windows.
- PDF header not at offset 0 and another format at offset 0.
- Multiple valid magic headers present within early bytes.

### Reporting
- Evidence spans for each detected magic.
- Note potential interpretation conflict and likely bypass vector.

## Suggestions (Immediate)
1) Add `polyglot_signature_conflict` detector in `crates/sis-pdf-detectors`.
2) Extend structural diff reporting to surface recovered-vs-xref object deltas.
3) Add action chain expansion across embedded object sources.
4) Normalize resource risk reporting to a single section with consistent labels.

## Placeholder: Semantic IR-Style Object Graph Analysis (TBD)

Placeholder for a future module that converts the object graph into a semantic
IR (basic-block style) for control-flow/data-flow analysis. Details will be
specified once requirements are available.
