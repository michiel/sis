# PDFObj IR Static Graph Analysis Plan (No ML)

This plan details how to use PDFObj IR + ORG for static malware signal detection
without machine learning. It focuses on deterministic, explainable rules that
operate over IR tokens and object reference graphs.

## Goals
- Use IR + ORG to detect suspicious structures and chains without ML.
- Emit actionable findings with evidence spans and object refs.
- Keep runtime fast; avoid heavy decoding unless explicitly enabled.

## Inputs
- PDFObj IR per object (assembly-like lines).
- ORG (Object Reference Graph) with nodes as object IDs and edges as refs.
- Existing ObjectGraph for evidence spans and object metadata.

## Core Static Signals

### 1) Suspicious Reference Paths
- Triggered when a high-risk action node reaches a payload node.
- Examples:
  - `/OpenAction` -> `/S /JavaScript`
  - `/AA` -> `/S /Launch`
  - `/Action` -> `/URI` or `/GoToR`
- Implementation:
  - Identify action nodes by IR tokens and/or existing detectors.
  - Run bounded BFS/DFS over ORG (depth 3-5) to find payload types.
  - Emit finding with path summary and involved object IDs.

### 2) Unreachable or Orphaned Payloads
- Objects containing payload-like IR tokens but not reachable from `/Root`.
- Examples: JS or action dictionaries not referenced from catalog or pages.
- Implementation:
  - Build reachability from catalog/root (use existing traversal helpers).
  - Flag payload-like objects outside reachable set.
  - Emit finding: `orphan_payload_object`.

### 3) Shadowed Object Chains
- Object ID shadowing or xref differentials with payload objects.
- Implementation:
  - Use existing `object_id_shadowing` and diff results.
  - If shadowed objects contain action/JS tokens, elevate severity.
  - Emit finding: `shadow_payload_chain` with object list.

### 4) Hidden Action Chains in ObjStm
- ObjStm entries containing action/JS tokens.
- Implementation:
  - Use IR paths containing `/ObjStm` context if available.
  - Or inspect objects originating from ObjStm (graph metadata).
  - Emit finding: `objstm_action_chain`.

### 5) External Action + Obfuscation Context
- Existing `external_action_risk_context` can be strengthened by IR:
  - Hex-escaped names in IR tokens.
  - Deep filter chains present on referenced streams.
  - Action targets buried in nested dictionaries.

### 6) Action-to-Embedded Payload Correlation
- Action objects that resolve to embedded files or rich media objects.
- Implementation:
  - ORG traversal from action nodes to embedded file nodes.
  - Emit finding: `action_embedded_payload_path` with chain.

## IR Token Rules (No Graph)

### 1) High-Risk IR Tokens
- `/JavaScript`, `/JS`, `/Launch`, `/GoToR`, `/SubmitForm`, `/URI`.
- Emit IR-only findings for objects containing these tokens.

### 2) Obfuscation Heuristics
- Hex-escaped names (`#xx` in PDF names) appearing in keys.
- Excessive nesting depth in IR paths (e.g., `/A/B/C/D/...`).
- Repeated or unusually long token sequences.

### 3) Stream Metadata Correlation
- IR stream metadata indicates risky filters or unusual lengths.
- If a stream is referenced from action/JS chains, escalate.

## Graph Scoring (Static)

### Graph Score Model (Deterministic)
- Score per finding based on:
  - Presence of action tokens.
  - Distance between action and payload nodes.
  - Obfuscation markers on path.
  - Shadowed or orphaned status.
- Final score can be mapped to severity:
  - High: short path + JS/Launch + obfuscation
  - Medium: action + external target
  - Low: isolated payload tokens

## Implementation Steps

### Step 1: IR Token Index
- Build a per-object token index from IR lines:
  - `token -> Vec<ObjRef>`
  - `obj -> Vec<String>`
- Use this for quick lookups (JS, Action, URI, etc.).

### Step 2: ORG Path Utilities
- Add bounded BFS utilities returning the path of object IDs.
- Reuse existing `graph_walk` helpers if possible.

### Step 3: Static Graph Detectors
- Add new detectors in `sis-pdf-detectors`:
  - `orphan_payload_object`
  - `action_payload_path`
  - `shadow_payload_chain`
  - `objstm_action_chain`
- Each detector emits findings with:
  - object refs
  - path summary
  - evidence spans

### Step 4: Reporting
- Add a report section: "IR/ORG Static Graph Findings".
- Include the path string and top IR tokens for context.

## Evidence and Explainability
- Findings include object IDs, IR paths, and evidence spans.
- Use existing evidence mapping for objects and actions.
- Keep a stable path string for reproducibility.

## Performance Considerations
- Bounded traversal depth; cap total path evaluations.
- Only build IR/ORG for scans where `--ml` or a new `--ir` flag is set.
- Optionally allow `--ir-depth` to control traversal depth.

## Tests
- Fixture: PDF with `/OpenAction` -> JS action -> stream.
- Fixture: orphaned JS object not reachable from catalog.
- Fixture: action object in ObjStm.
- Ensure stable finding IDs and paths.

## Deliverables
- New detectors and static rules.
- Path utilities and token index.
- Reporting improvements for IR/ORG static analysis.
