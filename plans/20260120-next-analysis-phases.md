# Implementation Plan: New sis-pdf Analysis Modules

## Goals
- Deliver six new analysis modules in staged, executable increments.
- Maintain safety, accuracy, efficiency, and completeness.
- Use Australian English spelling and structured `tracing` fields.
- Ensure all new findings have test coverage and documentation updates.

## Scope
Stages cover:
1) Embedded Files and Launch Actions
2) Actions and Triggers
3) XFA Forms
4) Rich Media Content
5) Encryption and Obfuscation
6) Filter Chain Anomalies

## Stage 0: Alignment, scope, and baseline

### Checklist
- [ ] Confirm existing findings and schemas to extend (`docs/findings.md`, any finding registry in code).
- [ ] Record which planned findings already exist vs need new IDs (mapping below).
- [ ] Identify shared helper needs (stream magic, hashing, entropy, filter parsing).
- [ ] Add or update fixtures in `crates/sis-pdf-core/tests/fixtures/` for attachments, actions, and media.
- [ ] Add test scaffolding in `crates/sis-pdf-detectors/tests/` or `crates/sis-pdf-core/tests/` as appropriate.
- [ ] Verify baseline tests pass.

### Acceptance
- Shared helpers and fixtures are in place.
- No new findings are emitted yet.
- Tests compile and run.

### Findings inventory (initial mapping)
- Existing IDs: `embedded_file_present`, `filespec_present`, `launch_action_present`, `aa_present`, `aa_event_present`, `open_action_present`, `annotation_action_chain`, `action_payload_path`, `gotor_present`, `submitform_present`, `uri_present`, `xfa_present`, `xfa_script_present`, `actionscript_present`, `swf_url_iocs`, `richmedia_present`, `3d_present`, `sound_movie_present`, `encryption_present`, `crypto_weak_algo`, `quantum_vulnerable_crypto`, `filter_chain_depth_high`, `declared_filter_invalid`, `undeclared_compression_present`, `label_mismatch_stream_type`.
- Implemented in Stage 1: `embedded_executable_present`, `embedded_script_present`, `embedded_archive_encrypted`, `embedded_double_extension`, `launch_external_program`, `launch_embedded_file`.
- Likely new IDs (if distinct from metadata): `action_chain_complex`, `action_hidden_trigger`, `action_automatic_trigger`, `xfa_submit`, `xfa_sensitive_field`, `xfa_too_large`, `swf_embedded`, `stream_high_entropy`, `embedded_encrypted`, `encryption_key_short`, `filter_chain_unusual`, `filter_order_invalid`, `filter_combination_unusual`.

## Stage 1: Embedded Files and Launch Actions

### Scope
Detect and enrich embedded file findings; correlate `/Launch` actions with embedded attachments and external program invocations.

### Checklist
- [ ] Implement `EmbeddedFileDetector` enhancements in `crates/sis-pdf-detectors`:
  - [ ] SHA-256, size, filename, and magic-type extraction.
  - [ ] Double extension detection.
  - [ ] Encrypted archive flag for ZIPs.
- [ ] Implement `LaunchActionDetector` enrichment:
  - [ ] Parse `/Launch` in `/Action`, `/AA`, `/OpenAction`.
  - [ ] Correlate `/F` and `/Win` targets with embedded files or external paths.
- [ ] Emit findings: `embedded_executable_present`, `embedded_script_present`, `embedded_archive_encrypted`, `embedded_double_extension`, `launch_external_program`, `launch_embedded_file`.
- [ ] Ensure evidence fields include object ids, filenames, file types, hashes, and launch targets.
- [ ] Register detector(s) in `crates/sis-pdf-detectors/lib.rs`.

### Tests
- [ ] Add fixtures for embedded EXE, embedded ZIP (encrypted), embedded script, and Launch action.
- [ ] Integration tests asserting metadata and finding IDs in `crates/sis-pdf-core/tests/`.

### Acceptance
- Deep scan emits attachment findings with metadata and Launch correlation.
- Tests cover all new findings and pass locally.

## Stage 2: Actions and Triggers

### Scope
Build action-trigger chain mapping and flag complex or hidden action paths.

### Checklist
- [ ] Implement `ActionTriggerDetector` to walk `/OpenAction`, `/AA`, annotation actions, and AcroForm triggers.
- [ ] Build a bounded action chain tracker (configurable max depth).
- [ ] Emit findings: `action_chain_complex`, `action_hidden_trigger`, `action_automatic_trigger`.
- [ ] Evidence includes event types, object ids, and chain path.
- [ ] Integrate with IR graph edges where available.

### Tests
- [ ] PDFs with annotation `/AA` to JavaScript, hidden widgets with actions, and multi-step chains.
- [ ] Benign hyperlink annotation to verify no false positives.

### Acceptance
- Chain findings surface in deep scan with stable evidence fields.
- Tests cover benign and malicious patterns.

## Stage 3: XFA Forms

### Scope
Parse XFA XML, detect embedded scripts and submissions, and enumerate sensitive fields.

### Checklist
- [ ] Implement `XfaFormDetector` to extract `/XFA` streams and parse XML.
- [ ] Detect `<script>` tags and emit `xfa_script_present` enrichments or new finding for scripts if required.
- [ ] Emit `xfa_submit` for submit actions with target URLs.
- [ ] Emit `xfa_sensitive_field` for sensitive field names.
- [ ] Emit `xfa_too_large` when size limits are exceeded.
- [ ] Register in Phase C and guard with XFA presence.

### Tests
- [ ] PDF with XFA script and submit action.
- [ ] PDF with oversized XFA content for size cutoff.

### Acceptance
- XFA findings appear with evidence; malformed XML does not crash scanning.
- Tests pass.

## Stage 4: Rich Media Content

### Scope
Inspect embedded SWF and other rich media streams for script tags and risky indicators.

### Checklist
- [ ] Implement `RichMediaDetector` enhancements:
  - [ ] Identify SWF by magic and emit `swf_embedded`.
  - [ ] Parse SWF tags and emit `actionscript_present` or a richer variant if required.
  - [ ] Detect 3D/media types (U3D/PRC/MP3/MP4) with size metadata.
- [ ] Enforce size limits and stream budgets.

### Tests
- [ ] PDF with embedded SWF containing ActionScript tags.
- [ ] PDF with embedded audio or 3D content.

### Acceptance
- SWF detection and ActionScript findings appear reliably.
- Tests cover SWF and at least one other media type.

## Stage 5: Encryption and Obfuscation

### Scope
Broaden encryption metadata checks and stream entropy detection.

### Checklist
- [ ] Implement `EncryptionDetector` to inspect `/Encrypt` dictionary and emit `encryption_present` plus weak algorithm findings.
- [ ] Compute stream entropy and emit `stream_high_entropy` when thresholds exceeded.
- [ ] Detect embedded encrypted archives or uncommon `/Crypt` filter usage.
- [ ] Add configuration for entropy thresholds and per-stream limits.

### Tests
- [ ] PDFs with RC4-40 and AES-128/256 encryption settings.
- [ ] PDF with high-entropy stream.

### Acceptance
- Encryption and high-entropy findings emitted with clear evidence.
- Tests cover weak and strong encryption cases.

## Stage 6: Filter Chain Anomaly Detection

### Scope
Detect unusual or invalid filter sequences beyond depth-only heuristics.

### Checklist
- [ ] Implement `FilterChainDetector` to validate filter order and flag uncommon combinations.
- [ ] Maintain a small allowlist of normal chains.
- [ ] Emit `filter_chain_unusual`, `filter_order_invalid`, `filter_combination_unusual`.
- [ ] Ensure integration does not conflict with `filter_chain_depth_high`.

### Tests
- [ ] PDFs with valid filter chains (should not trigger).
- [ ] PDFs with exotic or invalid filter sequences (should trigger).

### Acceptance
- Findings emitted only for anomalous filter sequences.
- Tests cover valid and invalid cases.

## Stage 7: Documentation and integration sweep

### Checklist
- [ ] Update `docs/findings.md` with new finding IDs, metadata fields, and evidence notes.
- [ ] Update any user-facing docs in `docs/` that reference CLI output.
- [ ] Ensure reporting/JSON schema documentation aligns with new findings.
- [ ] Run full test suite and targeted scans on sample PDFs.

### Acceptance
- Documentation matches emitted findings.
- Tests pass and sample scans show expected output using `sis`.

## Notes
- Each stage merges only when tests pass and findings metadata are defined.
- Keep new detectors within `crates/sis-pdf-detectors`.
- Avoid logging sensitive content; keep evidence concise and structured.
