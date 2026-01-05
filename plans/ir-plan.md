# PDFObj IR Implementation Plan

This document expands the provided technical plan into a detailed, project-specific
implementation plan for SIS-PDF. It includes module boundaries, data structures,
interfaces, recovery behavior, and step-by-step integration work.

## Goals
- Add PDFObj IR extraction that is robust to malformed PDFs.
- Build an Object Reference Graph (ORG) from parsed objects and references.
- Add a semantic embedding pipeline (PDFObj2Vec) for object IR text.
- Add a GNN (GIN-style) classifier using ORG + embeddings.
- Keep default scans fast; only run IR/GNN when ML is enabled.

## Scope and Constraints
- ASCII-only outputs; deterministic ordering; stable IDs.
- Preserve existing parser and detectors; IR is additive.
- Add heavy ML dependencies behind a feature flag.
- Do not inline raw stream bytes in IR; use metadata only.
- Maintain compatibility with current `--ml` workflow.

## Architecture Overview

### New Modules / Crates
1) `crates/sis-pdf-pdf/src/ir.rs`
   - Convert `ObjectGraph` + `PdfAtom` into PDFObj IR lines.
   - Implements recovery/fallback handling in non-strict modes.

2) `crates/sis-pdf-core/src/org.rs`
   - Object Reference Graph (ORG) data model.
   - Reference extraction from `PdfAtom` trees.

3) `crates/sis-pdf-core/src/ir_pipeline.rs`
   - Orchestrates IR extraction, ORG construction, embeddings.
   - Produces `GraphFeatures` for ML inference.

4) `crates/sis-pdf-ml-graph/` (new crate; feature `ml-graph`)
   - Embedding backends (ONNX transformer or Word2Vec/Doc2Vec).
   - GNN inference (GIN). No training code required at runtime.

### Data Structures
- `PdfIrLine`
  - `obj_ref: (u32, u16)`
  - `path: String` (e.g. `/OpenAction/JS`)
  - `value_type: String` (name, dict, array, ref, num, str, bool, null, stream)
  - `value: String` (short value or ref id; no raw stream bytes)

- `PdfIrObject`
  - `obj_ref: (u32, u16)`
  - `lines: Vec<PdfIrLine>`
  - `deviations: Vec<String>` (optional; from parse recovery)

- `OrgGraph`
  - `nodes: Vec<ObjRef>` (obj/gen)
  - `adjacency: HashMap<ObjRef, Vec<ObjRef>>`
  - Optional: `reverse_adjacency`

- `GraphFeatures`
  - `node_texts: Vec<String>` (joined IR per object)
  - `node_embeddings: Vec<Vec<f32>>`
  - `edge_index: Vec<(usize, usize)>`

## 1. PDFObj IR Parser Implementation in Rust

### Objective
Extend the existing parsing infrastructure in `sis-pdf-pdf` to produce
PDFObj IR (assembly-like, per-object textual lines) that enumerates
key-value pairs and types, and remains robust against malformed PDFs.

### IR Format and Emission Rules
- Each object emits a list of IR lines that are stable and ordered.
- Dictionaries:
  - Emit a line for each key/value.
  - If the value is a nested dictionary, emit a placeholder line:
    - `1-0, /OpenAction, dict, <blank>`
  - Then emit nested lines using a full path:
    - `1-0, /OpenAction/S, name, /JavaScript`
    - `1-0, /OpenAction/JS, ref, 5-0`
- Arrays:
  - Short homogeneous arrays -> `num_list` or `name_list` with short values.
  - Mixed arrays -> `mix_list` with a short type summary.
- References:
  - Emit `ref` with `obj-gen` target.
- Streams:
  - Emit `stream` with metadata only (length, filters, optional decode ratio).
  - Never include raw stream bytes or decoded data in IR text.
- Primitives:
  - `num: 42`, `bool: true`, `null`, `str: (Hello)` (size-capped preview).

### Malformed PDF Handling (Non-Strict / Recovery Mode)
Implement Poir-style recovery behavior similar to existing deviation handling:
- Unterminated strings:
  - If `(` opened but no closing `)` found, close at EOF or before `endobj`.
  - Record a deviation (e.g., `string_unterminated`).
- Missing `endobj`:
  - Treat next `obj` token or EOF as implicit `endobj`.
  - Record deviation (e.g., `missing_endobj`).
- Incomplete arrays/dicts:
  - Auto-close missing `]` or `>>` tokens and continue.
  - Record deviation (e.g., `missing_dict_end`).
- Illegal or missing references:
  - Emit `ref` to missing obj as usual, and create a placeholder node in ORG.
- XRef/trailer anomalies:
  - Keep `recover_xref` path (scan objects regardless of xref integrity).
  - IR generation should proceed even if xref parsing is partial.

### Implementation Steps
1) Add `ir.rs` with `emit_ir(object: &ObjEntry, opts: IrOptions) -> PdfIrObject`.
2) Add `IrOptions`:
   - `max_lines_per_object`, `max_string_len`, `max_array_elems`.
3) Add recursive traversal that produces stable ordering of lines.
4) Link to parser deviations for transparent recovery reporting.
5) Unit tests for dict/array/ref/stream objects with expected IR output.

## 2. Object Reference Graph (ORG) Construction

### Objective
Build a directed reference graph where each object is a node and each
indirect reference is an edge. This is the structural backbone for ML.

### Extraction and Graph Rules
- For each `ObjEntry`, recursively traverse `PdfAtom` values.
- For each `PdfAtom::Ref { obj, gen }`, add `src -> target` edge.
- Store unique nodes using `(obj, gen)` tuple.
- Add placeholder nodes for missing referenced objects.
- Optional: create reverse edges if needed for certain models.

### Data Model
- `OrgGraph` with adjacency list and node list.
- Provide `edge_index()` for ML input (list of source/target indices).

### Implementation Steps
1) Add `org.rs` with `OrgGraph::from_object_graph(&ObjectGraph)`.
2) Add `collect_refs(obj: &PdfObj, out: &mut Vec<ObjRef>)`.
3) Add serialization helper for JSON/DOT export.

### Export and Debugging
- Extend `sis export-graph` or add `sis export-org`:
  - Output adjacency in JSON and/or DOT.
  - Include object IDs and counts for sanity checks.

## 3. Semantic Analysis and Embedding (PDFObj2Vec)

### Objective
Generate dense semantic vectors for each object based on its IR text,
so that ML can capture contextual meaning beyond scalar features.

### Embedding Strategies
1) Transformer Embeddings (BERT/CodeT5)
   - Preferred for semantic richness.
   - Load ONNX model at runtime for inference.
   - Use tokenizer files in `ml_model_dir`.
   - Output CLS embedding or mean pooled tokens.

2) Word2Vec / Doc2Vec (PV-DM)
   - Simpler, faster fallback.
   - Use pre-trained vectors loaded from `ml_model_dir`.
   - Average token vectors to produce object embedding.

3) Hybrid and Extensibility
   - Allow future integration with fine-tuned PDFObj2Vec models.
   - Keep backend interface stable for new models.

### Embedding Pipeline
1) IR Preparation:
   - Join object IR lines with a stable delimiter.
   - Normalize key/value tokens (e.g., `Type_/Page`).
   - Cap length to avoid extreme inputs.
2) Model Inference:
   - Batch object IR texts for better throughput.
   - Cache model instance across scans.
3) Storage:
   - Attach `Vec<f32>` embedding to ORG node index.

### API
- `EmbeddingEngine::embed(texts: &[String]) -> Vec<Vec<f32>>`
- Provide `EmbeddingConfig` to describe backend and model files.

### Performance Considerations
- Only run when `--ml` is enabled.
- Batch embeddings to reduce overhead.
- Keep memory bounded by dropping IR text after embedding if not needed.

## 4. Graph Neural Network (GNN) Classifier Design

### Objective
Use a GIN-style GNN to classify the ORG with node embeddings,
producing a PDF malware score.

### Model Design
- Input: `node_features [N, D]`, `edge_index [2, E]`.
- Multiple GIN layers:
  - `h_v = MLP( (1+eps)*h_v + sum(neighbors) )`.
- Readout: sum/mean pooling of node features.
- Output: score in [0,1], thresholded by `ml_threshold`.

### Inference Integration
- Use ONNX or TorchScript for inference.
- Model file in `ml_model_dir/graph.onnx`.
- Use `GraphModel::predict(features) -> MalwarePrediction`.

### Output Mapping
- Report the score and threshold in JSON/Markdown.
- Reuse existing ML reporting plumbing when possible.

## 5. Integration into SIS-PDF

### Project Structure
- `sis-pdf-pdf`: IR extraction only.
- `sis-pdf-core`: pipeline orchestration, ORG build.
- `sis-pdf-ml-graph`: embeddings + GNN (feature-flagged).

### Scan Flow (ML enabled)
1) Parse PDF -> `ObjectGraph`.
2) IR extraction -> `Vec<PdfIrObject>`.
3) ORG build -> `OrgGraph`.
4) Embedding -> `node_embeddings`.
5) GNN inference -> `ml_prediction`.
6) Report ML score/label in output.

### CLI and Config
- Extend `MlConfig`:
  - `mode: traditional|graph`
  - `embed_model_path`
  - `graph_model_path`
  - `embedding_backend`
- Auto-detect model type by inspecting `ml_model_dir`.
- Keep `--ml` flag; add `--ml-mode graph` if needed.

### Output Integration
- JSON: add `ml.graph.score`, `ml.graph.threshold`, `ml.graph.label`.
- Markdown: add a short ML section.
- SARIF: optional rule entry for ML classifier.

## 6. Additional Improvements and Considerations

### Modularization & Feature Flags
- `ml-graph` feature controls embedding/GNN dependencies.
- Default build remains lightweight.

### Performance Optimizations
- Load models once per run; reuse across batch scans.
- Parallelize embedding by object (optional, controlled by config).
- Avoid retaining large decoded streams during IR extraction.

### Memory Management
- Drop IR strings after embeddings computed unless explicitly requested.
- Cap IR generation per object and per file.

### Compatibility with Detectors
- IR/ORG are additive; detectors continue using `ObjectGraph`.
- Future: allow detectors to consume ORG for advanced analyses.

### Training and Model Updates
- Document offline training workflow:
  - Export IR + ORG dataset for model training.
  - Load trained model from `ml_model_dir`.

### Testing and Validation
- Unit tests for IR generation and ORG edges.
- Integration tests with dummy model.
- Malformed PDF fixtures for recovery handling.
- Fuzz tests for IR conversion on existing fuzz targets.

## Milestones
1) IR extraction + ORG build with unit tests.
2) Embedding backend scaffold + dummy inference.
3) GNN inference integration + CLI wiring.
4) ML report output + export utilities.
5) Performance tuning + docs.

## References
- PDFObj IR and PDFObj2Vec concepts (Liu et al., CCS 2025).
- Existing `ObjectGraph`, parsing, and ML config in SIS-PDF.
