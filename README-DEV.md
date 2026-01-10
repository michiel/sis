# Development guide

## Workspace layout

```
sis-pdf/
  Cargo.toml
  crates/
    sis-pdf-core/      Core scan pipeline, models, reporting
    sis-pdf-pdf/       PDF parsing, object graph, decoding
    sis-pdf-detectors/ Detection rules
    sis-pdf-ml-graph/  Graph ML inference utilities
    sis-pdf/           CLI front-end
    js-analysis/       JavaScript static and dynamic analysis
  docs/                Specifications and analysis documentation
  scripts/
    test_helpers/      Development test fixtures and helper code
```

## Build

```
cargo build
```

To enable JavaScript sandboxing for runtime behaviour analysis:

```
cargo build --features js-sandbox
```

To enable graph ML inference:

```
cargo build --features ml-graph
```

## Tests

```
cargo test
```

## Fuzzing

Install cargo-fuzz:

```
cargo install cargo-fuzz
```

List targets:

```
cd fuzz
cargo fuzz list
```

Run a target (examples):

```
cargo +nightly fuzz run lexer
cargo +nightly fuzz run parser
cargo +nightly fuzz run graph
cargo +nightly fuzz run objstm
cargo +nightly fuzz run decode_streams
```

To use a custom corpus, pass a directory path:

```
cargo +nightly fuzz run parser fuzz/corpus/parser
```

## Status

This is a working implementation aligned to the spec in `docs/sis-pdf-spec.md`. It focuses on parsing correctness, evidence spans, and a practical rule set.

JavaScript malware detection includes comprehensive static analysis across 22 malware categories with ~95% coverage of known PDF JavaScript malware patterns. See `docs/js-detection-roadmap.md` for implementation details and future enhancements.

Expect iterative hardening and expansion.
