# Query Interface Guide

This guide describes the `sis query` interface for exploring PDF structure, content, and findings.

## Basics

Run a one-shot query:

```bash
sis query sample.pdf images
```

Start an interactive REPL:

```bash
sis query sample.pdf
```

## Common Queries

```bash
sis query sample.pdf pages
sis query sample.pdf js.count
sis query sample.pdf embedded
sis query sample.pdf images
sis query sample.pdf images.risky
```

## Image Queries

Image queries report image XObjects and XFA images:

```bash
sis query sample.pdf images
sis query sample.pdf images.jbig2
sis query sample.pdf images.jpx
sis query sample.pdf images.ccitt
sis query sample.pdf images.risky
sis query sample.pdf images.malformed --deep
```

## Predicate Filters

Use `--where` to filter results:

```bash
sis query sample.pdf images --where "pixels > 1000000 AND risky == true"
sis query sample.pdf images --where "format == 'PNG' AND entropy > 7.5"
```

See `docs/query-predicates.md` for all fields.

## Extraction

Extract payloads to disk:

```bash
sis query sample.pdf images --extract-to /tmp/images
sis query sample.pdf images --extract-to /tmp/images --raw
```

## Output Formats

```bash
sis query sample.pdf images --format json
sis query sample.pdf images --format jsonl
```
