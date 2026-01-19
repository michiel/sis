# Query predicate reference

This guide documents the `--where` predicate filters for `sis query`.

## Supported queries

Predicate filtering is supported for:
- `js`, `js.count`
- `embedded`, `embedded.count`
- `objects.list`, `objects.with`, `objects.count`
- `urls`, `urls.count`
- `events`, `events.document`, `events.page`, `events.field`, `events.count`
- `findings`, `findings.count`, `findings.kind`, `findings.high`, `findings.medium`, `findings.low`, `findings.info`, `findings.critical`

## Fields

Predicates can use these fields:
- `length`: size in bytes for the underlying payload or text field
- `entropy`: Shannon entropy (0-8 range) for the payload or text field
- `filter`: query-specific category (see mappings below)
- `type`: high-level category name for the record
- `subtype`: query-specific subtype (see mappings below)

## Field mappings by query

### JavaScript (`js`, `js.count`)
- `length`: extracted JavaScript bytes (decoded or raw depending on flags)
- `entropy`: extracted JavaScript bytes
- `type`: `Stream` or `String`
- `filter`: stream `/Filter` name (if present)
- `subtype`: stream `/Subtype` name (if present)

### Embedded files (`embedded`, `embedded.count`)
- `length`: extracted embedded payload bytes
- `entropy`: extracted embedded payload bytes
- `type`: `Stream`
- `filter`: stream `/Filter` name (if present)
- `subtype`: stream `/Subtype` name (if present)

### Objects (`objects.list`, `objects.with`, `objects.count`)
- `length`: stream length (decoded where possible; falls back to `/Length`)
- `entropy`: stream bytes entropy (0 when not available)
- `type`: object atom type (for example `Stream`, `Dict`, `Array`, `String`)
- `filter`: stream `/Filter` name (if present)
- `subtype`: dictionary or stream `/Subtype` name (if present)

### URLs (`urls`, `urls.count`)
- `length`: URL string length
- `entropy`: URL string bytes
- `type`: `Url`

### Events (`events*`)
- `length`: `action_details` string length
- `entropy`: `action_details` bytes
- `type`: `Event`
- `filter`: event level (`document`, `page`, `field`)
- `subtype`: `event_type`

### Findings (`findings*`)
- `length`: finding `description` length
- `entropy`: finding `description` bytes
- `type`: `Finding`
- `filter`: severity (`info`, `low`, `medium`, `high`, `critical`)
- `subtype`: finding `kind`

## Examples

```bash
# Large JavaScript payloads with high entropy
sis query js file.pdf --where "length > 1024 AND entropy > 5.5"

# Events triggered at document level
sis query events file.pdf --where "filter == 'document'"

# High severity findings
sis query findings file.pdf --where "filter == 'high'"

# Streams using FlateDecode
sis query objects.with Stream file.pdf --where "filter == '/FlateDecode'"
```
