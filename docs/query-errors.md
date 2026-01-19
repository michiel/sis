# Query error schema

This guide documents structured error output for `sis query` when `--format json` or `--format jsonl` is used (or the `--json` shorthand).

## JSON schema

Errors are returned as a `result` object with these fields:

```json
{
  "status": "error",
  "error_code": "OBJ_NOT_FOUND",
  "message": "Object 9999 0 not found",
  "context": {
    "requested": "9999 0"
  }
}
```

## Error codes

- `OBJ_NOT_FOUND`: requested object does not exist in the xref table
- `QUERY_SYNTAX_ERROR`: invalid query or predicate syntax
- `DECODE_ERROR`: stream decode failures or extraction issues
- `PARSE_ERROR`: malformed PDF structure or parse errors
- `PERMISSION_ERROR`: encrypted or permission-restricted content
- `FILE_READ_ERROR`: failed to read the input file
- `QUERY_ERROR`: fallback for uncategorised errors

## Behaviour

- Text output prints the `message` string.
- JSON output includes the error object under the `result` field.
- JSONL output emits one error per line (suitable for pipelines).
- Batch mode continues processing and includes error entries for failed files.
