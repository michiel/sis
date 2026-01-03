use ysnp_pdf::parser::parse_indirect_object_at;

#[test]
fn parse_simple_object() {
    let data = b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n";
    let (entry, end) = parse_indirect_object_at(data, 0).unwrap();
    assert_eq!(entry.obj, 1);
    assert_eq!(entry.gen, 0);
    assert!(end as usize <= data.len());
}

#[test]
fn parse_literal_string_escape() {
    let data = b"2 0 obj\n(Hi\\nWorld)\nendobj\n";
    let (entry, _) = parse_indirect_object_at(data, 0).unwrap();
    if let ysnp_pdf::object::PdfAtom::Str(s) = entry.atom {
        let decoded = match s {
            ysnp_pdf::object::PdfStr::Literal { decoded, .. } => decoded,
            _ => Vec::new(),
        };
        assert_eq!(decoded, b"Hi\nWorld");
    } else {
        panic!("expected string");
    }
}
