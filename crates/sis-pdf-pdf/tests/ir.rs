use sis_pdf_pdf::{parse_pdf, ParseOptions};
use sis_pdf_pdf::ir::{ir_for_graph, IrOptions};

#[test]
fn ir_emits_nested_dict_paths() {
    let bytes = b"%PDF-1.7\n1 0 obj\n<< /Type /Page /OpenAction << /S /JavaScript /JS 5 0 R >> >>\nendobj\n5 0 obj\n(alert)\nendobj\n%%EOF";
    let graph = parse_pdf(
        bytes,
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 5_000_000,
            max_objects: 500_000,
            max_objstm_total_bytes: 256 * 1024 * 1024,
        },
    )
    .expect("parse pdf");
    let ir = ir_for_graph(&graph.objects, &IrOptions::default());
    let mut found_openaction = false;
    let mut found_openaction_s = false;
    for obj in ir {
        for line in obj.lines {
            if line.path == "/OpenAction" && line.value_type == "dict" {
                found_openaction = true;
            }
            if line.path == "/OpenAction/S" && line.value_type == "name" {
                found_openaction_s = true;
            }
        }
    }
    assert!(found_openaction);
    assert!(found_openaction_s);
}
