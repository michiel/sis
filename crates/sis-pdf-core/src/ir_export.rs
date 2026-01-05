use sis_pdf_pdf::ir::PdfIrObject;

pub fn export_ir_json(ir_objects: &[PdfIrObject]) -> serde_json::Value {
    let objects: Vec<serde_json::Value> = ir_objects
        .iter()
        .map(|obj| {
            let lines: Vec<serde_json::Value> = obj
                .lines
                .iter()
                .map(|l| {
                    serde_json::json!({
                        "obj": format!("{} {}", l.obj_ref.0, l.obj_ref.1),
                        "path": l.path,
                        "type": l.value_type,
                        "value": l.value,
                    })
                })
                .collect();
            serde_json::json!({
                "obj": format!("{} {}", obj.obj_ref.0, obj.obj_ref.1),
                "lines": lines,
                "deviations": obj.deviations,
            })
        })
        .collect();
    serde_json::json!({"objects": objects})
}

pub fn export_ir_text(ir_objects: &[PdfIrObject]) -> String {
    let mut out = String::new();
    for obj in ir_objects {
        out.push_str(&format!("# {} {}\n", obj.obj_ref.0, obj.obj_ref.1));
        for line in &obj.lines {
            out.push_str(&format!(
                "{}, {}, {}, {}\n",
                format!("{}-{}", line.obj_ref.0, line.obj_ref.1),
                line.path,
                line.value_type,
                line.value
            ));
        }
        if !obj.deviations.is_empty() {
            out.push_str(&format!("# deviations: {}\n", obj.deviations.join(",")));
        }
        out.push('\n');
    }
    out
}
