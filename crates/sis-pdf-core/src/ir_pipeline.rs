use std::collections::HashMap;

use sis_pdf_pdf::ir::{IrOptions, PdfIrObject};
use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::ObjRef;
use crate::org::OrgGraph;

#[derive(Debug, Clone)]
pub struct IrGraphArtifacts {
    pub ir_objects: Vec<PdfIrObject>,
    pub org: OrgGraph,
    pub node_texts: Vec<String>,
}

pub fn build_ir_graph(graph: &ObjectGraph<'_>, opts: &IrOptions) -> IrGraphArtifacts {
    let ir_objects = sis_pdf_pdf::ir::ir_for_graph(&graph.objects, opts);
    let org = OrgGraph::from_object_graph(graph);
    let mut ir_map: HashMap<ObjRef, &PdfIrObject> = HashMap::new();
    for obj in &ir_objects {
        let key = ObjRef {
            obj: obj.obj_ref.0,
            gen: obj.obj_ref.1,
        };
        ir_map.insert(key, obj);
    }
    let mut node_texts = Vec::new();
    for node in &org.nodes {
        if let Some(ir) = ir_map.get(node) {
            node_texts.push(render_ir_text(ir));
        } else {
            node_texts.push("<missing_object>".into());
        }
    }
    IrGraphArtifacts {
        ir_objects,
        org,
        node_texts,
    }
}

fn render_ir_text(obj: &PdfIrObject) -> String {
    let mut out = String::new();
    for line in &obj.lines {
        if !out.is_empty() {
            out.push_str(" ; ");
        }
        out.push_str(&line.path);
        out.push(' ');
        out.push_str(&line.value_type);
        out.push(' ');
        out.push_str(&line.value);
    }
    out
}
