use crate::org::OrgGraph;

pub fn export_org_json(org: &OrgGraph) -> serde_json::Value {
    let nodes: Vec<String> = org
        .nodes
        .iter()
        .map(|n| format!("{} {}", n.obj, n.gen))
        .collect();
    let mut edges = Vec::new();
    for (src, targets) in &org.adjacency {
        for t in targets {
            edges.push(serde_json::json!({
                "from": format!("{} {}", src.obj, src.gen),
                "to": format!("{} {}", t.obj, t.gen),
            }));
        }
    }
    serde_json::json!({
        "nodes": nodes,
        "edges": edges,
    })
}

pub fn export_org_dot(org: &OrgGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph pdf_org {\n");
    for node in &org.nodes {
        out.push_str(&format!(
            "  \"{} {}\";\n",
            node.obj, node.gen
        ));
    }
    for (src, targets) in &org.adjacency {
        for t in targets {
            out.push_str(&format!(
                "  \"{} {}\" -> \"{} {}\";\n",
                src.obj, src.gen, t.obj, t.gen
            ));
        }
    }
    out.push_str("}\n");
    out
}
