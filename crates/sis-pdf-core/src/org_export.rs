use crate::org::OrgGraph;

pub fn export_org_json(org: &OrgGraph) -> serde_json::Value {
    // If enhanced data is available, export it
    if let (Some(enhanced_nodes), Some(enhanced_edges)) =
        (&org.enhanced_nodes, &org.enhanced_edges)
    {
        let nodes: Vec<serde_json::Value> = enhanced_nodes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "id": format!("{} {}", n.obj_ref.obj, n.obj_ref.gen),
                    "obj": n.obj_ref.obj,
                    "gen": n.obj_ref.gen,
                    "type": n.obj_type,
                    "roles": n.roles,
                })
            })
            .collect();

        let edges: Vec<serde_json::Value> = enhanced_edges
            .iter()
            .map(|e| {
                serde_json::json!({
                    "from": format!("{} {}", e.from.obj, e.from.gen),
                    "to": format!("{} {}", e.to.obj, e.to.gen),
                    "type": e.edge_type,
                    "suspicious": e.suspicious,
                })
            })
            .collect();

        return serde_json::json!({
            "nodes": nodes,
            "edges": edges,
            "enhanced": true,
        });
    }

    // Fallback to basic export
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
        "enhanced": false,
    })
}

pub fn export_org_dot(org: &OrgGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph pdf_org {\n");

    // If enhanced data is available, use it
    if let (Some(enhanced_nodes), Some(enhanced_edges)) =
        (&org.enhanced_nodes, &org.enhanced_edges)
    {
        // Export nodes with type information
        for node in enhanced_nodes {
            let mut label = format!("{} {}", node.obj_ref.obj, node.obj_ref.gen);
            if let Some(obj_type) = &node.obj_type {
                label.push_str(&format!("\\n{}", obj_type));
            }
            if !node.roles.is_empty() {
                label.push_str(&format!("\\n[{}]", node.roles.join(", ")));
            }
            out.push_str(&format!("  \"{} {}\" [label=\"{}\"];\n", node.obj_ref.obj, node.obj_ref.gen, label));
        }

        // Export edges with type information
        for edge in enhanced_edges {
            let edge_label = edge.edge_type.as_ref().map(|t| t.as_str()).unwrap_or("ref");
            let style = if edge.suspicious {
                "color=red, style=bold"
            } else {
                ""
            };
            out.push_str(&format!(
                "  \"{} {}\" -> \"{} {}\" [label=\"{}\" {}];\n",
                edge.from.obj, edge.from.gen, edge.to.obj, edge.to.gen, edge_label, style
            ));
        }
    } else {
        // Fallback to basic export
        for node in &org.nodes {
            out.push_str(&format!("  \"{} {}\";\n", node.obj, node.gen));
        }
        for (src, targets) in &org.adjacency {
            for t in targets {
                out.push_str(&format!(
                    "  \"{} {}\" -> \"{} {}\";\n",
                    src.obj, src.gen, t.obj, t.gen
                ));
            }
        }
    }

    out.push_str("}\n");
    out
}
