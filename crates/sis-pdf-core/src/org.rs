use std::collections::{BTreeSet, HashMap};

use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::{build_adjacency, ObjRef};

#[derive(Debug, Clone)]
pub struct OrgGraph {
    pub nodes: Vec<ObjRef>,
    pub adjacency: HashMap<ObjRef, Vec<ObjRef>>,
}

impl OrgGraph {
    pub fn from_object_graph(graph: &ObjectGraph<'_>) -> Self {
        let mut adjacency = build_adjacency(&graph.objects);
        let mut nodes_set: BTreeSet<ObjRef> = BTreeSet::new();
        for entry in &graph.objects {
            nodes_set.insert(ObjRef {
                obj: entry.obj,
                gen: entry.gen,
            });
        }
        let mut missing = Vec::new();
        for (_src, targets) in adjacency.iter() {
            for t in targets {
                if !nodes_set.contains(t) {
                    missing.push(*t);
                }
            }
        }
        for m in missing {
            nodes_set.insert(m);
            adjacency.entry(m).or_default();
        }
        let nodes: Vec<ObjRef> = nodes_set.into_iter().collect();
        Self { nodes, adjacency }
    }

    pub fn edge_index(&self) -> Vec<(usize, usize)> {
        let mut index_map: HashMap<ObjRef, usize> = HashMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            index_map.insert(*n, i);
        }
        let mut edges = Vec::new();
        for (src, targets) in &self.adjacency {
            let Some(&src_idx) = index_map.get(src) else { continue };
            for t in targets {
                if let Some(&t_idx) = index_map.get(t) {
                    edges.push((src_idx, t_idx));
                }
            }
        }
        edges
    }
}
