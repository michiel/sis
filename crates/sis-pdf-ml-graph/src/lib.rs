use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use blake3::Hasher;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GraphModelSpec {
    pub embed_dim: usize,
    pub gnn: GnnSpec,
    pub threshold: Option<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GnnSpec {
    pub layers: Vec<GnnLayer>,
    pub readout: LinearLayer,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GnnLayer {
    pub eps: f32,
    pub weight: Vec<Vec<f32>>,
    pub bias: Vec<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinearLayer {
    pub weight: Vec<f32>,
    pub bias: f32,
}

#[derive(Debug, Clone)]
pub struct GraphModel {
    pub spec: GraphModelSpec,
}

#[derive(Debug, Clone)]
pub struct GraphPrediction {
    pub score: f32,
    pub label: bool,
    pub threshold: f32,
}

impl GraphModel {
    pub fn load(model_dir: &Path) -> Result<Self> {
        let spec_path = model_dir.join("graph_model.json");
        let data = fs::read(&spec_path)
            .map_err(|e| anyhow!("failed to read {}: {}", spec_path.display(), e))?;
        let spec: GraphModelSpec = serde_json::from_slice(&data)
            .map_err(|e| anyhow!("invalid graph_model.json: {}", e))?;
        Ok(Self { spec })
    }

    pub fn predict(
        &self,
        node_texts: &[String],
        edge_index: &[(usize, usize)],
        threshold: f32,
    ) -> Result<GraphPrediction> {
        let embed_dim = self.spec.embed_dim;
        let mut node_features: Vec<Vec<f32>> = node_texts
            .iter()
            .map(|t| hash_embed(t, embed_dim))
            .collect();
        let neighbors = build_neighbors(node_features.len(), edge_index);
        for layer in &self.spec.gnn.layers {
            node_features = gin_layer(&node_features, &neighbors, layer)?;
        }
        let graph_vec = readout_sum(&node_features);
        let score = sigmoid(linear(&graph_vec, &self.spec.gnn.readout));
        let label = score >= threshold;
        Ok(GraphPrediction {
            score,
            label,
            threshold,
        })
    }
}

pub fn load_and_predict(
    model_dir: &Path,
    node_texts: &[String],
    edge_index: &[(usize, usize)],
    threshold: f32,
) -> Result<GraphPrediction> {
    let model = GraphModel::load(model_dir)?;
    let cfg_threshold = model.spec.threshold.unwrap_or(threshold);
    model.predict(node_texts, edge_index, cfg_threshold)
}

fn hash_embed(text: &str, dim: usize) -> Vec<f32> {
    let mut out = vec![0.0f32; dim.max(1)];
    let mut count = 0u32;
    for token in tokenize(text) {
        let mut h = Hasher::new();
        h.update(token.as_bytes());
        let hash = h.finalize();
        let bytes = hash.as_bytes();
        let idx = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let slot = idx % out.len();
        out[slot] += 1.0;
        count += 1;
    }
    if count > 0 {
        let scale = 1.0 / (count as f32).sqrt();
        for v in &mut out {
            *v *= scale;
        }
    }
    out
}

fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '/' || ch == '_' || ch == '-' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(cur.clone());
            cur.clear();
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn build_neighbors(n: usize, edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
    let mut neighbors = vec![Vec::new(); n];
    for (src, dst) in edges {
        if *src < n && *dst < n {
            neighbors[*src].push(*dst);
        }
    }
    neighbors
}

fn gin_layer(
    inputs: &[Vec<f32>],
    neighbors: &[Vec<usize>],
    layer: &GnnLayer,
) -> Result<Vec<Vec<f32>>> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }
    let in_dim = inputs[0].len();
    let out_dim = layer.weight.len();
    for row in &layer.weight {
        if row.len() != in_dim {
            return Err(anyhow!("gnn layer weight dim mismatch"));
        }
    }
    if layer.bias.len() != out_dim {
        return Err(anyhow!("gnn layer bias dim mismatch"));
    }
    let mut outputs = vec![vec![0.0f32; out_dim]; inputs.len()];
    for (i, h) in inputs.iter().enumerate() {
        let mut agg = vec![0.0f32; in_dim];
        for j in 0..in_dim {
            agg[j] = (1.0 + layer.eps) * h[j];
        }
        for n in &neighbors[i] {
            if let Some(hn) = inputs.get(*n) {
                for j in 0..in_dim {
                    agg[j] += hn[j];
                }
            }
        }
        let mut out = vec![0.0f32; out_dim];
        for (o, row) in layer.weight.iter().enumerate() {
            let mut sum = layer.bias[o];
            for j in 0..in_dim {
                sum += row[j] * agg[j];
            }
            out[o] = relu(sum);
        }
        outputs[i] = out;
    }
    Ok(outputs)
}

fn readout_sum(nodes: &[Vec<f32>]) -> Vec<f32> {
    if nodes.is_empty() {
        return Vec::new();
    }
    let dim = nodes[0].len();
    let mut out = vec![0.0f32; dim];
    for n in nodes {
        for i in 0..dim {
            out[i] += n[i];
        }
    }
    out
}

fn linear(vec: &[f32], layer: &LinearLayer) -> f32 {
    let mut sum = layer.bias;
    for (w, x) in layer.weight.iter().zip(vec.iter()) {
        sum += w * x;
    }
    sum
}

fn relu(v: f32) -> f32 {
    if v > 0.0 { v } else { 0.0 }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

pub fn graph_model_dir_from_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_model_predicts_with_simple_weights() {
        let layer = GnnLayer {
            eps: 0.0,
            weight: vec![
                vec![1.0, 0.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0, 0.0],
                vec![0.0, 0.0, 1.0, 0.0],
                vec![0.0, 0.0, 0.0, 1.0],
            ],
            bias: vec![0.0, 0.0, 0.0, 0.0],
        };
        let spec = GraphModelSpec {
            embed_dim: 4,
            gnn: GnnSpec {
                layers: vec![layer],
                readout: LinearLayer {
                    weight: vec![0.5, 0.5, 0.5, 0.5],
                    bias: 0.0,
                },
            },
            threshold: None,
        };
        let model = GraphModel { spec };
        let node_texts = vec!["/Type /Page".to_string(), "/JS alert".to_string()];
        let edge_index = vec![(0usize, 1usize)];
        let pred = model.predict(&node_texts, &edge_index, 0.0).expect("predict");
        assert!(pred.score >= 0.0);
        assert!(pred.label);
    }
}
