use std::collections::BTreeMap;

use crate::model::{AttackSurface, Finding, Severity};

#[derive(Debug, serde::Serialize)]
pub struct Summary {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub grouped: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Report {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        let mut grouped: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
        for f in &findings {
            let surface = attack_surface_name(f.surface);
            grouped
                .entry(surface)
                .or_default()
                .entry(f.kind.clone())
                .or_default()
                .push(f.id.clone());
        }
        let summary = summary_from_findings(&findings);
        Self {
            summary,
            findings,
            grouped,
        }
    }
}

pub fn print_human(report: &Report) {
    println!("Findings: {}", report.summary.total);
    println!(
        "High: {}  Medium: {}  Low: {}  Info: {}",
        report.summary.high, report.summary.medium, report.summary.low, report.summary.info
    );
    println!();
    for (surface, kinds) in &report.grouped {
        println!("{}", surface);
        for (kind, ids) in kinds {
            println!("  {} ({})", kind, ids.len());
            for id in ids {
                println!("    - {}", id);
            }
        }
    }
}

fn summary_from_findings(findings: &[Finding]) -> Summary {
    let mut summary = Summary {
        total: findings.len(),
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    for f in findings {
        match f.severity {
            Severity::High | Severity::Critical => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }
    }
    summary
}

pub fn attack_surface_name(surface: AttackSurface) -> String {
    format!("{:?}", surface)
}
