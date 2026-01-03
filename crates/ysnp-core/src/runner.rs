use anyhow::Result;

use crate::model::Finding;
use crate::report::Report;
use crate::scan::{DecodedCache, ScanContext, ScanOptions};
use ysnp_pdf::{parse_pdf, ParseOptions};

pub fn run_scan_with_detectors(
    bytes: &[u8],
    options: ScanOptions,
    detectors: &[Box<dyn crate::detect::Detector>],
) -> Result<Report> {
    let graph = parse_pdf(bytes, ParseOptions { recover_xref: options.recover_xref })?;
    let ctx = ScanContext {
        bytes,
        graph,
        decoded: DecodedCache::new(options.max_decode_bytes),
        options,
    };

    let mut findings: Vec<Finding> = if ctx.options.parallel {
        use rayon::prelude::*;
        detectors
            .par_iter()
            .filter(|d| ctx.options.deep || d.cost() != crate::detect::Cost::Expensive)
            .map(|d| d.run(&ctx))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect()
    } else {
        let mut out = Vec::new();
        for d in detectors {
            if !ctx.options.deep && d.cost() == crate::detect::Cost::Expensive {
                continue;
            }
            out.extend(d.run(&ctx)?);
        }
        out
    };

    for f in &mut findings {
        if f.id.is_empty() {
            f.id = stable_id(f);
        }
    }
    findings.sort_by(|a, b| (a.surface as u32, &a.kind, &a.id).cmp(&(b.surface as u32, &b.kind, &b.id)));
    Ok(Report::from_findings(findings))
}

fn stable_id(f: &Finding) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(f.kind.as_bytes());
    hasher.update(format!("{:?}", f.surface).as_bytes());
    for o in &f.objects {
        hasher.update(o.as_bytes());
    }
    for e in &f.evidence {
        hasher.update(format!("{:?}", e.source).as_bytes());
        hasher.update(e.offset.to_string().as_bytes());
        hasher.update(e.length.to_string().as_bytes());
        if let Some(origin) = e.origin {
            hasher.update(origin.start.to_string().as_bytes());
            hasher.update(origin.end.to_string().as_bytes());
        }
    }
    format!("ysnp-{}", hasher.finalize().to_hex())
}
