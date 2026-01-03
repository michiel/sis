use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;

#[derive(Parser)]
#[command(name = "ysnp")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scan {
        pdf: String,
        #[arg(long)]
        deep: bool,
        #[arg(long, default_value_t = 32 * 1024 * 1024)]
        max_decode_bytes: usize,
        #[arg(long)]
        no_recover: bool,
        #[arg(long)]
        json: bool,
    },
    Explain {
        pdf: String,
        finding_id: String,
    },
    Extract {
        #[arg(value_parser = ["js", "embedded"])]
        kind: String,
        pdf: String,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Scan {
            pdf,
            deep,
            max_decode_bytes,
            no_recover,
            json,
        } => run_scan(&pdf, deep, max_decode_bytes, !no_recover, json),
        Command::Explain { pdf, finding_id } => run_explain(&pdf, &finding_id),
        Command::Extract { kind, pdf, out } => run_extract(&kind, &pdf, &out),
    }
}

fn mmap_file(path: &str) -> Result<Mmap> {
    let f = fs::File::open(path)?;
    unsafe { Mmap::map(&f).map_err(|e| anyhow!(e)) }
}

fn run_scan(
    pdf: &str,
    deep: bool,
    max_decode_bytes: usize,
    recover_xref: bool,
    json: bool,
) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let opts = ysnp_core::scan::ScanOptions {
        deep,
        max_decode_bytes,
        recover_xref,
        parallel: true,
    };
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        ysnp_core::report::print_human(&report);
    }
    Ok(())
}

fn run_explain(pdf: &str, finding_id: &str) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    let opts = ysnp_core::scan::ScanOptions {
        deep: true,
        max_decode_bytes: 32 * 1024 * 1024,
        recover_xref: true,
        parallel: false,
    };
    let detectors = ysnp_detectors::default_detectors();
    let report = ysnp_core::runner::run_scan_with_detectors(&mmap, opts, &detectors)?;
    let Some(finding) = report.findings.iter().find(|f| f.id == finding_id) else {
        return Err(anyhow!("finding id not found"));
    };
    println!("{} - {}", finding.id, finding.title);
    println!("{}", finding.description);
    println!("Severity: {:?}  Confidence: {:?}", finding.severity, finding.confidence);
    println!();
    for ev in &finding.evidence {
        println!(
            "Evidence: source={:?} offset={} length={} note={}",
            ev.source,
            ev.offset,
            ev.length,
            ev.note.as_deref().unwrap_or("-")
        );
        if matches!(ev.source, ysnp_core::model::EvidenceSource::File) {
            let start = ev.offset as usize;
            let end = start.saturating_add(ev.length as usize).min(mmap.len());
            let slice = &mmap[start..end];
            println!("{}", preview_bytes(slice));
        } else {
            println!("(decoded evidence preview not available)");
        }
    }
    Ok(())
}

fn run_extract(kind: &str, pdf: &str, outdir: &PathBuf) -> Result<()> {
    let mmap = mmap_file(pdf)?;
    fs::create_dir_all(outdir)?;
    let graph = ysnp_pdf::parse_pdf(&mmap, ysnp_pdf::ParseOptions { recover_xref: true })?;
    match kind {
        "js" => extract_js(&graph, &mmap, outdir),
        "embedded" => extract_embedded(&graph, &mmap, outdir),
        _ => Err(anyhow!("unknown extract kind")),
    }
}

fn extract_js(graph: &ysnp_pdf::ObjectGraph<'_>, bytes: &[u8], outdir: &PathBuf) -> Result<()> {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let Some(dict) = entry_dict(entry) {
            if let Some((_, obj)) = dict.get_first(b"/JS") {
                if let Some(data) = extract_obj_bytes(graph, bytes, obj) {
                    let path = outdir.join(format!("js_{}_{}.js", entry.obj, entry.gen));
                    fs::write(path, data)?;
                    count += 1;
                }
            }
        }
    }
    println!("Extracted {} JavaScript payloads", count);
    Ok(())
}

fn extract_embedded(
    graph: &ysnp_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    outdir: &PathBuf,
) -> Result<()> {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let ysnp_pdf::object::PdfAtom::Stream(st) = &entry.atom {
            if st.dict.has_name(b"/Type", b"/EmbeddedFile") {
                if let Ok(decoded) = ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                {
                    let name = embedded_filename(&st.dict).unwrap_or_else(|| {
                        format!("embedded_{}_{}.bin", entry.obj, entry.gen)
                    });
                    let path = outdir.join(name);
                    fs::write(path, decoded.data)?;
                    count += 1;
                }
            }
        }
    }
    println!("Extracted {} embedded files", count);
    Ok(())
}

fn embedded_filename(dict: &ysnp_pdf::object::PdfDict<'_>) -> Option<String> {
    if let Some((_, obj)) = dict.get_first(b"/F") {
        if let ysnp_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    if let Some((_, obj)) = dict.get_first(b"/UF") {
        if let ysnp_pdf::object::PdfAtom::Str(s) = &obj.atom {
            return Some(String::from_utf8_lossy(&string_bytes(s)).to_string());
        }
    }
    None
}

fn entry_dict<'a>(entry: &'a ysnp_pdf::graph::ObjEntry<'a>) -> Option<&'a ysnp_pdf::object::PdfDict<'a>> {
    match &entry.atom {
        ysnp_pdf::object::PdfAtom::Dict(d) => Some(d),
        ysnp_pdf::object::PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn extract_obj_bytes(
    graph: &ysnp_pdf::ObjectGraph<'_>,
    bytes: &[u8],
    obj: &ysnp_pdf::object::PdfObj<'_>,
) -> Option<Vec<u8>> {
    match &obj.atom {
        ysnp_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
        ysnp_pdf::object::PdfAtom::Stream(st) => {
            ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                .ok()
                .map(|d| d.data)
        }
        ysnp_pdf::object::PdfAtom::Ref { .. } => {
            let entry = graph.resolve_ref(obj)?;
            match &entry.atom {
                ysnp_pdf::object::PdfAtom::Str(s) => Some(string_bytes(s)),
                ysnp_pdf::object::PdfAtom::Stream(st) => {
                    ysnp_pdf::decode::decode_stream(bytes, st, 32 * 1024 * 1024)
                        .ok()
                        .map(|d| d.data)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn string_bytes(s: &ysnp_pdf::object::PdfStr<'_>) -> Vec<u8> {
    match s {
        ysnp_pdf::object::PdfStr::Literal { decoded, .. } => decoded.clone(),
        ysnp_pdf::object::PdfStr::Hex { decoded, .. } => decoded.clone(),
    }
}

fn preview_bytes(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes.iter().take(256) {
        if b.is_ascii_graphic() || b == b' ' {
            s.push(b as char);
        } else {
            s.push('.');
        }
    }
    s
}
