use anyhow::Result;

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;
use sis_pdf_pdf::decode::stream_filters;
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfName};

pub struct ExternalActionContextDetector;

impl Detector for ExternalActionContextDetector {
    fn id(&self) -> &'static str {
        "external_action_risk_context"
    }
    fn surface(&self) -> AttackSurface {
        AttackSurface::Actions
    }
    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH | Needs::STREAM_INDEX
    }
    fn cost(&self) -> Cost {
        Cost::Moderate
    }
    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut action_targets = Vec::new();
        let mut action_evidence = Vec::new();
        let mut action_objects = Vec::new();
        for entry in &ctx.graph.objects {
            let dict = match crate::entry_dict(entry) {
                Some(d) => d,
                None => continue,
            };
            if !is_external_action_dict(dict) {
                continue;
            }
            if let Some(details) = crate::resolve_action_details(ctx, &sis_pdf_pdf::object::PdfObj {
                span: dict.span,
                atom: PdfAtom::Dict(dict.clone()),
            }) {
                if let Some(target) = details.meta.get("action.target") {
                    action_targets.push(target.clone());
                }
                action_evidence.extend(details.evidence);
            } else {
                action_evidence.push(span_to_evidence(dict.span, "Action dict"));
            }
            action_objects.push(format!("{} {} obj", entry.obj, entry.gen));
        }
        if action_targets.is_empty() {
            return Ok(Vec::new());
        }

        let hex_name_count = count_hex_names(&ctx.graph);
        let deep_filter_count = count_deep_filters(&ctx.graph);
        if hex_name_count == 0 && deep_filter_count == 0 {
            return Ok(Vec::new());
        }

        let mut meta = std::collections::HashMap::new();
        meta.insert("external.action_count".into(), action_targets.len().to_string());
        meta.insert("external.action_targets".into(), action_targets.join(", "));
        if hex_name_count > 0 {
            meta.insert(
                "obfuscation.hex_name_count".into(),
                hex_name_count.to_string(),
            );
        }
        if deep_filter_count > 0 {
            meta.insert(
                "obfuscation.deep_filter_streams".into(),
                deep_filter_count.to_string(),
            );
        }

        let mut evidence = action_evidence;
        evidence.truncate(8);

        Ok(vec![Finding {
            id: String::new(),
            surface: self.surface(),
            kind: "external_action_risk_context".into(),
            severity: Severity::Medium,
            confidence: Confidence::Probable,
            title: "External action with obfuscation context".into(),
            description:
                "External action targets are present alongside obfuscation markers (hex-encoded names or deep filter chains)."
                    .into(),
            objects: action_objects,
            evidence,
            remediation: Some(
                "Inspect action targets and decode nested streams to confirm intent.".into(),
            ),
            meta,
            yara: None,
        }])
    }
}

fn is_external_action_dict(dict: &PdfDict<'_>) -> bool {
    dict.has_name(b"/S", b"/URI")
        || dict.has_name(b"/S", b"/GoToR")
        || dict.has_name(b"/S", b"/Launch")
        || dict.has_name(b"/S", b"/SubmitForm")
        || dict.get_first(b"/URI").is_some()
        || dict.get_first(b"/F").is_some()
}

fn count_hex_names(graph: &sis_pdf_pdf::ObjectGraph<'_>) -> usize {
    let mut count = 0usize;
    for entry in &graph.objects {
        let dict = match crate::entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        for (name, _) in &dict.entries {
            if name_has_hex(name) {
                count += 1;
            }
        }
    }
    count
}

fn name_has_hex(name: &PdfName<'_>) -> bool {
    name.raw.iter().any(|b| *b == b'#')
}

fn count_deep_filters(graph: &sis_pdf_pdf::ObjectGraph<'_>) -> usize {
    let mut count = 0usize;
    for entry in &graph.objects {
        if let PdfAtom::Stream(st) = &entry.atom {
            let filters = stream_filters(&st.dict);
            if filters.len() >= 3 {
                count += 1;
            }
        }
    }
    count
}
