use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::Result;
use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::vm::RuntimeLimits;
use boa_engine::{Context, JsString, JsValue, NativeFunction, Source};

use sis_pdf_core::detect::{Cost, Detector, Needs};
use sis_pdf_core::model::{AttackSurface, Confidence, Finding, Severity};
use sis_pdf_core::scan::span_to_evidence;

use crate::{entry_dict, resolve_payload};

pub struct JavaScriptSandboxDetector;

const JS_WALLCLOCK_TIMEOUT: Duration = Duration::from_secs(5);
const JS_WALLCLOCK_WARN: Duration = Duration::from_secs(1);
const JS_SANDBOX_MAX_BYTES: usize = 256 * 1024;

impl Detector for JavaScriptSandboxDetector {
    fn id(&self) -> &'static str {
        "js_sandbox"
    }

    fn surface(&self) -> AttackSurface {
        AttackSurface::JavaScript
    }

    fn needs(&self) -> Needs {
        Needs::OBJECT_GRAPH
    }

    fn cost(&self) -> Cost {
        Cost::Expensive
    }

    fn run(&self, ctx: &sis_pdf_core::scan::ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        for entry in &ctx.graph.objects {
            let Some(dict) = entry_dict(entry) else { continue };
            if !dict.has_name(b"/S", b"/JavaScript") && dict.get_first(b"/JS").is_none() {
                continue;
            }
            let Some((_, obj)) = dict.get_first(b"/JS") else { continue };
            let payload = resolve_payload(ctx, obj);
            let Some(info) = payload.payload else { continue };
            if info.bytes.len() > JS_SANDBOX_MAX_BYTES {
                let mut meta = std::collections::HashMap::new();
                meta.insert("js.sandbox_exec".into(), "false".into());
                meta.insert("js.sandbox_skip_reason".into(), "payload_too_large".into());
                meta.insert("payload.decoded_len".into(), info.bytes.len().to_string());
                meta.insert("js.sandbox_limit_bytes".into(), JS_SANDBOX_MAX_BYTES.to_string());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_sandbox_skipped".into(),
                    severity: Severity::Info,
                    confidence: Confidence::Probable,
                    title: "JavaScript sandbox skipped".into(),
                    description: "Sandbox skipped because the JS payload exceeds the size limit.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect the JS payload size and consider manual analysis.".into()),
                    meta,
                    yara: None,
                });
                continue;
            }
            let bytes = info.bytes.clone();
            let (tx, rx) = mpsc::channel();
            let start = Instant::now();
            std::thread::spawn(move || {
                let log = Rc::new(RefCell::new(Vec::<String>::new()));
                let mut context = Context::default();
                let mut limits = RuntimeLimits::default();
                limits.set_loop_iteration_limit(100_000);
                limits.set_recursion_limit(128);
                limits.set_stack_size_limit(512 * 1024);
                context.set_runtime_limits(limits);
                register_app(&mut context, log.clone());
                let source = Source::from_bytes(&bytes);
                let _ = context.eval(source);
                let calls = log.borrow().clone();
                let _ = tx.send(calls);
            });
            let calls = match rx.recv_timeout(JS_WALLCLOCK_TIMEOUT) {
                Ok(calls) => calls,
                Err(RecvTimeoutError::Timeout) => {
                    eprintln!(
                        "security_boundary: JS sandbox timed out after {:?} (obj {} {})",
                        JS_WALLCLOCK_TIMEOUT,
                        entry.obj,
                        entry.gen
                    );
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("js.sandbox_exec".into(), "true".into());
                    meta.insert("js.sandbox_timeout".into(), "true".into());
                    meta.insert(
                        "js.sandbox_timeout_ms".into(),
                        JS_WALLCLOCK_TIMEOUT.as_millis().to_string(),
                    );
                    findings.push(Finding {
                        id: String::new(),
                        surface: self.surface(),
                        kind: "js_sandbox_timeout".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Probable,
                        title: "JavaScript sandbox timeout".into(),
                        description: "Sandbox execution exceeded the time limit.".into(),
                        objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                        evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                        remediation: Some("Inspect the JS payload for long-running loops.".into()),
                        meta,
                        yara: None,
                    });
                    continue;
                }
                Err(_) => continue,
            };
            let elapsed = start.elapsed();
            if elapsed > JS_WALLCLOCK_WARN {
                eprintln!(
                    "security_boundary: JS sandbox slow execution {:?} (obj {} {})",
                    elapsed,
                    entry.obj,
                    entry.gen
                );
            }
            if calls.is_empty() {
                let mut meta = std::collections::HashMap::new();
                meta.insert("js.sandbox_exec".into(), "true".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_sandbox_exec".into(),
                    severity: Severity::Info,
                    confidence: Confidence::Probable,
                    title: "JavaScript sandbox executed".into(),
                    description: "Sandbox executed JS; no monitored API calls observed.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Review JS payload for non-API behavior.".into()),
                    meta,
                    yara: None,
                });
                continue;
            }
            let mut meta = std::collections::HashMap::new();
            meta.insert("js.runtime.calls".into(), calls.join(","));
            let has_network = calls.iter().any(|c| matches!(c.as_str(), "launchURL" | "getURL" | "submitForm"));
            let has_file = calls.iter().any(|c| matches!(c.as_str(), "browseForDoc" | "saveAs" | "exportDataObject"));
            if has_network {
                eprintln!(
                    "security_boundary: JS sandbox network-capable API invoked (obj {} {})",
                    entry.obj,
                    entry.gen
                );
                meta.insert("js.sandbox_exec".into(), "true".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_runtime_network_intent".into(),
                    severity: Severity::High,
                    confidence: Confidence::Probable,
                    title: "Runtime network intent".into(),
                    description: "JavaScript invoked network-capable APIs during sandboxed execution.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Inspect runtime JS calls and network targets.".into()),
                    meta: meta.clone(),
                    yara: None,
                });
            }
            if has_file {
                eprintln!(
                    "security_boundary: JS sandbox file-capable API invoked (obj {} {})",
                    entry.obj,
                    entry.gen
                );
                meta.insert("js.sandbox_exec".into(), "true".into());
                findings.push(Finding {
                    id: String::new(),
                    surface: self.surface(),
                    kind: "js_runtime_file_probe".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Probable,
                    title: "Runtime file or object probe".into(),
                    description: "JavaScript invoked file or object-related APIs during sandboxed execution.".into(),
                    objects: vec![format!("{} {} obj", entry.obj, entry.gen)],
                    evidence: vec![span_to_evidence(dict.span, "JavaScript dict")],
                    remediation: Some("Review runtime JS calls for file or export operations.".into()),
                    meta,
                    yara: None,
                });
            }
        }
        Ok(findings)
    }
}

fn register_app(context: &mut Context, log: Rc<RefCell<Vec<String>>>) {
    let make_fn = |name: &'static str| {
        let log = log.clone();
        unsafe {
            NativeFunction::from_closure(move |_this, _args, _ctx| {
                log.borrow_mut().push(name.to_string());
                Ok(JsValue::undefined())
            })
        }
    };

    let app = ObjectInitializer::new(context)
        .function(make_fn("launchURL"), JsString::from("launchURL"), 1)
        .function(make_fn("getURL"), JsString::from("getURL"), 1)
        .function(make_fn("submitForm"), JsString::from("submitForm"), 1)
        .function(make_fn("browseForDoc"), JsString::from("browseForDoc"), 0)
        .function(make_fn("saveAs"), JsString::from("saveAs"), 1)
        .function(make_fn("exportDataObject"), JsString::from("exportDataObject"), 1)
        .build();

    let _ = context.register_global_property(JsString::from("app"), app, Attribute::all());
}
