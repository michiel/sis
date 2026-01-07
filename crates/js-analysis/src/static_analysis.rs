use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

#[derive(Debug, Clone)]
pub struct DecodedLayers {
    pub bytes: Vec<u8>,
    pub layers: usize,
}

pub fn extract_js_signals(data: &[u8]) -> HashMap<String, String> {
    extract_js_signals_with_ast(data, true)
}

pub fn extract_js_signals_with_ast(data: &[u8], enable_ast: bool) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let entropy = shannon_entropy(data);
    out.insert("js.entropy".into(), format!("{:.3}", entropy));
    out.insert(
        "js.has_base64_like".into(),
        bool_str(count_base64_like_runs(data, 40) > 0),
    );
    out.insert(
        "js.long_token_run".into(),
        bool_str(longest_token_run(data) >= 32),
    );
    out.insert(
        "js.contains_hex_escapes".into(),
        bool_str(contains_hex_escape(data)),
    );
    out.insert(
        "js.contains_unicode_escapes".into(),
        bool_str(contains_unicode_escape(data)),
    );
    out.insert("js.contains_eval".into(), bool_str(find_token(data, b"eval")));
    out.insert(
        "js.dynamic_eval_construction".into(), 
        bool_str(contains_dynamic_eval_construction(data))
    );
    out.insert(
        "js.contains_unescape".into(),
        bool_str(find_token(data, b"unescape")),
    );
    out.insert(
        "js.contains_fromcharcode".into(),
        bool_str(find_token(data, b"fromCharCode")),
    );
    out.insert(
        "js.hex_fromcharcode_pattern".into(),
        bool_str(contains_hex_fromcharcode_pattern(data))
    );
    out.insert(
        "js.environment_fingerprinting".into(),
        bool_str(contains_environment_fingerprinting(data))
    );
    out.insert(
        "js.string_concat_density".into(),
        format!("{:.3}", byte_density(data, b'+')),
    );
    out.insert(
        "js.escape_density".into(),
        format!("{:.3}", byte_density(data, b'\\')),
    );
    out.insert(
        "js.regex_packing".into(),
        bool_str(contains_regex_packing(data)),
    );
    out.insert(
        "js.suspicious_apis".into(),
        bool_str(contains_suspicious_api(data)),
    );
    out.insert("js.ast_parsed".into(), "false".into());
    out.insert("js.sandbox_exec".into(), "false".into());
    #[cfg(feature = "js-ast")]
    {
        if enable_ast {
            if let Some(summary) = ast_behaviour_summary(data) {
                out.insert("js.ast_parsed".into(), "true".into());
                if let Some(summary) = summary.summary {
                    out.insert("js.behaviour_summary".into(), summary);
                }
                if !summary.call_args.is_empty() {
                    out.insert("js.ast_call_args".into(), summary.call_args.join("; "));
                }
                if !summary.urls.is_empty() {
                    out.insert("js.ast_urls".into(), summary.urls.join(", "));
                }
                if !summary.domains.is_empty() {
                    out.insert("js.ast_domains".into(), summary.domains.join(", "));
                }
            }
        }
    }

    let obf = is_obfuscationish(&out);
    out.insert("js.obfuscation_suspected".into(), bool_str(obf));
    out
}

pub fn decode_layers(data: &[u8], max_layers: usize) -> DecodedLayers {
    let mut current = data.to_vec();
    let mut layers = 0usize;
    loop {
        if layers >= max_layers {
            break;
        }
        if let Some(next) = decode_once(&current) {
            current = next;
            layers += 1;
            continue;
        }
        break;
    }
    DecodedLayers { bytes: current, layers }
}

fn decode_once(data: &[u8]) -> Option<Vec<u8>> {
    if let Some(decoded) = decode_js_escapes(data) {
        return Some(decoded);
    }
    if let Some(decoded) = decode_hex_string(data) {
        return Some(decoded);
    }
    if is_base64_like(data) {
        if let Ok(decoded) = STANDARD.decode(data) {
            if decoded.len() > 16 {
                return Some(decoded);
            }
        }
    }
    None
}

fn decode_js_escapes(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < data.len() {
        if data[i] == b'\\' && i + 1 < data.len() {
            match data[i + 1] {
                b'x' if i + 3 < data.len() => {
                    if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 4]), 16) {
                        out.push(v);
                        i += 4;
                        changed = true;
                        continue;
                    }
                }
                b'u' if i + 5 < data.len() => {
                    if let Ok(v) = u16::from_str_radix(&String::from_utf8_lossy(&data[i + 2..i + 6]), 16) {
                        if let Some(s) = std::char::from_u32(v as u32) {
                            out.push(s as u8);
                            i += 6;
                            changed = true;
                            continue;
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(data[i]);
        i += 1;
    }
    if changed { Some(out) } else { None }
}

fn decode_hex_string(data: &[u8]) -> Option<Vec<u8>> {
    let mut cleaned = Vec::new();
    for &b in data {
        if (b as char).is_ascii_hexdigit() {
            cleaned.push(b);
        } else if !b.is_ascii_whitespace() {
            return None;
        }
    }
    if cleaned.len() < 16 || cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let s = String::from_utf8_lossy(&cleaned[i..i + 2]);
        if let Ok(v) = u8::from_str_radix(&s, 16) {
            out.push(v);
        } else {
            return None;
        }
    }
    Some(out)
}

fn is_base64_like(data: &[u8]) -> bool {
    data.iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=' || b.is_ascii_whitespace())
}

fn count_base64_like_runs(data: &[u8], min_len: usize) -> usize {
    let mut count = 0usize;
    let mut run = 0usize;
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
        } else {
            if run >= min_len {
                count += 1;
            }
            run = 0;
        }
    }
    if run >= min_len {
        count += 1;
    }
    count
}

fn longest_token_run(data: &[u8]) -> usize {
    let mut max = 0usize;
    let mut current = 0usize;
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'_' {
            current += 1;
        } else {
            if current > max {
                max = current;
            }
            current = 0;
        }
    }
    max.max(current)
}

fn contains_hex_escape(data: &[u8]) -> bool {
    find_token(data, b"\\x")
}

fn contains_unicode_escape(data: &[u8]) -> bool {
    find_token(data, b"\\u")
}

fn contains_regex_packing(data: &[u8]) -> bool {
    find_token(data, b"/" ) && find_token(data, b".replace")
}

fn contains_suspicious_api(data: &[u8]) -> bool {
    let apis: &[&[u8]] = &[
        // Existing APIs
        b"app.launchURL",
        b"util.printf",
        b"this.getURL",
        b"submitForm",
        b"importDataObject",
        b"exportDataObject",
        b"app.mailMsg",
        
        // PDF annotation manipulation (high risk)
        b"app.doc.syncAnnotScan",
        b"app.doc.getAnnots",
        b"app.doc.addAnnot",
        b"app.doc.removeAnnot",
        b".subject",
        
        // Environment fingerprinting
        b"app.plugIns.length",
        b"app.viewerType",
        b"app.platform",
        
        // Media exploitation
        b"this.media.newPlayer",
        b"app.media.newPlayer",
        
        // Advanced execution contexts
        b"this.getOCGs",
        b"app.doc.getOCGs",
    ];
    apis.iter().any(|pat| find_token(data, pat))
}

fn find_token(data: &[u8], token: &[u8]) -> bool {
    data.windows(token.len()).any(|w| w.eq_ignore_ascii_case(token))
}

fn contains_dynamic_eval_construction(data: &[u8]) -> bool {
    // Detect patterns like: 'ev' + 'a' + 'l' or variable[function_name]()
    let patterns: &[&[u8]] = &[
        // String concatenation to form "eval"
        b"'ev'",
        b"\"ev\"", 
        // Common eval construction fragments
        b"'a'",
        b"\"a\"",
        b"'l'",
        b"\"l\"",
    ];
    
    // Look for string concatenation operators near eval fragments
    let has_eval_fragments = patterns.iter().any(|pat| find_token(data, pat));
    let has_concat = find_token(data, b"+");
    let has_dynamic_access = find_token(data, b"[") && find_token(data, b"]");
    
    (has_eval_fragments && has_concat) || has_dynamic_access
}

fn contains_hex_fromcharcode_pattern(data: &[u8]) -> bool {
    // Detect String.fromCharCode with hex patterns like "0x" or parseInt usage
    let has_fromcharcode = find_token(data, b"fromCharCode");
    let has_hex_prefix = find_token(data, b"0x") || find_token(data, b"\"0x");
    let has_parseint = find_token(data, b"parseInt");
    
    has_fromcharcode && (has_hex_prefix || has_parseint)
}

fn contains_environment_fingerprinting(data: &[u8]) -> bool {
    // Detect conditional execution based on environment properties
    let fingerprint_props: &[&[u8]] = &[
        b"app.plugIns.length",
        b"app.viewerType",
        b"app.platform",
        b"app.viewerVersion",
        b"this.info.title",
        b"this.info.author",
    ];
    
    let has_fingerprinting = fingerprint_props.iter().any(|pat| find_token(data, pat));
    let has_conditional = find_token(data, b"if") && (find_token(data, b">") || find_token(data, b"==") || find_token(data, b"!="));
    
    has_fingerprinting && has_conditional
}

fn byte_density(data: &[u8], byte: u8) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let count = data.iter().filter(|b| **b == byte).count();
    count as f64 / data.len() as f64
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut out = 0.0;
    for &c in freq.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        out -= p * p.log2();
    }
    out
}

fn bool_str(val: bool) -> String {
    if val { "true".into() } else { "false".into() }
}

fn is_obfuscationish(meta: &HashMap<String, String>) -> bool {
    let base64_like = meta.get("js.has_base64_like").map(|v| v == "true").unwrap_or(false);
    let has_eval = meta.get("js.contains_eval").map(|v| v == "true").unwrap_or(false);
    let has_fcc = meta.get("js.contains_fromcharcode").map(|v| v == "true").unwrap_or(false);
    let has_unescape = meta.get("js.contains_unescape").map(|v| v == "true").unwrap_or(false);
    let has_hex = meta.get("js.contains_hex_escapes").map(|v| v == "true").unwrap_or(false);
    let has_unicode = meta.get("js.contains_unicode_escapes").map(|v| v == "true").unwrap_or(false);
    base64_like || (has_eval && (has_fcc || has_unescape)) || has_hex || has_unicode
}

#[cfg(feature = "js-ast")]
struct AstSummary {
    summary: Option<String>,
    call_args: Vec<String>,
    urls: Vec<String>,
    domains: Vec<String>,
}

#[cfg(feature = "js-ast")]
fn ast_behaviour_summary(data: &[u8]) -> Option<AstSummary> {
    use boa_ast::expression::literal::Literal;
    use boa_ast::expression::Call;
    use boa_ast::scope::Scope;
    use boa_ast::visitor::{VisitWith, Visitor};
    use boa_interner::{Interner, ToInternedString};
    use boa_parser::{Parser, Source};
    use std::collections::{BTreeMap, BTreeSet, HashMap as Map};

    let src = std::str::from_utf8(data).ok()?;
    let mut interner = Interner::default();
    let source = Source::from_bytes(src);
    let mut parser = Parser::new(source);
    let scope = Scope::new_global();
    let script = parser.parse_script(&scope, &mut interner).ok()?;

    struct JsAstVisitor<'a> {
        interner: &'a Interner,
        calls: Map<String, usize>,
        urls: BTreeSet<String>,
        domains: BTreeSet<String>,
        call_args: BTreeMap<String, BTreeSet<String>>,
    }

    impl<'ast, 'a> Visitor<'ast> for JsAstVisitor<'a> {
        type BreakTy = ();

        fn visit_call(&mut self, node: &'ast Call) -> std::ops::ControlFlow<Self::BreakTy> {
            let name = node.function().to_interned_string(self.interner);
            if !name.is_empty() {
                *self.calls.entry(name.clone()).or_insert(0) += 1;
            }
            if !name.is_empty() {
                for arg in node.args() {
                    if let boa_ast::expression::Expression::Literal(literal) = arg {
                        if let Some(sym) = literal.as_string() {
                            let value = self
                                .interner
                                .resolve_expect(sym)
                                .join(|s: &str| s.to_string(), String::from_utf16_lossy, true);
                            let summary = summarise_arg_value(&value, 60);
                            self.call_args
                                .entry(name.clone())
                                .or_default()
                                .insert(summary);
                            if looks_like_url(&value) {
                                self.urls.insert(value.clone());
                                if let Some(domain) = domain_from_url(&value) {
                                    self.domains.insert(domain);
                                }
                            }
                        }
                    }
                }
            }
            node.visit_with(self)
        }

        fn visit_literal(&mut self, node: &'ast Literal) -> std::ops::ControlFlow<Self::BreakTy> {
            if let Some(sym) = node.as_string() {
                let value = self
                    .interner
                    .resolve_expect(sym)
                    .join(|s: &str| s.to_string(), String::from_utf16_lossy, true);
                if looks_like_url(&value) {
                    self.urls.insert(value.clone());
                    if let Some(domain) = domain_from_url(&value) {
                        self.domains.insert(domain);
                    }
                }
            }
            node.visit_with(self)
        }
    }

    let mut visitor = JsAstVisitor {
        interner: &interner,
        calls: Map::new(),
        urls: BTreeSet::new(),
        domains: BTreeSet::new(),
        call_args: BTreeMap::new(),
    };
    let _ = script.visit_with(&mut visitor);

    let mut parts = Vec::new();
    if !visitor.calls.is_empty() {
        let mut calls: Vec<_> = visitor.calls.into_iter().collect();
        calls.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let summary = calls
            .into_iter()
            .take(10)
            .map(|(name, count)| format!("{} ({})", name, count))
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("Calls: {}", summary));
        }
    }
    if !visitor.urls.is_empty() {
        let summary = visitor
            .urls
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("URLs: {}", summary));
        }
    }
    if !visitor.domains.is_empty() {
        let summary = visitor
            .domains
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if !summary.is_empty() {
            parts.push(format!("Domains: {}", summary));
        }
    }
    let call_args = render_call_args(visitor.call_args, 6, 3);
    let urls = visitor.urls.iter().take(5).cloned().collect::<Vec<_>>();
    let domains = visitor.domains.iter().take(5).cloned().collect::<Vec<_>>();
    let summary = if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    };
    Some(AstSummary {
        summary,
        call_args,
        urls,
        domains,
    })
}

#[cfg(feature = "js-ast")]
fn looks_like_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("javascript:")
}

#[cfg(feature = "js-ast")]
fn render_call_args(
    map: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    max_calls: usize,
    max_args: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for (call, args) in map.into_iter().take(max_calls) {
        let mut list: Vec<String> = args.into_iter().take(max_args).collect();
        if list.is_empty() {
            continue;
        }
        if list.len() == 1 {
            out.push(format!("{}({})", call, list.remove(0)));
        } else {
            out.push(format!("{}({})", call, list.join(", ")));
        }
    }
    out
}

#[cfg(feature = "js-ast")]
fn summarise_arg_value(value: &str, max_len: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push(' ');
        } else {
            out.push('.');
        }
    }
    out.trim().to_string()
}

#[cfg(feature = "js-ast")]
fn domain_from_url(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("mailto:") {
        let rest = &value[7..];
        return rest
            .split('@')
            .nth(1)
            .map(|s| s.split('?').next().unwrap_or(s).to_string());
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let trimmed = value.split("://").nth(1)?;
        let host = trimmed.split('/').next().unwrap_or(trimmed);
        let host = host.split('?').next().unwrap_or(host);
        let host = host.split('#').next().unwrap_or(host);
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    } else {
        None
    }
}
